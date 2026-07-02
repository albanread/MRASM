//! mackb — a read-only knowledge layer over `cocoa.sqlite`, the shared macOS
//! Objective-C/SDK metadata mirror (sibling repo `cocoa_data`, also used by
//! MacModula2/MacNCL/MacBCPL/MF66/MF67). The macOS analogue of [`winkb`] —
//! same read-only-connection, resolve-by-query shape, but sourced from the
//! Obj-C runtime + BridgeSupport instead of Win32 metadata.
//!
//! Five tables matter to an assembler:
//! * `method_abi` — for every `(class, selector, is_class)` Objective-C method,
//!   the ALREADY-COMPUTED AAPCS64 register shape: a return token and one token
//!   per argument (`g` gpr/id, `f` fp/double, `h1..h4` HFA, `i1`/`i2` small
//!   int-struct, `b` byref, `s` sret, `v` void, `?` unmodelable). This is what
//!   drives `objccall`'s register marshaling — see the send-synthesizer
//!   algorithm recorded in the `mrasm-port` design notes (ported from MF67's
//!   `src/objc.rs`/`src/session.rs`).
//! * `bs_functions`/`bs_function_args` — plain C (framework) function
//!   signatures as raw `@encode` type tokens, for `invoke`.
//! * `posix_functions`/`posix_function_args`/`posix_function_abi` — a curated
//!   POSIX/BSD libc surface `bs_functions` doesn't cover (BridgeSupport is a
//!   Cocoa-bridging format, never meant for `malloc`/`open`/`read`/…), ingested
//!   straight from clang's AST over the live SDK headers (`ingest_posix.py`),
//!   with an AAPCS64 classification (`derive_posix_abi.py`) in the SAME token
//!   vocabulary as `method_abi` — see [`posix_abi`](MacKb::posix_abi).
//! * `structs`/`struct_fields` — resolved struct layouts (member names + byte
//!   offsets), for `sizeof`/`Struct.field` the way winkb serves `RECT.right`.
//!
//! Opened read-only; the file is never modified. Degrades gracefully: if the
//! DB is absent, [`MacKb::load`] still returns a usable (but empty-answering)
//! `MacKb` — see [`MacKb::is_available`] — mirroring MF67's `cocoadb.rs`
//! ("the database is an ergonomic convenience, not a gate").

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use std::cell::RefCell;
use std::collections::HashMap;

/// The knowledge base: a read-only connection to `cocoa.sqlite`, or `None` if
/// the database couldn't be opened (every lookup then returns `None`/empty).
pub struct MacKb {
    conn: Option<Connection>,
    method_abi_cache: RefCell<HashMap<String, Option<MethodAbi>>>,
    ambiguous_cache: RefCell<HashMap<(String, usize), bool>>,
}

/// One method's (or function's) AAPCS64 register shape, straight from
/// `method_abi.ret_class`/`arg_classes` — the raw per-arg tokens, undecoded.
/// Expanding a token to register classes (an `h4` HFA return rides `v0..v3`,
/// an `i2` small struct arg takes 2 GPRs, …) is the `objccall` macro's job, not
/// this crate's — mirrors MF67's `expand_arg_token`/`ret_class_of` split
/// between the DB (facts) and the compiler (interpretation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodAbi {
    pub ret: String,
    pub args: Vec<String>,
}

/// A plain C function's signature, from BridgeSupport — raw `@encode` type
/// tokens per argument and for the return, undecoded (same split as
/// [`MethodAbi`]: this crate ingests faithfully, the consumer classifies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CFunction {
    pub name: String,
    pub framework: Option<String>,
    pub ret_type: String,
    pub arg_types: Vec<String>,
}

/// A curated POSIX/BSD libc function's signature, from `posix_functions`/
/// `posix_function_args` — plain C type strings exactly as clang reports them
/// (`"const char *"`, `"size_t"`, …), NOT `@encode` tokens like [`CFunction`]
/// uses (a different source, a different type-string convention — kept
/// separate rather than merged into one ambiguous representation). For
/// register-marshaling purposes use [`MacKb::posix_abi`] instead, which gives
/// the already-classified g/f/i1/i2/v tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixFunction {
    pub name: String,
    /// The canonical header this function is declared in, e.g. `"unistd.h"`
    /// — a curation choice (see `ingest_posix.py`), not a clang fact.
    pub header: String,
    /// Best-effort return type for display. A function that itself returns a
    /// function pointer (POSIX has exactly one in the curated set: `signal`)
    /// can't be sliced out of the full type string by paren-depth alone; such
    /// cases carry the literal string `"<complex declarator, see qualtype>"`
    /// here — `qualtype` always has the real signature regardless.
    pub ret_type: String,
    /// The full function type exactly as clang's `qualType` reports it, e.g.
    /// `"ssize_t (int, void *, size_t)"`.
    pub qualtype: String,
    pub variadic: bool,
    pub arg_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructField {
    pub name: String,
    pub ty: String,
    pub offset: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructLayout {
    pub name: String,
    pub size: i64,
    pub align: i64,
    pub fields: Vec<StructField>,
}

impl MacKb {
    /// Open `cocoa.sqlite` read-only at an explicit path.
    pub fn open(path: &str) -> Result<MacKb> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("open {path} read-only"))?;
        Ok(MacKb { conn: Some(conn), method_abi_cache: RefCell::new(HashMap::new()), ambiguous_cache: RefCell::new(HashMap::new()) })
    }

    /// `$COCOA_DATA_DB`, else `<crate>/../../../cocoa_data/cocoa.sqlite` (the
    /// sibling-repo convention every other consumer in the portfolio uses).
    /// Never fails: an unopenable DB yields a `MacKb` where every lookup
    /// returns `None`/empty rather than blocking assembly — see
    /// [`is_available`](MacKb::is_available).
    pub fn load() -> MacKb {
        let path = std::env::var("COCOA_DATA_DB").unwrap_or_else(|_| {
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../../cocoa_data/cocoa.sqlite").to_string()
        });
        Self::open(&path).unwrap_or_else(|_| MacKb {
            conn: None,
            method_abi_cache: RefCell::new(HashMap::new()),
            ambiguous_cache: RefCell::new(HashMap::new()),
        })
    }

    /// True if the metadata DB is open (false ⇒ every lookup returns `None`/empty).
    pub fn is_available(&self) -> bool {
        self.conn.is_some()
    }

    fn split_args(s: &str) -> Vec<String> {
        if s.is_empty() {
            Vec::new()
        } else {
            s.split(',').map(str::to_string).collect()
        }
    }

    /// Resolve a method's ABI shape EXACTLY for a known `(class, selector,
    /// is_class)` — walk this yourself up the superclass chain if the class
    /// itself has no row (this crate doesn't chase `rt_classes.superclass`;
    /// the caller usually already knows the concrete receiver class from a
    /// typed local). Memoized.
    pub fn method_abi_exact(&self, class: &str, selector: &str, is_class: bool) -> Option<MethodAbi> {
        let key = format!("={class}|{}|{selector}", is_class as u8);
        if let Some(hit) = self.method_abi_cache.borrow().get(&key) {
            return hit.clone();
        }
        let conn = self.conn.as_ref()?;
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT ret_class, arg_classes FROM method_abi WHERE class=?1 AND selector=?2 AND is_class=?3",
                rusqlite::params![class, selector, is_class as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let resolved = row.map(|(ret, args)| MethodAbi { ret, args: Self::split_args(&args) });
        self.method_abi_cache.borrow_mut().insert(key, resolved.clone());
        resolved
    }

    /// Resolve a selector's ABI shape BY NAME — the most common `(ret_class,
    /// arg_classes)` signature across all classes whose argument count matches
    /// `arity` (instance methods only). Use when the receiver's static class
    /// isn't known; check [`is_ambiguous`](MacKb::is_ambiguous) first if
    /// correctness under an unknown class matters. Memoized.
    pub fn method_abi_by_name(&self, selector: &str, arity: usize) -> Option<MethodAbi> {
        let key = format!("*{arity}|{selector}");
        if let Some(hit) = self.method_abi_cache.borrow().get(&key) {
            return hit.clone();
        }
        let conn = self.conn.as_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT ret_class, arg_classes, COUNT(*) AS n FROM method_abi \
                 WHERE selector=?1 AND is_class=0 GROUP BY ret_class, arg_classes ORDER BY n DESC",
            )
            .ok()?;
        let rows: Vec<(String, String)> = stmt
            .query_map(rusqlite::params![selector], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .ok()?
            .filter_map(Result::ok)
            .collect();
        let resolved = rows
            .into_iter()
            .find(|(_, args)| Self::split_args(args).len() == arity)
            .map(|(ret, args)| MethodAbi { ret, args: Self::split_args(&args) });
        self.method_abi_cache.borrow_mut().insert(key, resolved.clone());
        resolved
    }

    /// True when an instance selector has more than one DISTINCT `(ret_class,
    /// arg_classes)` shape across the classes that define it (at the given
    /// arity) — the ~0.6% of selectors where the by-name guess can be wrong
    /// for a minority class, and a static assembler (no runtime dispatch to
    /// fall back on, unlike MF67's PIC) should surface a `--check` diagnostic
    /// rather than silently guess. Memoized.
    pub fn is_ambiguous(&self, selector: &str, arity: usize) -> bool {
        let key = (selector.to_string(), arity);
        if let Some(&a) = self.ambiguous_cache.borrow().get(&key) {
            return a;
        }
        let a = self.query_ambiguous(selector, arity);
        self.ambiguous_cache.borrow_mut().insert(key, a);
        a
    }

    fn query_ambiguous(&self, selector: &str, arity: usize) -> bool {
        let Some(conn) = self.conn.as_ref() else { return false };
        let Ok(mut stmt) = conn
            .prepare("SELECT DISTINCT ret_class, arg_classes FROM method_abi WHERE selector=?1 AND is_class=0")
        else {
            return false;
        };
        let Ok(rows) = stmt.query_map(rusqlite::params![selector], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        }) else {
            return false;
        };
        let shapes: std::collections::HashSet<(String, String)> = rows
            .filter_map(Result::ok)
            .filter(|(_, args)| Self::split_args(args).len() == arity)
            .collect();
        shapes.len() > 1
    }

    /// A plain C function's signature (POSIX/framework), from BridgeSupport.
    /// `name` must match `bs_functions.name` exactly.
    pub fn function(&self, name: &str) -> Result<Option<CFunction>> {
        let Some(conn) = self.conn.as_ref() else { return Ok(None) };
        let framework: Option<String> = conn
            .query_row("SELECT framework FROM bs_functions WHERE name=?1", rusqlite::params![name], |r| r.get(0))
            .ok();
        // A row absent from bs_functions but the caller still queried by name:
        // not found. Distinguish "no framework recorded" (Some(None)) from
        // "no such function" (framework never assigned) via a row-exists check.
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM bs_functions WHERE name=?1 LIMIT 1",
                rusqlite::params![name],
                |_| Ok(true),
            )
            .unwrap_or(false);
        if !exists {
            return Ok(None);
        }
        let ret_type: String = conn
            .query_row(
                "SELECT type64 FROM bs_function_args WHERE function=?1 AND kind='retval' LIMIT 1",
                rusqlite::params![name],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "v".to_string()); // no retval row recorded ⇒ void
        let mut stmt = conn.prepare(
            "SELECT type64 FROM bs_function_args WHERE function=?1 AND kind='arg' ORDER BY idx",
        )?;
        let arg_types: Vec<String> =
            stmt.query_map(rusqlite::params![name], |r| r.get(0))?.filter_map(Result::ok).collect();
        Ok(Some(CFunction { name: name.to_string(), framework, ret_type, arg_types }))
    }

    /// A curated POSIX/BSD libc function's signature (plain C types, for
    /// display/diagnostics). `name` must match `posix_functions.name`
    /// exactly. `bs_functions` covers framework C APIs but not bare libc —
    /// try [`function`](MacKb::function) first if the name might be either.
    pub fn posix_function(&self, name: &str) -> Result<Option<PosixFunction>> {
        let Some(conn) = self.conn.as_ref() else { return Ok(None) };
        let row: Option<(String, String, String, i64)> = conn
            .query_row(
                "SELECT header, ret_type, qualtype, variadic FROM posix_functions WHERE name=?1",
                rusqlite::params![name],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .ok();
        let Some((header, ret_type, qualtype, variadic)) = row else { return Ok(None) };
        let mut stmt =
            conn.prepare("SELECT type FROM posix_function_args WHERE name=?1 ORDER BY idx")?;
        let arg_types: Vec<String> =
            stmt.query_map(rusqlite::params![name], |r| r.get(0))?.filter_map(Result::ok).collect();
        Ok(Some(PosixFunction {
            name: name.to_string(),
            header,
            ret_type,
            qualtype,
            variadic: variadic != 0,
            arg_types,
        }))
    }

    /// A curated POSIX/BSD libc function's AAPCS64 register shape, from
    /// `posix_function_abi` — the SAME token vocabulary and [`MethodAbi`]
    /// shape as [`method_abi_exact`](MacKb::method_abi_exact), so a consumer
    /// (`invoke`/`objccall`) marshals a libc call and a Cocoa send with one
    /// code path. `name` must match `posix_functions.name` exactly.
    pub fn posix_abi(&self, name: &str) -> Option<MethodAbi> {
        let key = format!("#{name}");
        if let Some(hit) = self.method_abi_cache.borrow().get(&key) {
            return hit.clone();
        }
        let conn = self.conn.as_ref()?;
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT ret_class, arg_classes FROM posix_function_abi WHERE name=?1",
                rusqlite::params![name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let resolved = row.map(|(ret, args)| MethodAbi { ret, args: Self::split_args(&args) });
        self.method_abi_cache.borrow_mut().insert(key, resolved.clone());
        resolved
    }

    /// A resolved struct layout (member names + byte offsets), e.g. `CGRect`,
    /// `CMTime`. `name` must match `structs.name` exactly.
    pub fn struct_layout(&self, name: &str) -> Result<Option<StructLayout>> {
        let Some(conn) = self.conn.as_ref() else { return Ok(None) };
        let row: Option<(i64, i64)> = conn
            .query_row("SELECT size, align FROM structs WHERE name=?1", rusqlite::params![name], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .ok();
        let Some((size, align)) = row else { return Ok(None) };
        let mut stmt = conn.prepare(
            "SELECT name, ty, offset FROM struct_fields WHERE struct=?1 ORDER BY idx",
        )?;
        let fields: Vec<StructField> = stmt
            .query_map(rusqlite::params![name], |r| {
                Ok(StructField { name: r.get(0)?, ty: r.get(1)?, offset: r.get(2)? })
            })?
            .filter_map(Result::ok)
            .collect();
        Ok(Some(StructLayout { name: name.to_string(), size, align, fields }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db_path() -> String {
        std::env::var("COCOA_DATA_DB").unwrap_or_else(|_| {
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../../cocoa_data/cocoa.sqlite").to_string()
        })
    }

    #[test]
    fn missing_db_degrades_gracefully() {
        let kb = MacKb::open("/nonexistent/path/cocoa.sqlite");
        assert!(kb.is_err(), "open() itself should fail on a bad path");
        // load() must never fail even if the sibling repo isn't checked out.
        let saved = std::env::var("COCOA_DATA_DB").ok();
        unsafe { std::env::set_var("COCOA_DATA_DB", "/nonexistent/path/cocoa.sqlite") };
        let kb = MacKb::load();
        assert!(!kb.is_available());
        assert_eq!(kb.method_abi_exact("NSView", "frame", false), None);
        assert_eq!(kb.method_abi_by_name("frame", 0), None);
        assert!(!kb.is_ambiguous("frame", 0));
        assert!(kb.function("printf").unwrap().is_none());
        assert!(kb.struct_layout("CGRect").unwrap().is_none());
        match saved {
            Some(v) => unsafe { std::env::set_var("COCOA_DATA_DB", v) },
            None => unsafe { std::env::remove_var("COCOA_DATA_DB") },
        }
    }

    #[test]
    fn real_db_resolves_known_shapes() {
        if !std::path::Path::new(&db_path()).exists() {
            eprintln!("skipping: cocoa.sqlite not found at {}", db_path());
            return;
        }
        let kb = MacKb::load();
        assert!(kb.is_available());

        // frame -> NSRect, an HFA(4) return (documented in cocoa_data's README).
        let frame = kb.method_abi_exact("NSView", "frame", false).expect("NSView frame");
        assert_eq!(frame.ret, "h4", "frame: {frame:?}");

        // count -> a plain cell/gpr return, zero args, extremely common (unambiguous by name).
        let count = kb.method_abi_by_name("count", 0).expect("count by name");
        assert!(count.args.is_empty());

        // A struct with known fields.
        let rect = kb.struct_layout("CGRect").expect("CGRect lookup").expect("CGRect present");
        assert!(rect.size > 0);
        assert!(!rect.fields.is_empty());

        // A well-known libc function BridgeSupport should carry.
        if let Some(f) = kb.function("printf").unwrap() {
            assert!(!f.arg_types.is_empty(), "printf: {f:?}");
        }
    }

    #[test]
    fn real_db_resolves_posix_functions() {
        if !std::path::Path::new(&db_path()).exists() {
            eprintln!("skipping: cocoa.sqlite not found at {}", db_path());
            return;
        }
        let kb = MacKb::load();

        // bs_functions (BridgeSupport, framework-only) doesn't cover bare libc —
        // the whole reason posix_functions exists.
        assert!(kb.function("malloc").unwrap().is_none(), "malloc unexpectedly in bs_functions");

        let read = kb.posix_function("read").unwrap().expect("read");
        assert_eq!(read.header, "unistd.h");
        assert_eq!(read.ret_type, "ssize_t");
        assert_eq!(read.arg_types, vec!["int", "void *", "size_t"]);
        assert!(!read.variadic);
        let read_abi = kb.posix_abi("read").expect("read abi");
        assert_eq!(read_abi.ret, "g");
        assert_eq!(read_abi.args, vec!["g", "g", "g"]);

        let open = kb.posix_function("open").unwrap().expect("open");
        assert!(open.variadic);

        // div_t/ldiv_t: the two struct-by-value returns in the curated set —
        // confirmed by a compiled sizeof probe (see derive_posix_abi.py), not
        // guessed: div_t=8 bytes->i1 (one GPR), ldiv_t=16 bytes->i2 (two GPRs).
        assert_eq!(kb.posix_abi("div").unwrap().ret, "i1");
        assert_eq!(kb.posix_abi("ldiv").unwrap().ret, "i2");

        // signal: the one function-pointer-returning POSIX function in the set —
        // ret_type can't be sliced out syntactically (see PosixFunction docs),
        // but the ABI classifier still correctly calls it a pointer (one GPR).
        let signal = kb.posix_function("signal").unwrap().expect("signal");
        assert_eq!(signal.ret_type, "<complex declarator, see qualtype>");
        assert_eq!(kb.posix_abi("signal").unwrap().ret, "g");

        assert!(kb.posix_function("not_a_real_function").unwrap().is_none());
        assert!(kb.posix_abi("not_a_real_function").is_none());
    }
}
