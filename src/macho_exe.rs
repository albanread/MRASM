//! Self-contained Mach-O (AArch64) executable writer: [`EncodedModule`] → a
//! runnable `MH_EXECUTE`, with **no external linker and no external codesign
//! tool** — `ld64`/`clang` were only ever a bring-up crutch (`tests/macho_run42.rs`
//! used them to prove the object writer). This is the WRASM "no linker" ethos
//! applied to macOS: source text in, a running, ad-hoc-signed executable out.
//!
//! Layout mirrors the minimal shape `clang`+`ld64` actually produce (verified by
//! hand-building it and diffing against a `clang`-linked reference with `otool
//! -l`/`codesign -dvvv`, then stripping every load command that turned out to be
//! purely informational): `__PAGEZERO` (the null-deref guard) · `__TEXT`
//! (headers + `__text`, one 16KB page) · `__LINKEDIT` (symtab + strtab + the
//! embedded code signature). `LC_LOAD_DYLINKER`/`LC_MAIN` are required — a
//! `LC_UNIXTHREAD`-style static binary with no dyld is not something the kernel
//! will run on modern macOS. `LC_LOAD_DYLIB(libSystem)` is kept even when the
//! module makes no external call: every observed working executable has it, and
//! dropping it was not worth re-verifying once the minimal set above was proven.
//! Dropped as inessential (present in a `clang`-linked binary but not required for
//! the kernel/dyld to load and run one): `LC_UUID`, `LC_BUILD_VERSION`,
//! `LC_SOURCE_VERSION`, `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE`,
//! `LC_DYLD_EXPORTS_TRIE`, `LC_DYLD_CHAINED_FIXUPS`.
//!
//! **Ad-hoc code signing is mandatory on arm64** — the kernel refuses to exec
//! unsigned code, even code that calls nothing. [`build_code_signature`] computes
//! a real `CS_SuperBlob`/`CS_CodeDirectory` (SHA-256 page hashes over every file
//! byte preceding the signature blob) with our own `sha2`, not by shelling to
//! `codesign`. Code-signing blobs are **big-endian** regardless of host
//! endianness — the one place in this file that isn't `to_le_bytes()`.
//!
//! Known limitation (documented, not silently dropped): `module.externs` must be
//! empty. Calling into a dylib (e.g. `libSystem`'s `exit`/`puts`) needs a dyld
//! bind mechanism (chained fixups or classic bind opcodes) plus `__TEXT,__stubs`
//! trampolines for `bl`, which is a distinct, larger follow-up — see
//! `mrasm-port` memory. This writer covers externless programs end to end.

use std::collections::BTreeMap;

use anyhow::{bail, ensure, Result};
use sha2::{Digest, Sha256};

use crate::backend::EncodedModule;

const PAGE: u64 = 0x4000; // 16KB — Apple Silicon segment/file alignment
const HASH_PAGE: usize = 4096; // code-signature hashing page size (fixed, independent of PAGE)
const BASE: u64 = 0x1_0000_0000; // __TEXT vmaddr (ld64's conventional PIE base)

const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xb;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_DYLINKER: u32 = 0xe;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_MAIN: u32 = 0x8000_0028; // LC_MAIN | LC_REQ_DYLD

fn segment_name(bytes: &[u8]) -> [u8; 16] {
    let mut f = [0u8; 16];
    f[..bytes.len()].copy_from_slice(bytes);
    f
}

/// One `LC_SEGMENT_64`, with an optional single section (this writer never
/// needs more than one section per segment).
fn cmd_segment_64(
    segname: &[u8],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    section: Option<(&[u8], u64, u64, u64)>, // (sectname, addr, size, file offset)
) -> Vec<u8> {
    let nsects: u32 = section.is_some() as u32;
    let cmdsize = 72 + nsects as usize * 80;
    let mut out = Vec::with_capacity(cmdsize);
    out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    out.extend_from_slice(&(cmdsize as u32).to_le_bytes());
    out.extend_from_slice(&segment_name(segname));
    out.extend_from_slice(&vmaddr.to_le_bytes());
    out.extend_from_slice(&vmsize.to_le_bytes());
    out.extend_from_slice(&fileoff.to_le_bytes());
    out.extend_from_slice(&filesize.to_le_bytes());
    out.extend_from_slice(&maxprot.to_le_bytes());
    out.extend_from_slice(&initprot.to_le_bytes());
    out.extend_from_slice(&nsects.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    if let Some((sectname, addr, size, offset)) = section {
        out.extend_from_slice(&segment_name(sectname));
        out.extend_from_slice(&segment_name(segname));
        out.extend_from_slice(&addr.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes()); // align = 2^2 (instruction word)
        out.extend_from_slice(&0u32.to_le_bytes()); // reloff
        out.extend_from_slice(&0u32.to_le_bytes()); // nreloc
        out.extend_from_slice(&0x8000_0400u32.to_le_bytes()); // S_ATTR_PURE_INSTRUCTIONS|SOME_INSTRUCTIONS
        out.extend_from_slice(&[0u8; 12]); // reserved1, reserved2, reserved3
    }
    out
}

fn cmd_symtab(symoff: u32, nsyms: u32, stroff: u32, strsize: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&LC_SYMTAB.to_le_bytes());
    out.extend_from_slice(&24u32.to_le_bytes());
    out.extend_from_slice(&symoff.to_le_bytes());
    out.extend_from_slice(&nsyms.to_le_bytes());
    out.extend_from_slice(&stroff.to_le_bytes());
    out.extend_from_slice(&strsize.to_le_bytes());
    out
}

/// Zeroed `LC_DYSYMTAB` — dyld requires the command to be present alongside
/// `LC_SYMTAB`, but every field is legitimately 0 when there are no symbols.
fn cmd_dysymtab() -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(&LC_DYSYMTAB.to_le_bytes());
    out.extend_from_slice(&80u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 72]); // 18 x u32, all zero
    out
}

fn cmd_load_dylinker() -> Vec<u8> {
    let name = b"/usr/lib/dyld\0";
    let pad = (4 - ((12 + name.len()) % 4)) % 4;
    let cmdsize = 12 + name.len() + pad;
    let mut out = Vec::with_capacity(cmdsize);
    out.extend_from_slice(&LC_LOAD_DYLINKER.to_le_bytes());
    out.extend_from_slice(&(cmdsize as u32).to_le_bytes());
    out.extend_from_slice(&12u32.to_le_bytes()); // name offset within this command
    out.extend_from_slice(name);
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

fn cmd_main(entryoff: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&LC_MAIN.to_le_bytes());
    out.extend_from_slice(&24u32.to_le_bytes());
    out.extend_from_slice(&entryoff.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // stacksize = 0 -> default
    out
}

fn cmd_load_dylib(path: &str) -> Vec<u8> {
    let mut name = path.as_bytes().to_vec();
    name.push(0);
    let pad = (4 - ((24 + name.len()) % 4)) % 4;
    let cmdsize = 24 + name.len() + pad;
    let mut out = Vec::with_capacity(cmdsize);
    out.extend_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
    out.extend_from_slice(&(cmdsize as u32).to_le_bytes());
    out.extend_from_slice(&24u32.to_le_bytes()); // name offset
    out.extend_from_slice(&0u32.to_le_bytes()); // timestamp
    out.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // current_version 1.0.0
    out.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // compat_version 1.0.0
    out.extend_from_slice(&name);
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

fn cmd_code_signature(dataoff: u32, datasize: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&dataoff.to_le_bytes());
    out.extend_from_slice(&datasize.to_le_bytes());
    out
}

/// The `CS_CodeDirectory` fixed header size (magic..spare2): 9 `u32` fields +
/// 4 `u8` fields + a trailing `u32` = 44 bytes, followed by the identifier
/// string and then the hash slots.
const CD_HEADER_LEN: usize = 44;

/// Size (in bytes) the ad-hoc code signature blob will occupy for a signed
/// region of `signed_len` bytes and an identifier of `ident_len` (including
/// the terminating NUL). Needed up front because the code signature's own
/// `LC_CODE_SIGNATURE.dataoff` must be known before the signed region (which
/// ends right before it) can be finalized — see [`write_macho_exe`].
fn code_signature_size(signed_len: usize, ident_len: usize) -> usize {
    let hash_off = CD_HEADER_LEN + ident_len;
    let n_code_slots = signed_len.div_ceil(HASH_PAGE);
    let cd_len = hash_off + n_code_slots * 32;
    12 + 8 + cd_len // SuperBlob header(12) + one BlobIndex(8) + the CodeDirectory
}

/// Build an ad-hoc `CS_SuperBlob` wrapping one `CS_CodeDirectory` (SHA-256,
/// `HASH_PAGE`-byte pages) covering all of `signed_bytes`. Code-signing blobs
/// are big-endian regardless of host/target endianness.
fn build_code_signature(signed_bytes: &[u8], identifier: &str) -> Vec<u8> {
    let mut ident = identifier.as_bytes().to_vec();
    ident.push(0);

    let ident_off = CD_HEADER_LEN;
    let hash_off = ident_off + ident.len();
    let n_code_slots = signed_bytes.len().div_ceil(HASH_PAGE);
    let cd_len = hash_off + n_code_slots * 32;

    let mut cd = Vec::with_capacity(cd_len);
    cd.extend_from_slice(&0xfade_0c02u32.to_be_bytes()); // CSMAGIC_CODEDIRECTORY
    cd.extend_from_slice(&(cd_len as u32).to_be_bytes()); // length
    cd.extend_from_slice(&0x0002_0001u32.to_be_bytes()); // version (pre-scatter/team-id; simplest valid shape)
    cd.extend_from_slice(&0x0000_0002u32.to_be_bytes()); // flags = CS_ADHOC
    cd.extend_from_slice(&(hash_off as u32).to_be_bytes());
    cd.extend_from_slice(&(ident_off as u32).to_be_bytes());
    cd.extend_from_slice(&0u32.to_be_bytes()); // nSpecialSlots
    cd.extend_from_slice(&(n_code_slots as u32).to_be_bytes());
    cd.extend_from_slice(&(signed_bytes.len() as u32).to_be_bytes()); // codeLimit
    cd.push(32); // hashSize (SHA-256)
    cd.push(2); // hashType = SHA256
    cd.push(0); // platform (0 = not a platform binary)
    cd.push(12); // pageSize = log2(4096)
    cd.extend_from_slice(&0u32.to_be_bytes()); // spare2
    debug_assert_eq!(cd.len(), CD_HEADER_LEN);
    cd.extend_from_slice(&ident);
    debug_assert_eq!(cd.len(), hash_off);
    for chunk in signed_bytes.chunks(HASH_PAGE) {
        cd.extend_from_slice(&Sha256::digest(chunk));
    }
    debug_assert_eq!(cd.len(), cd_len);

    // SuperBlob: magic, total length, count=1, one (type, offset) index entry,
    // then the CodeDirectory blob itself.
    let mut sb = Vec::with_capacity(12 + 8 + cd.len());
    sb.extend_from_slice(&0xfade_0cc0u32.to_be_bytes()); // CSMAGIC_EMBEDDED_SIGNATURE
    sb.extend_from_slice(&((12 + 8 + cd.len()) as u32).to_be_bytes());
    sb.extend_from_slice(&1u32.to_be_bytes()); // count
    sb.extend_from_slice(&0u32.to_be_bytes()); // CSSLOT_CODEDIRECTORY
    sb.extend_from_slice(&20u32.to_be_bytes()); // offset of the CD blob from the SuperBlob start
    sb.extend_from_slice(&cd);
    sb
}

/// Build a self-contained, ad-hoc-signed Mach-O `MH_EXECUTE` for `module`,
/// entering at the `.globl` symbol `entry`. No external linker, no external
/// codesign tool. `module.externs` must be empty (see module docs).
pub fn write_macho_exe(module: &EncodedModule, entry: &str) -> Result<Vec<u8>> {
    ensure!(
        module.externs.is_empty(),
        "write_macho_exe: {} extern(s) {:?} not supported yet (needs a dyld bind mechanism — see mrasm-port memory); \
         write_macho_obj + the system linker is the fallback for a program that calls out",
        module.externs.len(),
        module.externs
    );
    let entry_off_in_code = *module
        .symbols
        .get(entry)
        .ok_or_else(|| anyhow::anyhow!("entry symbol '{entry}' not defined (.globl it)"))?;

    // ── plan the __TEXT page: header + load commands, then the code ────────
    let identifier = entry; // a short, deterministic identifier; no meaning beyond diagnostics
    let text_section_off = {
        // Two-pass: build every command once with placeholder LINKEDIT/codesig
        // values (their exact offsets depend on where __TEXT's code ends, which
        // depends on nothing but ncmds — a fixed set for this writer — so a
        // single upfront sum suffices; no fixpoint needed).
        let header_len = 32u64;
        let cmds_len: u64 = [72, 152, 72, 24, 80, 28, 24, 52, 16].iter().sum::<u64>();
        // cmd sizes: PAGEZERO(72) TEXT+1sect(152) LINKEDIT(72) SYMTAB(24)
        // DYSYMTAB(80) DYLINKER(28, "/usr/lib/dyld") MAIN(24)
        // DYLIB(52, "/usr/lib/libSystem.B.dylib") CODE_SIGNATURE(16).
        let after_cmds = header_len + cmds_len;
        // 4-byte instruction alignment is enough; page room is ample (16KB).
        (after_cmds + 3) / 4 * 4
    };
    ensure!(
        text_section_off + module.code.len() as u64 <= PAGE,
        "write_macho_exe: code ({} bytes) doesn't fit in the one-page __TEXT layout (headers take {text_section_off} bytes of {PAGE}) — \
         a multi-page __TEXT layout isn't implemented yet",
        module.code.len()
    );
    let entryoff = text_section_off + entry_off_in_code as u64;

    let pagezero = cmd_segment_64(b"__PAGEZERO", 0, BASE, 0, 0, 0, 0, None);
    let text = cmd_segment_64(
        b"__TEXT",
        BASE,
        PAGE,
        0,
        PAGE,
        0x5, // maxprot r-x
        0x5, // initprot r-x
        Some((b"__text", BASE + text_section_off, module.code.len() as u64, text_section_off)),
    );

    // ── __LINKEDIT: symtab (0 entries for now) + strtab + code signature ───
    let nsyms = 0u32;
    let strsize = 4u32; // minimum: a leading NUL + alignment padding
    let linkedit_fileoff = PAGE;
    let symoff = linkedit_fileoff as u32;
    let stroff = symoff + nsyms * 16;
    let codesig_dataoff_unaligned = stroff + strsize;
    let codesig_dataoff = (codesig_dataoff_unaligned + 15) / 16 * 16; // 16-byte align, matches observed convention

    let codesig_datasize = code_signature_size(codesig_dataoff as usize, identifier.len() + 1) as u32;
    let linkedit_filesize = (codesig_dataoff - linkedit_fileoff as u32) as u64 + codesig_datasize as u64;
    let linkedit_vmsize = (linkedit_filesize + PAGE - 1) / PAGE * PAGE;
    let linkedit = cmd_segment_64(
        b"__LINKEDIT",
        BASE + PAGE,
        linkedit_vmsize,
        linkedit_fileoff,
        linkedit_filesize,
        0x1, // maxprot r--
        0x1, // initprot r--
        None,
    );

    let symtab_cmd = cmd_symtab(symoff, nsyms, stroff, strsize);
    let dysymtab_cmd = cmd_dysymtab();
    let dylinker_cmd = cmd_load_dylinker();
    let main_cmd = cmd_main(entryoff);
    let dylib_cmd = cmd_load_dylib("/usr/lib/libSystem.B.dylib");
    let codesig_cmd = cmd_code_signature(codesig_dataoff, codesig_datasize);

    let cmds: [&[u8]; 9] = [
        &pagezero, &text, &linkedit, &symtab_cmd, &dysymtab_cmd, &dylinker_cmd, &main_cmd, &dylib_cmd, &codesig_cmd,
    ];
    let ncmds = cmds.len() as u32;
    let sizeofcmds: usize = cmds.iter().map(|c| c.len()).sum();

    let mut out = Vec::with_capacity(codesig_dataoff as usize + codesig_datasize as usize);
    out.extend_from_slice(&0xfeed_facfu32.to_le_bytes()); // MH_MAGIC_64
    out.extend_from_slice(&0x0100_000cu32.to_le_bytes()); // CPU_TYPE_ARM64
    out.extend_from_slice(&0u32.to_le_bytes()); // CPU_SUBTYPE_ARM64_ALL
    out.extend_from_slice(&0x2u32.to_le_bytes()); // MH_EXECUTE
    out.extend_from_slice(&ncmds.to_le_bytes());
    out.extend_from_slice(&(sizeofcmds as u32).to_le_bytes());
    out.extend_from_slice(&(0x1u32 | 0x4 | 0x80 | 0x0020_0000).to_le_bytes()); // NOUNDEFS|DYLDLINK|TWOLEVEL|PIE
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    for c in &cmds {
        out.extend_from_slice(c);
    }
    ensure!(out.len() as u64 == text_section_off, "internal layout error: header+cmds {} != predicted {text_section_off}", out.len());
    while (out.len() as u64) < text_section_off {
        out.push(0);
    }
    out.extend_from_slice(&module.code);
    while (out.len() as u64) < PAGE {
        out.push(0);
    }

    ensure!(out.len() as u32 == symoff, "internal layout error: __TEXT end {} != symoff {symoff}", out.len());
    // 0 symbol-table entries to write.
    ensure!(out.len() as u32 == stroff, "internal layout error");
    out.extend_from_slice(&[0u8; 4]); // strtab: leading NUL + pad to strsize
    while (out.len() as u32) < codesig_dataoff {
        out.push(0);
    }

    let signature = build_code_signature(&out, identifier);
    ensure!(
        signature.len() as u32 == codesig_datasize,
        "internal layout error: codesig predicted {codesig_datasize} bytes, built {}",
        signature.len()
    );
    out.extend_from_slice(&signature);

    Ok(out)
}

/// Convenience wrapper mirroring [`crate::pe::write_pe`]'s import-map shape,
/// for call-site symmetry with the PE writer even though this writer doesn't
/// resolve imports yet. `_imports` is accepted but must be empty.
pub fn write_macho_exe_checked(
    module: &EncodedModule,
    _imports: &BTreeMap<String, String>,
    entry: &str,
) -> Result<Vec<u8>> {
    if !_imports.is_empty() {
        bail!("write_macho_exe_checked: import map given but externs aren't supported yet");
    }
    write_macho_exe(module, entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a64::A64Encoder;
    use crate::backend::Encoder;

    #[test]
    fn rejects_externs() {
        let m = A64Encoder.encode(".globl _main\n_main:\n  bl _puts\n  ret\n").unwrap();
        let err = write_macho_exe(&m, "_main").unwrap_err();
        assert!(err.to_string().contains("extern"), "{err}");
    }

    #[test]
    fn rejects_missing_entry() {
        let m = A64Encoder.encode(".globl _main\n_main:\n  ret\n").unwrap();
        let err = write_macho_exe(&m, "_nope").unwrap_err();
        assert!(err.to_string().contains("_nope"), "{err}");
    }

    #[test]
    fn produces_a_valid_mach_header() {
        let m = A64Encoder.encode(".globl _main\n_main:\n  movz w0, #42\n  ret\n").unwrap();
        let exe = write_macho_exe(&m, "_main").unwrap();
        assert_eq!(u32::from_le_bytes(exe[0..4].try_into().unwrap()), 0xfeed_facf);
        assert_eq!(u32::from_le_bytes(exe[4..8].try_into().unwrap()), 0x0100_000c);
        assert_eq!(u32::from_le_bytes(exe[12..16].try_into().unwrap()), 0x2, "MH_EXECUTE");
    }
}
