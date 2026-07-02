//! mackb — CLI over the macOS Cocoa/SDK knowledge base. The macOS analogue of
//! `winkb`'s CLI, sourced from `cocoa.sqlite` instead of `windows_api.db`.
//!
//!   mackb method <Class> <selector> [class]   exact method ABI shape
//!   mackb method <selector> <arity>            by-name method ABI shape + ambiguity
//!   mackb function <name>                      C function signature (framework APIs)
//!   mackb posix <name>                         POSIX/libc signature + AAPCS64 ABI shape
//!   mackb struct <Name>                        struct layout (fields + byte offsets)
//!
//! DB path: $COCOA_DATA_DB, else `<crate>/../../../cocoa_data/cocoa.sqlite`.

use std::process::ExitCode;

use mackb::MacKb;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let kb = MacKb::load();
    if !kb.is_available() {
        eprintln!("warning: cocoa.sqlite not found ($COCOA_DATA_DB or ../../../cocoa_data/cocoa.sqlite) — every lookup will report 'not found'");
    }

    match (args.get(1).map(String::as_str), args.get(2), args.get(3)) {
        (Some("method"), Some(class_or_sel), Some(sel_or_arity)) => {
            if let Ok(arity) = sel_or_arity.parse::<usize>() {
                let selector = class_or_sel;
                match kb.method_abi_by_name(selector, arity) {
                    Some(m) => println!("{selector}({arity} arg(s)) -> ret={} args={:?}", m.ret, m.args),
                    None => println!("'{selector}' with {arity} arg(s): not found"),
                }
                let ambiguous = kb.is_ambiguous(selector, arity);
                println!("ambiguous across classes: {ambiguous}");
            } else {
                let (class, selector) = (class_or_sel, sel_or_arity);
                let is_class = args.get(4).map(|s| s == "class").unwrap_or(false);
                match kb.method_abi_exact(class, selector, is_class) {
                    Some(m) => println!("[{class} {selector}] -> ret={} args={:?}", m.ret, m.args),
                    None => println!("[{class} {selector}]: not found"),
                }
            }
        }
        (Some("function"), Some(name), _) => match kb.function(name)? {
            Some(f) => println!(
                "{name} ({}) -> ret={} args={:?}",
                f.framework.as_deref().unwrap_or("?"),
                f.ret_type,
                f.arg_types
            ),
            None => println!("'{name}': not found (bs_functions covers framework C APIs, not bare POSIX/libc)"),
        },
        (Some("posix"), Some(name), _) => match kb.posix_function(name)? {
            Some(f) => {
                let variadic = if f.variadic { ", variadic" } else { "" };
                println!("{name} ({}{variadic}) -> {}", f.header, f.qualtype);
                if let Some(abi) = kb.posix_abi(name) {
                    println!("  ABI: ret={} args={:?}", abi.ret, abi.args);
                }
            }
            None => println!(
                "'{name}': not found (curated POSIX/BSD surface only — see ingest_posix.py; try `mackb function` for framework C APIs)"
            ),
        },
        (Some("struct"), Some(name), _) => match kb.struct_layout(name)? {
            Some(s) => {
                println!("{name} ({} bytes, align {})", s.size, s.align);
                for f in &s.fields {
                    println!("  +{:<3} {:<20} {}", f.offset, f.name, f.ty);
                }
            }
            None => println!("'{name}': not found"),
        },
        _ => {
            eprintln!(
                "usage:\n  mackb method <Class> <selector> [class]\n  mackb method <selector> <arity>\n  mackb function <name>\n  mackb posix <name>\n  mackb struct <Name>"
            );
            return Ok(());
        }
    }
    Ok(())
}
