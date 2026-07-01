//! End-to-end proof that MRASM needs NO external linker and NO external
//! codesign tool to produce a runnable executable: AArch64 asm text ->
//! `A64Encoder` -> `write_macho_exe` -> chmod +x -> execute directly -> exit 42.
//!
//! Unlike `tests/macho_run42.rs` (which proves the *object* writer by handing
//! its output to the system `clang`/`ld64`), this test never shells out to any
//! Apple toolchain component — the Mach-O bytes, including the ad-hoc code
//! signature, come entirely from this crate.

use rasm::{write_macho_exe, A64Encoder, Encoder};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn self_signed_exe_exits_with_42_no_external_tools() {
    let m = A64Encoder.encode(".globl _main\n_main:\n  movz w0, #42\n  ret\n").unwrap();
    let exe = write_macho_exe(&m, "_main").unwrap();

    let dir = std::env::temp_dir().join(format!("mrasm_exe_run42_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let exe_path = dir.join("run42");
    std::fs::write(&exe_path, &exe).unwrap();
    let mut perms = std::fs::metadata(&exe_path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&exe_path, perms).unwrap();

    let run = Command::new(&exe_path).status().expect("spawn self-signed exe");
    assert_eq!(run.code(), Some(42));

    let _ = std::fs::remove_dir_all(&dir);
}
