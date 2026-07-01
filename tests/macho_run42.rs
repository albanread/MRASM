//! End-to-end proof of the "run a number" milestone: AArch64 asm text ->
//! `A64Encoder` -> `write_macho_obj` -> a real Mach-O `.o` -> linked by the
//! system `clang`/`ld64` -> executed -> the process exit code is 42.
//!
//! This is the regression gate for the whole pipeline, not just the encoder or
//! the object writer in isolation — it proves the bytes are valid enough for
//! the real macOS linker and kernel to accept, not just internally consistent.
//! Skips (rather than fails) if `clang` isn't on PATH, since CI environments
//! without Xcode command-line tools shouldn't break the encoder-only tests.

use rasm::{write_macho_obj, A64Encoder, Encoder};
use std::process::Command;

#[test]
fn linked_exe_exits_with_42() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: clang not on PATH");
        return;
    }

    let m = A64Encoder.encode(".globl _main\n_main:\n  movz w0, #42\n  ret\n").unwrap();
    let obj = write_macho_obj(&m);

    let dir = std::env::temp_dir().join(format!("mrasm_run42_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let obj_path = dir.join("run42.o");
    let exe_path = dir.join("run42");
    std::fs::write(&obj_path, &obj).unwrap();

    let link = Command::new("clang")
        .arg("-o")
        .arg(&exe_path)
        .arg(&obj_path)
        .output()
        .expect("spawn clang");
    assert!(link.status.success(), "link failed: {}", String::from_utf8_lossy(&link.stderr));

    let run = Command::new(&exe_path).status().expect("spawn linked exe");
    assert_eq!(run.code(), Some(42));

    let _ = std::fs::remove_dir_all(&dir);
}
