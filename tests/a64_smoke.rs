//! Smoke test: the ported AArch64 encoder is reachable through the public API
//! (`rasm::A64Encoder` implementing `rasm::Encoder`) and emits correct bytes.
//!
//! This is the macOS-arm64 analogue of the x86 `RasmEncoder` doctest in lib.rs.
//! The `movz w0,#42` / `ret` pair is exactly the body of the first "run a
//! number" program: a `main` returning 42 under the AArch64 LC_MAIN convention.

use rasm::{A64Encoder, Encoder};

#[test]
fn a64_encodes_return_42() {
    let m = A64Encoder.encode("movz w0, #42\nret\n").unwrap();
    assert_eq!(
        m.code,
        // movz w0,#42 = 0x52800540 ; ret = 0xd65f03c0 (little-endian)
        vec![0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6],
        "got {:02x?}",
        m.code
    );
    assert!(m.relocs.is_empty());
    assert!(m.externs.is_empty());
}

#[test]
fn a64_extern_bl_emits_branch26_reloc() {
    // A call to an undefined symbol becomes a Branch26 relocation + an extern.
    let m = A64Encoder.encode(".globl main\nmain:\n  bl puts\n  ret\n").unwrap();
    assert_eq!(m.externs, vec!["puts".to_string()]);
    assert_eq!(m.relocs.len(), 1);
    assert_eq!(m.relocs[0].kind, rasm::RelocKind::Branch26);
    assert_eq!(m.relocs[0].target, "puts");
}
