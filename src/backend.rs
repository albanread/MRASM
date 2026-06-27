//! The encoder contract and its data types.
//!
//! [`Encoder`] turns assembled (post-macro-expansion) Intel-syntax text into a
//! position-independent code blob plus a symbol table and relocation list. The
//! native [`RasmEncoder`](crate::rasm::RasmEncoder) implements it.

use std::collections::BTreeMap;

use anyhow::Result;

/// A relocation to resolve once final addresses are known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reloc {
    /// Byte offset of the field to patch within the encoded code blob.
    pub at: usize,
    /// Field width in bytes (4 for rel32 / RIP-rel disp32, 8 for abs64).
    pub size: u8,
    pub kind: RelocKind,
    /// Target symbol name (internal label or extern).
    pub target: String,
    /// Constant added to the resolved target before encoding.
    pub addend: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    /// `call`/`jmp`/`jcc rel32`: field = target - (field_addr + 4).
    BranchRel32,
    /// `lea reg,[rip+disp32]` and friends: field = target - (field_addr + 4).
    RipRel32,
    /// 64-bit absolute address embedded in a data cell.
    /// Shared with AArch64 (`.quad sym` → `ARM64_RELOC_UNSIGNED`).
    Abs64,

    // ── AArch64 (fields packed *within* the 32-bit instruction word) ──────
    // Unlike x86 rel32 (a contiguous little-endian field), these patch a
    // bit-slice of the 4-byte word, so the loader must insert the immediate by
    // masking — not by writing N little-endian bytes.
    /// `b`/`bl` 26-bit PC-relative branch (±128 MB), `<<2`.
    /// Mach-O `ARM64_RELOC_BRANCH26`.
    Branch26,
    /// `adrp` 21-bit PC-relative *page* address (±4 GB), bits split
    /// `immlo[30:29]`/`immhi[23:5]`. Mach-O `ARM64_RELOC_PAGE21`.
    AdrpPage21,
    /// Low-12 page offset for the `add`/`ldr` after an `adrp` (`imm[21:10]`,
    /// scaled by access size for `ldr`). Mach-O `ARM64_RELOC_PAGEOFF12`.
    AddPageOff12,
}

/// The product of [`Encoder::encode`]: position-independent code (and optional
/// read/write data) blobs plus the symbol table and relocation list a loader
/// needs to place it.
#[derive(Debug, Clone, Default)]
pub struct EncodedModule {
    /// The encoded `.text` bytes, with reloc fields left as placeholders (0).
    pub code: Vec<u8>,
    /// The `.data` bytes (read/write globals), empty unless `.data` is used.
    pub data: Vec<u8>,
    /// `name -> code offset` for every `.globl`/labelled symbol defined in `.text`.
    pub symbols: BTreeMap<String, usize>,
    /// `name -> data offset` for every label defined in `.data` (so a `.text`
    /// reference to it can be resolved against the data section's address).
    pub data_symbols: BTreeMap<String, usize>,
    /// Relocations to apply at load time (externs, and `.text`→`.data` refs).
    pub relocs: Vec<Reloc>,
    /// Names referenced but not defined here (externs to bind).
    pub externs: Vec<String>,
}

/// Encode assembled (post-macro-expansion) Intel-syntax assembly into machine
/// code. The input is the same text LLVM-MC is fed, which lets the encoder be a
/// drop-in and aids byte-identity.
pub trait Encoder {
    fn encode(&self, asm_text: &str) -> Result<EncodedModule>;
}
