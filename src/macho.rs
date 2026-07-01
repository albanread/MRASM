//! Mach-O (AArch64) relocatable object writer: [`EncodedModule`] → `.o` bytes
//! that the system linker (`ld`/`clang`) can link into a macOS executable.
//!
//! Mirrors [`crate::coff`]'s shape: a `__text` section (+ `__data` when the
//! module has globals), an `nlist_64` symbol table for the `.globl` code
//! definitions (external, N_SECT) and the `.data` labels (local, N_SECT), then
//! the undefined externs every relocation needs (N_UNDF|N_EXT), plus one
//! `relocation_info` per [`Reloc`]. A single anonymous `LC_SEGMENT_64` (empty
//! segname — the object-file convention; the linker assigns segments) holds
//! both sections, exactly like a `.o` produced by `as`/`clang -c`.
//!
//! Known gap: `ARM64_RELOC_ADDEND` (a separate reloc entry preceding
//! PAGE21/PAGEOFF12/BRANCH26 when the addend is non-zero) is not emitted —
//! the a64 encoder currently only produces addend-0 relocs, so this is inert,
//! not silently wrong; revisit if `adrp sym+N@PAGE`-style non-zero addends land.

use std::collections::BTreeMap;

use crate::backend::{EncodedModule, RelocKind};

const MH_MAGIC_64: u32 = 0xfeedfacf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const MH_OBJECT: u32 = 0x1;
// clang sets this on every object file it emits; ld64 uses it to garbage-collect
// at symbol (not section) granularity. Harmless, and matches what a real `.o` looks like.
const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x2000;

const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;

const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

const N_UNDF: u8 = 0x00;
const N_SECT: u8 = 0x0e;
const N_EXT: u8 = 0x01;

const ARM64_RELOC_UNSIGNED: u32 = 0;
const ARM64_RELOC_BRANCH26: u32 = 2;
const ARM64_RELOC_PAGE21: u32 = 3;
const ARM64_RELOC_PAGEOFF12: u32 = 4;

const HEADER_SIZE: usize = 32; // mach_header_64
const SEGMENT_CMD_SIZE: usize = 72; // segment_command_64 (no sections)
const SECTION_SIZE: usize = 80; // section_64
const SYMTAB_CMD_SIZE: usize = 24;
const RELOC_SIZE: usize = 8; // relocation_info
const NLIST_SIZE: usize = 16; // nlist_64

struct Sym {
    name: String,
    value: u32,
    /// 1 = `__text`, 2 = `__data`, 0 = undefined.
    section: u8,
    external: bool,
}

fn section_name(bytes: &[u8]) -> [u8; 16] {
    let mut f = [0u8; 16];
    f[..bytes.len()].copy_from_slice(bytes);
    f
}

/// Serialize `m` into a Mach-O relocatable object file (`MH_OBJECT`, arm64).
pub fn write_macho_obj(m: &EncodedModule) -> Vec<u8> {
    let has_data = !m.data.is_empty();
    let nsects: u32 = if has_data { 2 } else { 1 };

    // ── symbol table: defined `__text` globls, defined `__data` labels, then
    //    the undefined externs every relocation needs to name ─────────────────
    let mut syms: Vec<Sym> = Vec::new();
    let mut index: BTreeMap<String, u32> = BTreeMap::new();
    for (name, &off) in &m.symbols {
        index.insert(name.clone(), syms.len() as u32);
        syms.push(Sym { name: name.clone(), value: off as u32, section: 1, external: true });
    }
    for (name, &off) in &m.data_symbols {
        index.entry(name.clone()).or_insert_with(|| {
            let i = syms.len() as u32;
            syms.push(Sym { name: name.clone(), value: off as u32, section: 2, external: false });
            i
        });
    }
    let ensure_undef = |name: &str, syms: &mut Vec<Sym>, index: &mut BTreeMap<String, u32>| {
        if !index.contains_key(name) {
            index.insert(name.to_string(), syms.len() as u32);
            syms.push(Sym { name: name.to_string(), value: 0, section: 0, external: true });
        }
    };
    for name in &m.externs {
        ensure_undef(name, &mut syms, &mut index);
    }
    for r in &m.relocs {
        ensure_undef(&r.target, &mut syms, &mut index);
    }

    let code_len = m.code.len();
    let data_len = m.data.len();
    let nreloc = m.relocs.len();

    let ncmds: u32 = 2; // LC_SEGMENT_64, LC_SYMTAB
    let sizeofcmds = SEGMENT_CMD_SIZE + nsects as usize * SECTION_SIZE + SYMTAB_CMD_SIZE;
    let header_end = HEADER_SIZE + sizeofcmds;

    let text_off = header_end;
    let text_reloc_off = text_off + code_len; // only __text carries relocs here
    let data_off = text_reloc_off + nreloc * RELOC_SIZE;
    let sym_off = data_off + if has_data { data_len } else { 0 };
    let str_off = sym_off + syms.len() * NLIST_SIZE;

    let mut out: Vec<u8> = Vec::new();

    // ── mach_header_64 ───────────────────────────────────────────────────────
    out.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    out.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    out.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
    out.extend_from_slice(&MH_OBJECT.to_le_bytes());
    out.extend_from_slice(&ncmds.to_le_bytes());
    out.extend_from_slice(&(sizeofcmds as u32).to_le_bytes());
    out.extend_from_slice(&MH_SUBSECTIONS_VIA_SYMBOLS.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved

    // ── LC_SEGMENT_64 (anonymous segment — the object-file convention) ────────
    out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    out.extend_from_slice(&((SEGMENT_CMD_SIZE + nsects as usize * SECTION_SIZE) as u32).to_le_bytes());
    out.extend_from_slice(&[0u8; 16]); // segname = ""
    out.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
    let vmsize = (code_len + data_len) as u64;
    out.extend_from_slice(&vmsize.to_le_bytes());
    out.extend_from_slice(&(text_off as u64).to_le_bytes()); // fileoff
    out.extend_from_slice(&((code_len + data_len) as u64).to_le_bytes()); // filesize
    out.extend_from_slice(&7u32.to_le_bytes()); // maxprot = RWX
    out.extend_from_slice(&7u32.to_le_bytes()); // initprot = RWX
    out.extend_from_slice(&nsects.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags

    // ── section_64: __text,__TEXT ──────────────────────────────────────────────
    out.extend_from_slice(&section_name(b"__text"));
    out.extend_from_slice(&section_name(b"__TEXT"));
    out.extend_from_slice(&0u64.to_le_bytes()); // addr (segment-relative, 0)
    out.extend_from_slice(&(code_len as u64).to_le_bytes());
    out.extend_from_slice(&(text_off as u32).to_le_bytes()); // offset
    out.extend_from_slice(&2u32.to_le_bytes()); // align = 2^2 = 4 (instruction word)
    out.extend_from_slice(&(if nreloc > 0 { text_reloc_off as u32 } else { 0 }).to_le_bytes());
    out.extend_from_slice(&(nreloc as u32).to_le_bytes());
    let text_flags = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS; // S_REGULAR = 0
    out.extend_from_slice(&text_flags.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved1
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved3

    // ── section_64: __data,__DATA ──────────────────────────────────────────────
    if has_data {
        out.extend_from_slice(&section_name(b"__data"));
        out.extend_from_slice(&section_name(b"__DATA"));
        out.extend_from_slice(&(code_len as u64).to_le_bytes()); // addr
        out.extend_from_slice(&(data_len as u64).to_le_bytes());
        out.extend_from_slice(&(data_off as u32).to_le_bytes());
        out.extend_from_slice(&3u32.to_le_bytes()); // align = 2^3 = 8
        out.extend_from_slice(&0u32.to_le_bytes()); // reloff (none)
        out.extend_from_slice(&0u32.to_le_bytes()); // nreloc
        out.extend_from_slice(&0u32.to_le_bytes()); // flags = S_REGULAR
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
    }

    // ── LC_SYMTAB ───────────────────────────────────────────────────────────
    out.extend_from_slice(&LC_SYMTAB.to_le_bytes());
    out.extend_from_slice(&(SYMTAB_CMD_SIZE as u32).to_le_bytes());
    out.extend_from_slice(&(sym_off as u32).to_le_bytes());
    out.extend_from_slice(&(syms.len() as u32).to_le_bytes());
    out.extend_from_slice(&(str_off as u32).to_le_bytes());

    // ── string table is built alongside the symbol table below; patch strsize in now ──
    let mut strtab: Vec<u8> = vec![0]; // index 0 is always the empty string
    let mut str_indices: Vec<u32> = Vec::with_capacity(syms.len());
    for s in &syms {
        str_indices.push(strtab.len() as u32);
        strtab.extend_from_slice(s.name.as_bytes());
        strtab.push(0);
    }
    out.extend_from_slice(&(strtab.len() as u32).to_le_bytes()); // strsize

    debug_assert_eq!(out.len(), text_off);

    // ── __text raw ─────────────────────────────────────────────────────────────
    out.extend_from_slice(&m.code);

    // ── relocations (against `__text`; ARM64 fields are bit-packed in-word by
    //    the encoder, so at/size here just locate the 4-byte instruction) ───────
    for r in &m.relocs {
        let (r_type, r_pcrel, r_length): (u32, u32, u32) = match r.kind {
            RelocKind::Branch26 => (ARM64_RELOC_BRANCH26, 1, 2),
            RelocKind::AdrpPage21 => (ARM64_RELOC_PAGE21, 1, 2),
            RelocKind::AddPageOff12 => (ARM64_RELOC_PAGEOFF12, 0, 2),
            RelocKind::Abs64 => (ARM64_RELOC_UNSIGNED, 0, 3),
            RelocKind::BranchRel32 | RelocKind::RipRel32 => {
                panic!("x86-64 reloc {:?} to '{}' has no Mach-O/ARM64 mapping (use the COFF writer)", r.kind, r.target)
            }
        };
        let symbolnum = index[&r.target];
        let word = (symbolnum & 0x00ff_ffff) | (r_pcrel << 24) | (r_length << 25) | (1u32 << 27) | (r_type << 28);
        out.extend_from_slice(&(r.at as i32).to_le_bytes()); // r_address
        out.extend_from_slice(&word.to_le_bytes());
    }

    // ── __data raw ─────────────────────────────────────────────────────────────
    if has_data {
        out.extend_from_slice(&m.data);
    }

    // ── symbol table (nlist_64) ───────────────────────────────────────────────
    debug_assert_eq!(out.len(), sym_off);
    for (i, s) in syms.iter().enumerate() {
        out.extend_from_slice(&str_indices[i].to_le_bytes()); // n_strx
        let n_type = if s.section == 0 { N_UNDF } else { N_SECT | if s.external { N_EXT } else { 0 } };
        out.push(n_type);
        out.push(s.section); // n_sect (1-based section index, 0 = NO_SECT)
        out.extend_from_slice(&0u16.to_le_bytes()); // n_desc
        out.extend_from_slice(&(s.value as u64).to_le_bytes()); // n_value
    }

    // ── string table ──────────────────────────────────────────────────────────
    debug_assert_eq!(out.len(), str_off);
    out.extend_from_slice(&strtab);

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a64::A64Encoder;
    use crate::backend::Encoder;

    fn u32_at(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    }

    #[test]
    fn macho_header_and_text_section() {
        let m = A64Encoder.encode(".globl _main\n_main:\n  movz w0, #42\n  ret\n").unwrap();
        let obj = write_macho_obj(&m);

        assert_eq!(u32_at(&obj, 0), MH_MAGIC_64);
        assert_eq!(u32_at(&obj, 4), CPU_TYPE_ARM64);
        assert_eq!(u32_at(&obj, 12), MH_OBJECT);
        assert_eq!(u32_at(&obj, 16), 2, "two load commands: SEGMENT_64 + SYMTAB");

        // section_64 __text starts right after mach_header_64 + segment_command_64.
        let sect_off = HEADER_SIZE + SEGMENT_CMD_SIZE;
        assert_eq!(&obj[sect_off..sect_off + 6], b"__text");
        assert_eq!(&obj[sect_off + 16..sect_off + 22], b"__TEXT");

        // section_64: sectname(16) segname(16) addr(8) size(8) offset(4) align(4) …
        let text_size = u32_at(&obj, sect_off + 40) as usize; // size (u64, low word)
        let text_file_off = u32_at(&obj, sect_off + 48) as usize; // offset
        assert_eq!(&obj[text_file_off..text_file_off + text_size], &m.code[..]);
    }

    #[test]
    fn macho_extern_bl_emits_one_arm64_branch26_reloc() {
        let m = A64Encoder.encode(".globl _main\n_main:\n  bl _puts\n  ret\n").unwrap();
        let obj = write_macho_obj(&m);

        let sect_off = HEADER_SIZE + SEGMENT_CMD_SIZE;
        let nreloc = u32_at(&obj, sect_off + 60); // reloff(4)@56 nreloc(4)@60
        assert_eq!(nreloc, 1);
        let reloc_off = u32_at(&obj, sect_off + 56) as usize;
        let r_address = u32_at(&obj, reloc_off) as i32;
        assert_eq!(r_address, 0);
        let word = u32_at(&obj, reloc_off + 4);
        let r_type = (word >> 28) & 0xf;
        let r_extern = (word >> 27) & 1;
        let r_length = (word >> 25) & 0x3;
        let r_pcrel = (word >> 24) & 1;
        assert_eq!(r_type, ARM64_RELOC_BRANCH26);
        assert_eq!(r_extern, 1);
        assert_eq!(r_length, 2);
        assert_eq!(r_pcrel, 1);
    }
}
