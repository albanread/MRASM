# MRASM

### Powerful assistance that conceals nothing — now on Apple Silicon

The macOS arm64 port of **[WRASM](https://github.com/albanread/WRASM)**, a
from-scratch, self-contained assembler whose whole premise is that macro
assembly and the "high-level assembler" conveniences (`invoke`, typed structs,
declared-subroutine contracts) should never hide a single instruction — and
that an assembler should carry an intense, offline, always-available knowledge
of the platform it targets, instead of making you go look things up.

On Windows that knowledge is Win32 + COM. On macOS it's Cocoa, Metal, and
POSIX — reached the same way Objective-C reaches them: `objc_msgSend` plus a
registered selector, which turns out to be a *simpler* dispatch story than a
COM vtable, not a harder one. MRASM's job is to bring WRASM's whole
philosophy — visible codegen, checked contracts, a real knowledge database —
to that world.

> **Status: early, active port.** The AArch64 encoder and a genuinely
> self-contained, self-signed Mach-O executable writer are done and tested on
> real hardware. The `was` front-end (`invoke`/`comcall`/`objccall`, the
> `proc`/`frame` contract checks) is **not yet ported** — it still only
> generates Win64/x86 text. See [Current status](#current-status) below for
> the precise line.

## Why this is more tractable than it sounds

Three things that looked like the hard parts turned out to already exist,
reused rather than rebuilt from zero:

- **The AArch64 encoder** is ported from a sibling project
  ([JASM](https://github.com/albanread/JASM)) that already built a
  corpus-gated, byte-identical-to-LLVM-MC native AArch64 encoder for a
  different assembler. It covers integer/memory/control, scalar FP, and the
  full NEON surface.
- **`objc_msgSend` register marshaling** — the AArch64 equivalent of Win64's
  `invoke` shadow-space arithmetic — has a hand-written reference
  implementation in a sibling Forth project (MF67's `kernel/objc.masm`,
  literal AArch64 asm) and a *parametric* generator for every argument-shape
  variant (`src/objc.rs::synth_send_thunk`), both directly liftable.
- **The Cocoa/Metal/POSIX knowledge database already exists**, shared across
  every native-macOS project in this portfolio: `cocoa_data`, a 158MB SQLite
  mirror of the live Objective-C runtime + BridgeSupport metadata (482,000
  method encodings, already classified into exact AAPCS64 register shapes).
  MRASM doesn't need to build a windows_api.db-style generator — it needs a
  thin reader, which is done (`mackb`, below).

## Current status

| piece | state |
|---|---|
| **x86-64 encoder** (`RasmEncoder`) | Unmodified from WRASM. Still gated by the original 5,116-form corpus. Present, tested, but not the point of this fork — kept because nothing needed removing it. |
| **AArch64 encoder** (`A64Encoder`) | **Done.** Ported from JASM; gated by its own 1,181-form frozen corpus (no LLVM needed to build); additionally verified against a live LLVM-MC oracle (26 `oracle_diff` tests, `--features llvm`). |
| **Mach-O object writer** (`write_macho_obj`) | **Done.** Emits a relocatable `MH_OBJECT` `.o`; proven by handing it to the system `clang`/`ld64` and running the result (`tests/macho_run42.rs`). |
| **Self-contained signed Mach-O executable** (`write_macho_exe`) | **Done, for extern-free programs.** Emits a complete, runnable `MH_EXECUTE` with a real embedded ad-hoc code signature (computed in-crate with `sha2` — no shell-out to `codesign`) and **no external linker at all**. `codesign --verify` accepts the output; the kernel executes it directly (`tests/macho_exe_run42.rs`). **Does not yet support calling out** to a dylib (`module.externs` must be empty) — that needs a dyld bind mechanism plus `__stubs`/GOT trampolines, not yet built. |
| **`mackb`** (Cocoa/SDK knowledge reader) | **Done.** A read-only reader over the shared `cocoa_data` database: exact and by-name Objective-C method ABI shapes, ambiguity detection, plain C function signatures (framework APIs), struct layouts. Verified against the real 158MB database. Has its own CLI. |
| **`was` front-end for AAPCS64** (`invoke`, `objccall`) | **Not started.** WRASM's `was` crate still only emits Win64/x86 assembly text — `invoke`/`comcall` generate `push rbx`/shadow-space arithmetic/`rcx,rdx,r8,r9` directly, not just reference a register-name table. An AAPCS64 equivalent is a parallel code-generation backend, planned as a separate crate reusing only `was`'s OS-neutral macro engine (`.if`/`.while`, struct instances, `.include`, equate expansion). |
| **dyld bind / `__stubs` subsystem** | **Not started.** Prerequisite for the AAPCS64 front-end to produce anything that can actually call Cocoa, Metal, or even `printf` — right now `write_macho_exe` refuses any module with externs, on purpose, rather than emit something that looks right and crashes. |
| **`studio`** (the GUI IDE) | **Dropped from the workspace entirely**, not ported. It path-depends on a Windows-only Direct2D render core (`WF66`'s `docpane`) and a Windows-only `doccrate/rust-tcl`. A macOS render core exists in a sibling project's line of work and can be wired in once there's a front-end worth showing. |
| **`ide`** (knowledge → markdown cards) | Untouched from WRASM — still renders `winkb` (Win32) content. Will need a `mackb`-backed counterpart once there's something for it to describe. |

In short: **the two hardest-sounding systems problems — a verified native
AArch64 encoder, and a signed executable with no external linker — are done.**
What's left is mostly *front-end* work: teaching `was`'s macro layer to speak
AAPCS64 and `objc_msgSend` instead of Win64 and COM, and letting the resulting
programs actually call out to the OS.

## Workspace

| crate | what it is |
|-------|------------|
| **`rasm`** (root) | Both encoders (`RasmEncoder` for x86-64, `A64Encoder` for AArch64), the object/executable writers (`write_coff`/`write_pe` for Windows, `write_macho_obj`/`write_macho_exe` for macOS), the differential-test corpora for both architectures, and the `rasm-as` CLI. |
| **`winkb`** | The Windows knowledge layer: a read-only API over `windows_api.db` (Win32 functions, COM interfaces, struct layouts). Unmodified from WRASM. |
| **`mackb`** *(new)* | The macOS knowledge layer: a read-only API over `cocoa.sqlite` (Objective-C method ABI shapes, framework C function signatures, struct layouts). See [mackb](crates/mackb). |
| **`was`** | The Windows assembler front-end (`invoke`/`comcall`/`comobj`/`proc`/`frame`/`.if`/`.while`/`.include`). Unmodified from WRASM — still Win64-only; the AAPCS64/`objccall` equivalent doesn't exist yet. |
| **`ide`** | Turns a `winkb` query into renderable markdown cards. Unmodified from WRASM — still Win32-only content. |
| ~~`studio`~~ | Removed from the workspace (Windows-only Direct2D dependency). Not built. |

## Build & test

```sh
cargo build            # rasm + winkb + was + ide + mackb — builds clean on macOS arm64, no LLVM needed
cargo test              # both encoders' corpus gates (x86-64: 5,116 forms; AArch64: 1,181 forms), mackb, was, winkb, ide

# The LLVM-MC differential oracle (build/test-time only — nothing on the shipping
# path depends on it). Needs Homebrew LLVM: `brew install llvm`.
cargo test --features llvm
```

### The knowledge databases

- `winkb` reads `windows_api.db` (not committed; large). `$WINKB_DB`, default
  `E:\windows_api\windows_api.db` — a Windows-era default; irrelevant unless
  you're exercising the Win64 side on this checkout.
- `mackb` reads `cocoa.sqlite`, from the sibling `cocoa_data` repo.
  `$COCOA_DATA_DB`, default `../../../cocoa_data/cocoa.sqlite` relative to the
  crate (i.e. `cocoa_data` checked out next to `MRASM`). Missing DB degrades
  gracefully — every lookup returns `None` rather than failing the build.

## Try it

The one thing that runs end to end today is: AArch64 assembly text in, a
signed, runnable macOS executable out, with **zero external tools**.

```sh
cargo test --test macho_exe_run42 -- --nocapture
```

Or by hand, through the library directly:

```rust
use rasm::{A64Encoder, Encoder, write_macho_exe};

let m = A64Encoder.encode(".globl _main\n_main:\n  movz w0, #42\n  ret\n")?;
let exe = write_macho_exe(&m, "_main")?;
std::fs::write("hi", &exe)?;
// chmod +x hi && ./hi; echo $?   ->  42
```

Ask the macOS knowledge base things:

```sh
cargo run -p mackb --bin mackb -- method NSView frame     # -> ret=h4 args=[]  (an HFA NSRect)
cargo run -p mackb --bin mackb -- struct CGRect            # -> field names + byte offsets
cargo run -p mackb --bin mackb -- function CGRectMake       # -> framework + raw @encode signature
```

Everything under `was`/`winkb`/`ide` still targets Windows — those crates
build and their tests pass on macOS (LLVM cross-assembles fine for the
differential-oracle tests), but their *output* (COFF objects, PE executables)
isn't something you'd run on this machine. They're inherited, working, and
untouched, not yet superseded.

## Inherited from WRASM, not yet re-verified on macOS

`docs/`, `examples/`, `gpu/`, `library/`, `projects/` and `release/` are
carried over from WRASM as-is — design docs and a large `.was` demo corpus
(GDI framebuffers, a D3D11 shader Mandelbrot, a Direct2D particle fountain),
all written against Win32/COM. None of it has been touched for this port; it
documents where the *authoring layer* (macros, contracts, checks) needs to
land once AAPCS64/`objccall` exist, not where MRASM is today.

## Lineage

- **[WRASM](https://github.com/albanread/WRASM)** — the Windows original this
  is a port of; the x86-64 encoder, COFF/PE writers, and the whole `was`
  authoring-layer design are its work, carried over verbatim where not yet
  ported.
- **[JASM](https://github.com/albanread/JASM)** — source of the AArch64
  encoder (`A64Encoder`) and its corpus-gate methodology.
- **MF67** (an Objective-Forth sibling project) — source of the
  `objc_msgSend` register-marshaling design (`objc.masm`, `synth_send_thunk`)
  that MRASM's future `objccall` macro will implement.
- **cocoa_data** — the shared SQLite mirror of the macOS Objective-C surface
  (built once, queried by every native-macOS project in this portfolio) that
  `mackb` reads.

## License

MIT.
