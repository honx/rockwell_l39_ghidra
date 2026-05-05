# Open points

Things that aren't done yet, things we know are wrong or missing, and things worth investigating. Roughly ordered by impact on day-to-day analysis: most-impactful first.

## ISA gaps

### `JPI` (jump indirect with return in I) — opcode unknown

R65C19 datasheet Appendix A lists `JPI` as a 3-byte threaded-code instruction (table A-5: "PC+1 → I, (I) → PC, I+2 → I"). It functions as an indirect JSR that stashes the return address in the `I` register instead of on the stack. **Its opcode could not be read confidently from Table A-1's matrix scan.** None of the column-3 or column-B slots that fit the encoding profile (3 bytes, 5 cycles, takes an absolute operand) are clearly labelled `JPI` in the OCR.

If a future analyst encounters an unknown 3-byte opcode that disassembles oddly and immediately precedes a 16-bit value pointing into a jump table, that's likely `JPI`. Add it to the slaspec then.

**Status against the reference firmware:** a sweep across the disassembled ELSA image found zero unknown / invalid mnemonics, so the reference firmware does not appear to use `JPI`. This is consistent with `JPI` being intended for compiled-language run-times (Forth-style threaded interpreters), not for hand-written modem firmware.

### `ADD zp` and `ADD zp,X` — opcodes unknown

Datasheet Table A-3 lists `ADD` with three addressing modes: `IMM` (2 bytes, 2 cycles), `ZP` (2 bytes, 3 cycles), `ZP,X` (2 bytes, 4 cycles). The IMM form is at `$89` (the slaspec encodes it). The ZP and ZP,X forms are not at `$65` / `$75` (those are still standard `ADC`); their actual opcodes are not visible in the matrix as transcribed. Same situation as `JPI` — wait until they show up in real code, then map them.

**Status against the reference firmware:** also not encountered. The image uses 12 `ADC` instructions (carry-propagating add, standard 6502) and the spec's `ADD #imm` once or twice; no plain ZP-mode add-without-carry.

### BCD math is binary-only

Stock 6502 `ADC` and `SBC` honour the `D` flag and do decimal-correction at the end of the operation. The slaspec sets and reads `D` but does not perform the correction. For pure analysis this is fine; it would matter only if someone tried to use the spec to drive an emulator.

**Status against the reference firmware:** `SED` appears 6 times in the disassembly, so the firmware does briefly enter BCD mode (probably for AT-command result-code formatting or LCD-style number printing). Disassembly of those windows is correct but the decompiler will model the bracketed `ADC`/`SBC` as binary arithmetic, which is wrong for those handful of instructions. Adding a real BCD p-code expansion would close this.

### No cycle counts

Constructors don't carry cycle attributes. Doesn't affect Ghidra's analysis or decompilation. Add if a timing-sensitive workflow needs them.

## Loader / tooling

### Loader not packaged as `.jar`

`RockwellL39Loader.java` is source-only. Until it is built into an extension `.jar` and dropped in `$GHIDRA_INSTALL_DIR/Extensions/Ghidra/`, users have to load via the generic `BinaryLoader` and pick the language manually. Building is `gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR` from `ghidra/RockwellL39/`, but the existing `build.gradle` hasn't been validated against a real install yet — there will likely be small fix-ups (path to `buildExtension.gradle`, possibly a `Module.manifest` dependency adjustment).

### Banking is exposed as overlays only

For images >64 KiB, the loader currently creates `BANK_HIGH_n` overlay blocks at `$0000-$FFFF`. That is enough to disassemble each physical bank but does not model the actual `BSR` register semantics — Ghidra has no way to know which logical 8 KiB window each bank physically maps into at any given point in time. A proper solution is some combination of:

- A scripted analyser that watches `STI #imm,$001N` writes to BSR registers and emits cross-references to the overlay block that would be visible after that bank-switch.
- An "active bank" annotation per code region (probably stored as a Ghidra Equate or program property).

Neither is implemented.

### No BSR-aware cross-referencing

Following from the above: when the firmware does `STI #$70,$1B` followed by `JMP $6200`, Ghidra correctly disassembles both instructions but does not understand that `$6200` after that bank switch is in a different physical bank than `$6200` before it. A user-driven workaround is to re-import the firmware with a non-zero `File Offset` to inspect the post-switch view; an automated workaround is the analyser sketched above.

The reference ELSA image is a particularly clear example of why this matters: its boot is a **three-stage trampoline**, and each stage's `JMP` target reads from a *different* physical bank than the bank you'd see by linearly disassembling the file. The first stage at `$FFC0` jumps to `$6200`, but `$6200` after the BSR write reads from file offset `0x0200`, not `0x6200`. Without bank-aware xrefs, a Ghidra user has to follow that chain manually with the binary loader's "File Offset" knob — which we walk through end-to-end in `binary/elsa_microlink_336tqv.md`. An automatic analyser that recognised the `STI #imm,$001x; JMP $abs` pattern and computed the post-switch target would turn that manual walk into a one-click follow-jump.

A second observation from the same firmware sharpens what the analyser should look like. The ELSA modem doesn't reprogram BSRs in arbitrary ways at runtime — it switches between **four named, hand-tuned configurations** (Cfg1-Cfg4 in the firmware author's terminology) using four small dispatcher functions named `switch_rom_cfgX()`. Each configuration is a fixed 8-byte BSR-value vector. So the realistic shape of the analyser is:

1. Recognise calls to one of (a small number of) configuration-switch functions.
2. For each call site, annotate the configuration that is active *after* the call.
3. Resolve cross-bank references in subsequent code against the active configuration's overlay.

That is much more tractable than tracking arbitrary BSR writes. It also matches how real banked-ROM firmwares are written in practice: programmers don't enjoy deriving BSR values by hand; they use named macros / functions for the configurations they actually need.

### CRC peripheral is opaque

The slaspec defines `crc_init` as a p-code op but never invokes it; the pspec exposes `CRC_L`, `CRC_H` symbols at `$05FE/F` and that's the extent of CRC modelling. If the firmware uses the on-chip CRC heavily, an analyser that recognises the `STA $05FE` / `LDA $05FE` / `LDA $05FF` idiom and labels the surrounding code as "CRC initialise" / "CRC feed" / "CRC read" would pay for itself quickly.

## Spec / display polish

### Status flag pushes / pulls don't preserve bit 5

The 6502 status byte has bit 5 hard-wired to 1 when pushed; the slaspec's `pushSR` macro just packs the seven defined flags and uses `0xff` as the initial mask. The unused bit positions (5 in particular) end up as 1 by default, which matches hardware, but if anyone later refactors the macro to start from `0` instead of `0xff` they'll silently break this.

### `LAB` constructor uses local labels

The `LAB` instruction (absolute value of A, treated signed) is implemented with a `<skip>` local label and a `goto inst_next`. That works but is a little ugly; a cleaner expression would use SLEIGH's conditional assignment idiom. Cosmetic.

### Mnemonic display for `EXC`

`EXC zp,X` displays as `EXC 0x12,X` — fine, but other R65C19 specs use the spelling `EXC $12,X` (dollar-prefix). Ghidra's hex-vs-zero-x preference is global and not the slaspec's call.

## Documentation

### No instruction-by-instruction reference

`docs/architecture.md` describes the structure, but there isn't an "every R65C19 mnemonic, what it does, what flags it touches" reference. The R65C19 datasheet *is* that document, but having a one-page cheat-sheet inside the repo would help when reading firmware without the PDF open. Not critical.

### The loader source has no Javadoc

`RockwellL39Loader.java` has a top-of-file block comment that explains the convention. Methods don't have Javadoc. Fine for now; revisit if the loader grows.

## Tests

### Synthetic opcode-decode test covers a curated subset

`tests/test_02_opcode_decode.sh` exercises ~20 opcodes covering each major instruction family. It is **not** an exhaustive 256-opcode sweep. A complete sweep would assemble each opcode at a fresh address with all required operand bytes filled in and assert on the disassembled mnemonic; the matrix is in the datasheet (Table A-1) so this is mostly mechanical. Worth doing if the spec is ever significantly refactored.

### E2E test depends on the gitignored binary

`tests/test_03_e2e_firmware.sh` requires `binary/elsa_microlink_336tqv_v1.26.bin`, which is gitignored because the firmware isn't ours to redistribute. The test currently skips with a clear message if the file is missing. CI without the file therefore can't validate the end-to-end path.

A safer setup would publish a small synthetic firmware (with our own code that exercises the BSR registers, vector table, and a representative spread of R65C19 instructions) as a committed fixture, alongside the optional real-firmware test.

## Hardware variants

The slaspec is named `RockwellL39` and registers as a single language `RockwellL39:LE:16:default`. The C40, L3900, L3902, C2900, C3900, and C4000 are all handled by the same definition because their CPU cores are identical. The differences between them (RAM size, ROM size, BRK vector destination, FIFO behaviour) are platform-level and live in the pspec / loader, not the SLEIGH spec.

If anyone needs to disassemble a C2900 image — same CPU, but `BRK` vectors via IRQ6 rather than NMI — the cleanest fix is a separate variant `RockwellL39:LE:16:C2900` that includes the same slaspec but ships a different `BRK` constructor. Today the spec hard-codes the L3902/L3900 behaviour.
