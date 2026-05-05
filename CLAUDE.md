# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

This is a **reverse-engineering workspace**, not a buildable software project. There is no source tree, build system, or test suite — only the firmware image under analysis and the vendor datasheets needed to interpret it. Work in this repo consists of static analysis (Ghidra, scripts, notes) against `binary/elsa_microlink_336tqv_v1.26.bin`.

## Target

- **Device:** ELSA MicroLink 33.6 TQV modem (also branded 14.4 TQ / 28.8 TQ — same firmware family). Strings inside the image show `(C) ROCKWELL` followed by an ELSA notice and build date `18.07.97`.
- **Firmware image:** `binary/elsa_microlink_336tqv_v1.26.bin`, exactly **131072 bytes (128 KiB)**, raw — no header, no executable container (`file` reports `data`). Treat it as a flat ROM dump to be loaded at the device's reset/code base.
- **CPU:** Rockwell **R65C19** — a 6502-derived 8-bit microcontroller (CMOS 65C02 core with extra opcodes, internal registers, and on-chip peripherals). Code is **6502-family machine code**, little-endian, 16-bit address space with banking/paging handled by the L39 platform.
- **Modem chipset / platform:** Rockwell **C40 / L39** family with **RC240VFC** DSP front-end. The L39 manual defines the memory map, banking, peripheral registers, interrupt vectors, and DSP command interface that the firmware drives.

## Reference material (`reference/`)

These three PDFs are the authoritative spec for everything in the binary. When analyzing code, cross-check against them before guessing.

- `C40_L39_Technical_Reference_Manual.pdf` — system-level: memory map, bank switching, I/O register layout, peripherals, interrupt model. **Start here** to set up the Ghidra memory map.
- `R65C19_Data_Sheet_199202.pdf` — CPU-level: opcode set (including R65C19-specific extensions beyond stock 65C02), register file, on-chip timers/UART. Use this to build/verify a Ghidra processor spec — stock 6502/65C02 SLEIGH will not decode all instructions correctly.
- `RC240VFC.pdf` — DSP/modem datasheet: command interface, signaling, line interface. Most "what does this routine do" answers for modem-control code live here.

## Working in Ghidra

A processor module for this CPU lives in `ghidra/RockwellL39/` and has been smoke-tested against the firmware. Install it by copying the directory to `$GHIDRA_INSTALL_DIR/Ghidra/Processors/RockwellL39/`. The user's Ghidra is at `/home/honx/ghidra` (Ghidra 12.0.4); the module is already installed there.

**What the module provides:**
- Language `RockwellL39:LE:16:default` covering R65C19 / L3902 ISA: full 6502 + 65C02 base, the (zp,X)/(zp),Y → (zp)/(zp),X remap, and R65C19 extensions (STI, ADD, ASR, NEG, LAB, MPY, MPA, RND, CLW, TAW/TWA, PSH/PUL, PHW/PLW, EXC, RBA/SBA, BAR/BAS, JSB0-7, threaded-code NXT/LII/LAI/LAN/INI/PHI/PLI/PIA/TIP).
- Default symbols for the L3902 vector table at `$FFE0-$FFFF` and for I/O / bank-select registers at `$0000-$003F`.
- A loader (`RockwellL39Loader.java`) that recognizes raw-binary firmware images and creates I/O, RAM, CRC, and ROM blocks per the L39 TRM. Uses BinaryLoader + `-processor RockwellL39:LE:16:default` works fine if the loader hasn't been compiled.

**Reset vector for the reference image:** file offset `0xFFFE/F` reads `c0 ff` → reset target `$FFC0`. Bytes at `$FFC0` decode as:
```
ffc0: SEI
ffc1: STI #$70, $1B          ; configure BSR3 ($001B) for ES1+ES2+ES3 select
ffc4: JMP $6200               ; jump into freshly-mapped bank
```
This confirms the firmware uses the documented L3902 banking via BSRs and the 64 KiB CPU window is mapped 1:1 to the first half of the file at reset.

**Caveats / known holes in the SLEIGH spec:**
- `JPI` (threaded-code "jump indirect with return in I") is not encoded — its opcode wasn't captured cleanly from the datasheet matrix. Add when seen in the wild.
- `ADD zp` / `ADD zp,X` (only `ADD #imm` at `$89` is decoded). The ZP variants' opcodes weren't legible in the matrix.
- BCD math is modeled as binary (D-flag set/cleared but no decimal correction p-code).
- No cycle counts — the spec is for analysis only, not emulation.

When extending: the slaspec is `ghidra/RockwellL39/data/languages/RockwellL39.slaspec`; recompile via `$GHIDRA_INSTALL_DIR/support/sleigh path/to/RockwellL39.slaspec` and copy the resulting `.sla` into the install (or rerun an import — Ghidra recompiles the slaspec on first use if the `.sla` is missing).

## Conventions for analysis output

- When labeling routines or data structures, cite the datasheet section (e.g. `// L39 TRM §4.3 bank register`) rather than re-deriving the explanation. The PDFs are the source of truth; CLAUDE.md and notes should point at them, not duplicate them.
- The firmware contains German-language strings (`programmiertechnichen Gruenden`, etc.) and ELSA/Rockwell co-branding — treat both languages as expected, not as corruption.
