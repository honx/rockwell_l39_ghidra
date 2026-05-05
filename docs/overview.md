# Overview

This repository is a Ghidra processor module for the **Rockwell C40 / L39 / L3902** family of single-chip modem MCUs. The L39 series was used in 14.4-, 28.8-, and 33.6-kbps consumer modems through the mid-1990s; the L3902 specifically pairs an enhanced 6502 core with a 16550A-style host bus, an 8 KiB internal ROM, 1470 bytes of RAM, and an 8-register memory-banking scheme that addresses up to 512 KiB of external ROM in 8 KiB pages.

The module exists because mainline Ghidra ships with a `6502` and a `65C02` language, but neither covers the **R65C19 / L39 instruction-set extensions**, and neither models the L3902's banked memory map or peripheral register file. Trying to load an L3902 firmware as plain 65C02 produces wrong disassembly within a few hundred bytes, because the R65C19 reuses several 6502 NMOS-illegal opcode slots for new instructions and quietly redefines two indirect addressing modes.

## What's in the repository

```
.
├── CLAUDE.md                 # Quick orientation for future Claude Code sessions.
├── docs/
│   ├── overview.md           # This file.
│   ├── usage.md              # How to install the module and load firmware.
│   ├── architecture.md       # How the SLEIGH spec / loader are laid out.
│   └── open-points.md        # Known gaps, unanswered questions, future work.
├── ghidra/RockwellL39/       # The Ghidra processor module (drop-in extension).
│   ├── data/languages/
│   │   ├── RockwellL39.slaspec   # SLEIGH ISA description (source of truth).
│   │   ├── RockwellL39.ldefs     # Language registration.
│   │   ├── RockwellL39.pspec     # Vector table + I/O register symbols.
│   │   ├── RockwellL39.cspec     # Default calling convention.
│   │   └── RockwellL39.sla       # Compiled SLEIGH (regenerated; gitignored).
│   ├── src/main/java/rockwelll39/
│   │   └── RockwellL39Loader.java # Loader that maps banked images.
│   ├── Module.manifest
│   ├── extension.properties
│   └── build.gradle
├── tests/                    # Smoke tests and end-to-end checks.
│   ├── run_tests.sh
│   ├── lib/common.sh
│   ├── test_01_sleigh_compiles.sh
│   ├── test_02_opcode_decode.sh
│   ├── test_03_e2e_firmware.sh
│   ├── scripts/AssertDisassembly.java
│   └── fixtures/             # Generated test binaries.
├── reference/                # Datasheets (gitignored).
└── binary/                   # Reference firmware (gitignored).
```

## Target hardware: what the module covers

- **CPU:** Enhanced 6502 (R65C19 core). Inherits the 65C02 instruction set, then adds a 16-bit `W` register (multiply accumulator), a 16-bit `I` register (threaded-code execution), and roughly 43 new instructions across four groups: arithmetic (MPY/MPA/ADD/ASR/NEG/RND/CLW/LAB), bit operations (RBA/SBA/BAR/BAS), stack (PSH/PUL/PHW/PLW/PHI/PLI/PIA), and threaded-code (NXT/LII/LAI/LAN/INI/TIP/JPI). Two indirect addressing modes are repurposed: the stock 6502 `(zp,X)` becomes `(zp)`, and `(zp),Y` becomes `(zp),X`.
- **Memory map (CPU view):** I/O registers at `$0000-$003F`, dual-port host bus / scratchpad RAM at `$0020-$0032`, USART registers at `$0033-$003F`, internal RAM scattered across pages 0-5 (`$0040-$05FD`, total 1470 bytes), CRC at `$05FE-$05FF`, ES4 region at `$0600-$07FF`, then seven 8 KiB external-bank windows at `$0800-$DFFF` (selected by `BSR0`-`BSR6` at `$0018-$001E`), and an 8 KiB internal ROM at `$E000-$FFFF` (or banked via `BSR7`).
- **Vectors at top of address space:** RESET (`$FFFE/F`), NMI / BRK (`$FFFC/D`), six prioritised IRQs (`$FFF0/1` through `$FFFA/B`), plus eight fixed-target subroutine vectors at `$FFE0`-`$FFEE` for the `JSB0`-`JSB7` instructions.

## Reference inputs

Three vendor PDFs in `reference/` are the load-bearing source of truth (gitignored — they're not redistributable):

- **`R65C19_Data_Sheet_199202.pdf`** — defines the CPU. Appendix A is the opcode matrix and instruction summary; the rest of the SLEIGH spec is derived from it.
- **`C40_L39_Technical_Reference_Manual.pdf`** — defines the L3902 system: memory map, banking, peripheral register file, vectors. Section 3 is the relevant chapter.
- **`RC240VFC.pdf`** — datasheet for the modem-DSP front-end. Not used for ISA work but useful when labelling routines that drive the modem chip.

The reference firmware is `binary/elsa_microlink_336tqv_v1.26.bin` (128 KiB, ELSA MicroLink 33.6 TQV, build date 1997-07-18). It is used to validate the module end-to-end. The reset vector (`$FFFE/F`) reads `c0 ff` → reset target `$FFC0`, which decodes as `SEI` / `STI #$70,$1B` / `JMP $6200` — a textbook L3902 boot stub that initialises BSR3 and jumps into the freshly-mapped bank.

## Status

The module is **complete enough for production reverse-engineering work** on L3902 firmware. Auto-analysis on the reference image discovers 204 functions and decodes 2179 instructions in roughly four seconds, with no spurious mnemonics. The remaining gaps are listed in [`open-points.md`](open-points.md); none of them block typical analysis.
