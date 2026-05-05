# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## Repository purpose

Two intertwined deliverables:

1. **A Ghidra processor module** for the Rockwell C40 / L39 / L3902
   modem MCU family — `ghidra/RockwellL39/`. Mainline Ghidra ships
   nothing for this chip family. This module fills that gap.
2. **A reverse-engineering analysis** of an ELSA MicroLink 33.6 TQV
   firmware as a worked example of using the module —
   `binary/elsa_microlink_336tqv.md` (~500 lines).

There is also a CCC Congress talk (`talk/`) describing the LLM-assisted
workflow that produced the rest of the repo, and a top-level `README.md`
aimed at humans browsing the GitHub page.

## Layout

```
ghidra/RockwellL39/        Ghidra extension (drop-in)
docs/                      overview / usage / architecture / open-points
tests/                     three-tier test suite (sleigh / opcode / e2e)
binary/                    reference firmware + analysis writeup
reference/                 vendor PDFs (gitignored)
talk/                      Beamer talk for CCC Congress
```

## Target platform

- **Device:** ELSA MicroLink 33.6 TQV (also branded 14.4 TQ / 28.8 TQ —
  same firmware family). Strings inside the image show `(C) ROCKWELL`
  with an ELSA notice and build date `18.07.97`.
- **Firmware image:** `binary/elsa_microlink_336tqv_v1.26.bin`,
  exactly **131072 bytes (128 KiB)**, raw — no header. Gitignored
  because it isn't ours to redistribute.
- **CPU:** Rockwell **R65C19** — enhanced 65C02 with ~43 added
  instructions. Two indirect addressing modes are silently redefined:
  `(zp,X)` becomes `(zp)`, `(zp),Y` becomes `(zp),X`. Loading as plain
  65C02 produces wrong disassembly inside ~1 KiB.
- **Platform:** Rockwell **C40 / L39** family with **RC240VFC** DSP
  front-end. The L39 manual defines the memory map, banking, peripheral
  registers, interrupt vectors, and DSP command interface.

## Reference material (`reference/`)

These three PDFs are the authoritative spec for everything in the
binary. Cross-check against them before guessing.

- `R65C19_Data_Sheet_199202.pdf` — CPU-level: opcode set, register
  file, on-chip timers/USART. The slaspec is derived from this.
- `C40_L39_Technical_Reference_Manual.pdf` — system-level: memory
  map, bank switching, I/O register layout, peripherals, interrupt
  model. The pspec is derived from this.
- `RC240VFC.pdf` — DSP/modem datasheet: command interface, signaling,
  line interface. Useful for labelling routines that drive the modem
  chip; not used for ISA work.

## Working in Ghidra

The user's Ghidra is at `/home/honx/ghidra` (Ghidra 12.0.4); the module
is already installed there. To re-install (or install elsewhere):

```sh
cp -r ghidra/RockwellL39 $GHIDRA_INSTALL_DIR/Ghidra/Processors/
```

The language is `RockwellL39:LE:16:default`. Import a firmware via the
GUI's *Raw Binary* loader with that language and base address `0x0000`,
or headless:

```sh
$GHIDRA_INSTALL_DIR/support/analyzeHeadless /tmp/proj L39 \
    -import path/to/firmware.bin \
    -loader BinaryLoader -loader-baseAddr 0x0000 \
    -processor "RockwellL39:LE:16:default"
```

The Java loader `RockwellL39Loader.java` is source-only — not yet
packaged into a `.jar`. Use `BinaryLoader` + `-processor` until it is.

## Boot trampoline (reference firmware)

The ELSA firmware boots through three bank-switching stages. Knowing
this is essential when reading the disassembly:

```
$FFC0 (file 0xFFC0)   SEI / STI #$70,$1B / JMP $6200    -- swap BSR3
$6200 (now file 0x0200)  STI #$73,$1F / JMP $E7B6        -- swap BSR7
$E7B6 (now file 0x67B6)  hardware init + 8 BSR writes    -- establish Cfg2
```

The runtime memory map is **four named banking configurations**
(Cfg1-Cfg4) that the firmware switches between via four
`switch_rom_cfgX()` functions. After reset, Cfg2 is active. Three
windows are always RAM (`$8000-$DFFF` = RAM0/1/2 = 24 KiB external
SRAM); `$E000-$FFFF` is always ROM6 (the persistent dispatcher bank).
The four lower windows (`$0800-$7FFF`) swap between sets of physical
ROM banks per configuration. Full table in
`binary/elsa_microlink_336tqv.md`.

## Tests

```sh
./tests/run_tests.sh
```

- `test_01_sleigh_compiles.sh` — recompile the slaspec, fail on errors.
- `test_02_opcode_decode.sh` — synthetic 64 KiB fixture covering 43
  R65C19/65C02/6502 opcodes; assert each disassembles correctly.
- `test_03_e2e_firmware.sh` — import the reference firmware, run
  auto-analysis, assert on 17 invariants (boot stubs, runtime IRQ
  vectors, Cfg2 BSR sequence, mnemonic counts, function count).
  Skips cleanly if the gitignored firmware is absent.

## Caveats / known holes in the SLEIGH spec

- `JPI` (threaded-code "jump indirect with return in I") not encoded
  — opcode wasn't legible in the datasheet matrix scan. Not used by
  the reference firmware.
- `ADD zp` / `ADD zp,X` — only `ADD #imm` at `$89` is encoded. ZP
  variant opcodes weren't legible. Not used by the reference firmware.
- BCD math modeled as binary (D-flag set/cleared, no decimal correction
  p-code). Reference firmware uses `SED` 6 times; affects decompilation,
  not disassembly.
- No cycle counts — spec is for analysis only, not emulation.
- No bank-aware cross-reference analyser. Following calls across
  configurations is a manual exercise. See `docs/open-points.md`.

## Conventions for analysis output

- When labelling routines or data structures, cite the datasheet
  section (e.g. `// L39 TRM §3.5 IRQ vectors`) rather than re-deriving
  the explanation. The PDFs are the source of truth; CLAUDE.md and
  notes should point at them, not duplicate them.
- The firmware contains German-language strings
  (`programmiertechnichen Gruenden`, `Werte des fernen Modems`,
  `Konfiguration:`) and ELSA/Rockwell co-branding. Treat both
  languages as expected, not as corruption.
- When recompiling the slaspec: `$GHIDRA_INSTALL_DIR/support/sleigh
  ghidra/RockwellL39/data/languages/RockwellL39.slaspec`. Copy the
  resulting `.sla` into the install, or rerun an import (Ghidra
  recompiles on first use if the `.sla` is missing or older than the
  slaspec).
