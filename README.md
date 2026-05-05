# rockwell_l39_ghidra

Ghidra processor module for the **Rockwell C40 / L39 / L3902** family
of single-chip modem MCUs (1992-1998), plus a worked-example
reverse-engineering analysis of an ELSA MicroLink 33.6 TQV firmware.

The L39 family pairs an enhanced 6502 core (Rockwell R65C19, with ~43
extra instructions and two silently-redefined indirect addressing
modes) with a 16550A-emulating dual-port FIFO, 16-bit timers, USART,
and a memory-banking unit that maps up to 512 KiB of external memory
through a 64 KiB CPU view in 8 KiB pages. Mainline Ghidra ships nothing
for it; this module fills that gap.

## What's where

```
.
├── ghidra/RockwellL39/        Drop-in Ghidra processor module.
│   ├── data/languages/        SLEIGH spec + supporting metadata.
│   │   ├── RockwellL39.slaspec    full ISA (~600 lines)
│   │   ├── RockwellL39.ldefs      language registration
│   │   ├── RockwellL39.pspec      vector table + I/O register symbols
│   │   └── RockwellL39.cspec      default calling convention
│   ├── ghidra_scripts/        Bundled scripts.
│   │   ├── L3902BankingSetup.java  Creates per-configuration overlays
│   │   │                           and identifies switch_rom_cfgX()
│   │   │                           functions for the L3902 banking model.
│   │   └── L3902ResolveRom6.java   Adds a rom6 runtime-view overlay and
│   │                               redirects $Exxx references to the
│   │                               corresponding boot-time-view $6xxx
│   │                               (where ROM6 lives in the file).
│   ├── src/main/java/         Java loader for banked images.
│   ├── Module.manifest        Ghidra extension metadata.
│   ├── extension.properties
│   └── build.gradle
│
├── docs/                      Project documentation.
│   ├── overview.md            What this is, status, repo layout.
│   ├── usage.md               Install, GUI/headless import, tests.
│   ├── architecture.md        SLEIGH spec layout, key decisions.
│   ├── open-points.md         Known gaps, missing opcodes, future work.
│   └── README.md              Index.
│
├── tests/                     Three-tier test suite (all run in CI).
│   ├── run_tests.sh           Aggregate runner.
│   ├── test_01_sleigh_compiles.sh
│   ├── test_02_opcode_decode.sh
│   ├── test_03_e2e_firmware.sh
│   ├── lib/common.sh
│   └── scripts/               Ghidra postscripts (assertions).
│
├── binary/                    The reverse-engineering target.
│   ├── elsa_microlink_336tqv.md       Full analysis writeup (~500 lines).
│   ├── banking-configurations.png     Contributor diagram of the runtime
│   │                                  banking scheme.
│   └── elsa_microlink_336tqv_v1.26.bin Firmware blob (gitignored).
│
├── reference/                 Vendor datasheets (gitignored — not ours
│   │                          to redistribute).
│   ├── R65C19_Data_Sheet_199202.pdf   CPU instruction set
│   ├── C40_L39_Technical_Reference_Manual.pdf  System / banking
│   └── RC240VFC.pdf           Modem DSP front-end
│
├── talk/                      CCC Congress talk in Beamer.
│   ├── slides.tex             ~1100 lines, 42 slides + speaker notes.
│   ├── title-graphic.tex      TikZ diagram of the boot trampoline.
│   ├── Makefile               make slides / notes / handout / all.
│   ├── README.md              Build / presenter notes.
│   ├── slides.pdf             Reference render — 42 pages, slide-only.
│   ├── slides-notes.pdf       Slide + speaker notes side-by-side.
│   └── slides-handout.pdf     Handout mode, overlays collapsed.
│
├── CLAUDE.md                  Quick orientation for future Claude Code
│                              sessions working in this repo.
└── README.md                  This file.
```

## Project overview

The work has three intertwined deliverables:

1. **A Ghidra processor module** for the R65C19 ISA / L3902 platform
   — the part you'd want to install in your own Ghidra to disassemble
   any firmware running on this chip family. Drop-in: copy
   `ghidra/RockwellL39/` into `$GHIDRA_INSTALL_DIR/Ghidra/Processors/`
   and the language `RockwellL39:LE:16:default` is available from then
   on. See `docs/usage.md` for the import recipe.

2. **A test suite that proves the module works**, runnable headless
   without a vendor firmware. Three tiers: SLEIGH spec compiles,
   opcode-decode fixture (43 hand-picked opcodes covering every R65C19
   extension), end-to-end import of the reference firmware (17
   invariants checked). Run `tests/run_tests.sh`. The end-to-end test
   skips cleanly if the firmware blob isn't present, so CI can run
   the first two tiers without it.

3. **A reverse-engineering writeup** of the ELSA MicroLink 33.6 TQV
   firmware as a worked example of using the module on a non-trivial
   target. The firmware is a 1997 German consumer modem supporting
   V.34 / V.42bis / Class 2 fax / V.253 voice / H.324 video over POTS,
   built around a single 128 KiB EPROM that the L3902 swap-maps
   through eight 8 KiB windows in four named runtime configurations.
   See `binary/elsa_microlink_336tqv.md`.

A fourth artefact lives in `talk/`: a Beamer talk for CCC Congress on
the LLM-assisted RE workflow that produced the rest of the repo,
including the two corrections from the contributor that landed during
the work.

## Quick start

```sh
# 1. Install the Ghidra module.
cp -r ghidra/RockwellL39 $GHIDRA_INSTALL_DIR/Ghidra/Processors/

# 2. Run the tests (assumes GHIDRA_INSTALL_DIR is set or defaults to
#    /home/honx/ghidra; reference firmware is optional for the e2e test).
./tests/run_tests.sh

# 3. Import a firmware via headless Ghidra.
$GHIDRA_INSTALL_DIR/support/analyzeHeadless /tmp/proj L39 \
    -import path/to/firmware.bin \
    -loader BinaryLoader \
    -loader-baseAddr 0x0000 \
    -processor "RockwellL39:LE:16:default"
```

## Status

- **Module**: working on real-world R65C19 / L3902 firmware. Disassembles
  all 256 opcode slots used by the reference image; auto-analysis finds
  204 functions / 2222 instructions in ~4 s. SLEIGH spec is 600 lines,
  loader is 150 lines of Java.
- **Tests**: 89 assertions across 4 test scripts, all green against
  Ghidra 12.0.4. Two earlier RE bugs are now regression-tested.
- **Analysis**: ~500 lines of writeup covering the boot trampoline,
  the four-configuration runtime banking model, the dispatcher pattern
  at `$E81B`, and string-derived feature inventory. Several open
  questions documented in the writeup's last section.
- **Talk**: 42-slide Beamer deck, builds cleanly on TeX Live 2025 +
  beamer + metropolis.

## Known limitations

Documented in detail in `docs/open-points.md`. Highlights:

- Three R65C19 opcodes (`JPI`, `ADD zp`, `ADD zp,X`) couldn't be read
  off the datasheet's opcode matrix scan with confidence and aren't
  encoded. None appear in the reference firmware, but a different
  R65C19 image might use them.
- BCD math is modeled as binary in the SLEIGH p-code (the `D` flag
  is set/cleared but no decimal correction is emitted). Affects
  decompilation of the few `SED`-bracketed regions, not disassembly.
- Bank-aware cross-references: Phases 1+2+3 done (per-configuration
  overlays, `switch_rom_cfgX()` detection, ROM6 reference resolver
  with 149 redirects on the reference firmware), Phase 4
  (configuration propagation through the CFG + cfgN cross-reference
  rewriting) outstanding. See `docs/open-points.md`.
- The Java loader works but isn't packaged as a `.jar` extension yet —
  use `BinaryLoader` + `-processor RockwellL39:LE:16:default` until
  it is.

## How this was built

The module, tests, docs, and analysis were written in
~four working sessions of pair-programming with an LLM (Claude in agentic
mode), with shell + file access and the vendor PDFs as inputs. The talk
in `talk/` describes the workflow honestly, including the two
substantive bugs the LLM produced and the human reviewer who caught
them. The project is open source (Apache 2.0); patches and extensions
are welcome.

`CLAUDE.md` is a brief orientation file aimed at future Claude Code
sessions opening this repo. Humans can read it too — it's a slightly
denser tour than this README.

## Acknowledgements

- Anonymous contributor with hands-on Rockwell-modem RE experience for
  the BSR-encoding correction (commit `20026e9`) and the four-named-
  configurations correction (commit `660f41d`). The repo is correct
  because of those reviews.
- Rockwell International for shipping clear, well-organised datasheets
  in the early 1990s, and ELSA AG for shipping a modem worth taking
  apart 28 years later.
