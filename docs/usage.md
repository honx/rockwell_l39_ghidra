# Usage

## Prerequisites

- Ghidra 12.0.x (tested against 12.0.4). Other 11.x / 12.x releases will likely work — the SLEIGH grammar is stable across those versions.
- An L3902 (or compatible C40/L39 family) firmware image as a raw binary. Typical sizes are 8 KiB (single-bank), 64 KiB, 128 KiB, 256 KiB, or 512 KiB.

## Installing the module

The processor module is a drop-in Ghidra extension — no build step is required for ISA support, because Ghidra recompiles `.slaspec` files on first use.

```bash
# Replace with your Ghidra path:
GHIDRA=/home/honx/ghidra

cp -r ghidra/RockwellL39 "$GHIDRA/Ghidra/Processors/"
```

That's it. The new language `RockwellL39:LE:16:default` will appear in the language picker the next time Ghidra is launched (or when a headless run reads the language registry).

If you want to recompile the SLEIGH spec ahead of time (catches errors earlier and avoids a one-time delay on first import):

```bash
"$GHIDRA/support/sleigh" ghidra/RockwellL39/data/languages/RockwellL39.slaspec
cp ghidra/RockwellL39/data/languages/RockwellL39.sla "$GHIDRA/Ghidra/Processors/RockwellL39/data/languages/"
```

## Loading a firmware image (GUI)

1. **File → Import File…** and select your `.bin`.
2. In the Import dialog:
   - **Format:** *Raw Binary* (the dedicated `Rockwell C40/L39/L3902 firmware` loader is not yet packaged as a `.jar`; use Raw Binary until then).
   - **Language:** Click the `…` button and pick `RockwellL39:LE:16:default` / `default` compiler.
   - **Options → Base Address:** `0x0000`.
3. Click **OK**. Open the resulting program and let auto-analysis run.

The reset vector at `$FFFE/F` is automatically marked as an entry point by the pspec, so analysis starts from there.

For images **larger than 64 KiB** (typical: 128 KiB), the L3902 sees only 64 KiB of its 128 KiB EPROM at any given time, through its eight 8 KiB bank-select windows. By default Ghidra loads the first 64 KiB and you'll see the *boot-time* memory map. The bank-aware analyser scripts described next handle the runtime view automatically.

## Bank-aware analyser

Four scripts ship in `ghidra/RockwellL39/ghidra_scripts/`. Run them in
order via `-preScript` / `-postScript` to set up a Ghidra project that
correctly models the L3902's runtime banking:

```sh
$GHIDRA_INSTALL_DIR/support/analyzeHeadless /tmp/proj L39 \
    -import path/to/firmware.bin \
    -loader BinaryLoader -loader-baseAddr 0x0000 \
    -processor "RockwellL39:LE:16:default" \
    -scriptPath /path/to/repo/ghidra/RockwellL39/ghidra_scripts \
    -preScript  L3902BankingSetup.java \
    -postScript L3902ResolveRom6.java \
    -postScript L3902PropagateConfigs.java
```

What each script does:

1. **`L3902BankingSetup.java`** (Phase 1+2). Creates four overlay
   memory blocks (`cfg1`, `cfg2`, `cfg3`, `cfg4`) at `$0200-$7FFF`,
   each initialised from the appropriate physical 8 KiB banks of the
   firmware (per the contributor diagram in
   `binary/banking-configurations.png`). Locates the four
   `switch_rom_cfgX()` entry points by pattern-matching the
   four-`STI`-plus-`RTS` body in ROM6, renames each one according to
   its BSR0 value, and adds a header comment with the BSR write
   sequence. Read the firmware path either from
   `currentProgram.getExecutablePath()` or the first script argument.

2. **`L3902ResolveRom6.java`** (Phase 3). Adds a `rom6` overlay block
   at `$E000-$FFFF` initialised from file `0x6000-0x7FFF` (the
   persistent code bank), and walks every instruction in the default
   address space adding a redirect reference for any flow target in
   `[$E000, $FFFF]` to `default:(target - $8000)`. About 149 such
   references on the reference firmware — calls into the dispatcher
   at `$E81B`, the IRQ handlers at `$E2E7-$E3C2`, and the
   `switch_rom_cfgX` functions at `$E000-$E033`.

3. **`L3902PropagateConfigs.java`** (Phase 4). Walks the program's
   CFG to determine which configuration(s) each instruction runs
   under, then rewrites cross-references targeting `$0200-$7FFF`
   into the appropriate `cfgN` overlay's address space. Seeds the
   propagation with the fall-through address of every call site to a
   `switch_rom_cfgX` function. About 2125 `cfgN`-resolved references
   on the reference firmware (cfg1=460, cfg2=473, cfg3=622, cfg4=570),
   with around 1205 instructions tagged as polymorphic (shared
   between configurations — typical for the dispatcher and IRQ
   handlers).

After all four scripts run, the listing shows: `cfg1-cfg4` overlays
holding the four runtime configurations, a `rom6` overlay holding
the persistent code bank at `$E000-$FFFF`, the four
`switch_rom_cfgN` functions properly named, and runtime
cross-references resolving across both ROM6 and the cfg overlays.

The scripts are idempotent on overlay creation (they skip blocks
that already exist) but reference rewriting will add duplicate refs
on a second run. Run them once per import.

A worked example of the boot trampoline that motivates this
machinery — three stages of bank switches in 47 bytes — is in
[`../binary/elsa_microlink_336tqv.md`](../binary/elsa_microlink_336tqv.md).

## Loading a firmware image (headless)

```bash
GHIDRA=/home/honx/ghidra
PROJECT=/tmp/l39_proj
FW=/path/to/firmware.bin

rm -rf "$PROJECT" && mkdir -p "$PROJECT"

"$GHIDRA/support/analyzeHeadless" "$PROJECT" L39Project \
    -import "$FW" \
    -loader BinaryLoader \
    -loader-baseAddr 0x0000 \
    -processor "RockwellL39:LE:16:default"
```

The `-noanalysis` switch skips auto-analysis if you only want a clean import. To re-run analysis later, use `-process <name>` instead of `-import`.

## Running the test suite

```bash
GHIDRA_INSTALL_DIR=/home/honx/ghidra ./tests/run_tests.sh
```

The full suite includes:

- **`test_01_sleigh_compiles.sh`** — recompiles the SLEIGH spec and checks for errors. Always runs.
- **`test_02_opcode_decode.sh`** — generates a synthetic 64 KiB binary that exercises a curated set of R65C19 opcodes at known addresses, imports it under the new language, and asserts that disassembly matches the expected mnemonics. Always runs.
- **`test_03_e2e_firmware.sh`** — imports the real ELSA firmware from `binary/elsa_microlink_336tqv_v1.26.bin`, runs auto-analysis, and asserts on the reset vector, function count, and a few specific instructions. Skipped (with a warning) if the binary isn't present, since it's gitignored.

Each test is also runnable individually. They all honour `GHIDRA_INSTALL_DIR` and default to `/home/honx/ghidra`.

## What the module gives you

- Disassembly of the full 6502 / 65C02 base instruction set, with R65C19 indirect-mode remap correctly applied to the cc=01 ALU group.
- Disassembly of all R65C19 extensions encountered in real firmware: `STI`, `ADD`, `ASR`, `NEG`, `LAB`, `MPY`, `MPA`, `RND`, `CLW`, `TAW`, `TWA`, `PSH`, `PUL`, `PHW`, `PLW`, `EXC`, `RBA`, `SBA`, `BAR`, `BAS`, `JSB0`-`JSB7`, plus threaded-code `NXT`, `LII`, `LAI`, `LAN`, `INI`, `PHI`, `PLI`, `PIA`, `TIP`.
- Symbolic names for the L3902 vector table at `$FFE0-$FFFF` (`VEC_RESET`, `VEC_NMI`, `VEC_IRQ1`-`VEC_IRQ6`, `JSB0_target`-`JSB7_target`) and the on-chip register file at `$0000-$003F` (port latches, direction registers, BSRs, USART, FIFO control, etc.).
- Default calling convention with A/X/Y as register parameters and A as the return register, suitable for the decompiler.
- A loader source skeleton (`RockwellL39Loader.java`) ready to be packaged into a `.jar` if you want banking-aware import.
