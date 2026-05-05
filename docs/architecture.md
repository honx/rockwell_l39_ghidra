# Architecture

This document explains how the SLEIGH spec is structured and the major decisions baked into it. It is for people who need to extend or fix the module.

## SLEIGH file layout

`RockwellL39.slaspec` is one self-contained file (≈600 lines). It does **not** `@include "6502.slaspec"`, even though Ghidra ships one — the R65C19's redefinition of the `(zp,X)` and `(zp),Y` addressing modes makes inheritance impossible without rewriting the operand tables anyway, and a single-file spec is easier to audit against the datasheet.

Sections, top to bottom:

1. **Endianness, alignment, address spaces.** Little-endian, 1-byte alignment, 16-bit `RAM` as the default space, 1-byte `register` space.
2. **Register file.** `A`, `X`, `Y`, `P` (status byte) at offset `0x00`. `W` (16-bit) overlaid with `WL`/`WH` at `0x10`. `I` (16-bit) overlaid with `IL`/`IH` at `0x14`. `PC`/`SP` (16-bit) overlaid with `PCL`/`PCH`/`S`/`SH` at `0x20`. Status flags `N V B D Iflag Z C` as individual 1-byte registers at `0x30`. The `Iflag` (interrupt disable) is named with the `flag` suffix because `I` is taken by the threaded-code register.
3. **Tokens.** `opbyte` carries `op`, the standard `aaa`/`bbb`/`cc` 6502 opcode-decomposition fields, and `action`/`bitindex`/`optype` fields used for `BBR`/`BBS`/`RMB`/`SMB`. `data8` and `data16` carry signed `rel`, unsigned `imm8`, and `imm16`. Two extra one-byte tokens (`data8b`, `data8c`) exist so the multi-byte R65C19 instructions (`STI`, `RBA`, `SBA`, `BAR`, `BAS`) can have a second 8-bit operand parsed without colliding with `data8`.
4. **Macros.** `pushSR`/`popSR`/`push1`/`pop1`/`push2`/`pop2` for stack frames; `resultFlags` for the standard N/Z update; `subFlags` for the four-flag subtract update.
5. **Operand tables.** `OP1` covers the cc=01 ALU instructions and is where the R65C19 indirect-mode remap lives. `OP2` covers the cc=10 read-modify-write group. `OP2ST` and `OP2LD` add the `,Y` variants for `STX`/`LDX`. `ADDR16` / `ADDRI` / `ADDRIX` cover the absolute, absolute-indirect, and absolute-indexed-indirect modes for jumps.
6. **Instructions.** Grouped by family: cc=01 ALU, RMW shifts/inc/dec, X/Y loads/stores/compares/BIT, branches and jumps, status-register manipulation, transfers and stack moves, 65C02 bit-ops (BBR/BBS/RMB/SMB), R65C19 arithmetic, R65C19 threaded-code.

## Key decisions

### Why the addressing-mode remap matters

On stock 6502, opcode `$01` (cc=01, aaa=000, bbb=000) is `ORA (zp,X)`. On R65C19, the same opcode is `ORA (zp)` — same family, but the indirect mode no longer pre-indexes by X. Likewise `$11` (bbb=100) flips from `ORA (zp),Y` to `ORA (zp),X`. The L3902 datasheet (and the R65C19 datasheet's Appendix A) makes this explicit; if you forget about it, every `LDA (zp,X)` in the firmware is silently wrong.

The fix lives entirely in the `OP1` table: `bbb=0` exports `*(addr)` with no indexing, `bbb=4` exports `*(addr) + X`. The cc=10 / cc=00 instruction families don't use these modes, so `OP2` matches stock 65C02.

### `Iflag` rather than `I`

The 6502 status bit is conventionally called `I` (interrupt disable). The R65C19 also has a 16-bit register `I` for threaded-code execution. SLEIGH names live in one global namespace, so the status bit is renamed `Iflag` everywhere in the spec — including `pushSR`/`popSR`. This costs nothing semantically and avoids the most obvious foot-gun.

### `JSB0`-`JSB7` as `call [memory_address]`

The eight `JSB#` opcodes (`$0B`, `$1B`, ..., `$7B`) push the return address and then jump indirectly through one of the fixed words at `$FFE0`, `$FFE2`, ..., `$FFEE`. The spec models this as a normal `call [tgt]` with `tgt:2 = *:2 0xFFE_:2`, so the decompiler can resolve the target if the contents of those words are known (they typically are — the firmware initialises them statically).

The pspec attaches `JSB0_target` ... `JSB7_target` labels to those addresses so the user sees what each `JSB#` instance is actually calling.

### `BRK` vectors via NMI on the L3902

On a stock 6502 the `BRK` instruction goes through the IRQ vector at `$FFFE`. On the L3902, per L39 TRM §3.5.2, `BRK` instead vectors through the NMI/BRK shared vector at `$FFFC`. The spec follows the L3902 behaviour. Watch out: on the C2900 (an earlier sibling chip in the same family) `BRK` vectors via IRQ6 instead. If you ever target a C2900 image, this constructor needs adjusting.

### Threaded-code semantics

`NXT`, `LII`, `LAI`, `LAN`, `INI`, `PHI`, `PLI`, `PIA`, `TIP` use the 16-bit `I` register the way Forth uses its inner interpreter. `NXT` (`$8B`) is the workhorse: it loads the 2-byte word that `I` points to into `PC`, then increments `I` by 2 — i.e. "do the next threaded word and advance the instruction pointer". `TIP` (`$03`) is the threaded equivalent of `RTS` and is modelled as `return [I]` so the decompiler treats it as a function exit.

`PHI` and `PLI` push and pull `I` in opposite byte orders (PHI: high then low; PLI: low then high) — that is what the datasheet says; preserve it carefully if you refactor the macros.

### Multi-byte instructions

`STI` (3 bytes), `RBA` / `SBA` (4 bytes), `BAR` / `BAS` (5 bytes) take a second immediate operand after their primary operand. SLEIGH's token system would normally only let you read one operand of each type per instruction (`imm8` can only appear once in a row), so the spec defines extra tokens (`data8b`, `data8c`) to give those second operands their own field names. This is a minor bit of plumbing, not a semantic decision — it just keeps the grammar happy.

The displayed format strings are written without `^` joiners between an operand and a literal `","`, because that produces doubled commas in the final mnemonic. Put commas as plain separators between operands and let SLEIGH choose the spacing.

## Loader (`RockwellL39Loader.java`)

The loader extends `AbstractProgramWrapperLoader` and:

1. Accepts any binary whose length is a multiple of 8 KiB up to 512 KiB.
2. Creates a single initialised ROM block at `$0000-$FFFF` from the first 64 KiB of the file (`-loader-baseAddr 0x0000` semantics).
3. Layers uninitialised blocks for the on-chip I/O, RAM pages 0-5, and CRC so the user can label them.
4. Reads the 16-bit reset vector at `$FFFE` and registers the target as an entry point (creates `_reset` function).
5. For images larger than 64 KiB, loads each additional 64 KiB chunk as an overlay block at `$0000-$FFFF`, named `BANK_HIGH_1`, `BANK_HIGH_2`, etc. The user can switch between overlays in the listing.

The loader source compiles cleanly against the Ghidra 12.0.4 API but isn't yet built into a `.jar` — it ships as source only. Until that's done, `BinaryLoader` + `-processor RockwellL39:LE:16:default` is the standard route.

## Banking is not in the SLEIGH spec

A common question: does this module model the L3902's eight bank-select registers (`BSR0`-`BSR7`)? **No, and it shouldn't.** SLEIGH describes a fixed instruction-set architecture, not a system; bank-switching is a system-level concern that belongs in three different places, none of them the slaspec:

1. **Loader** — creates the memory blocks for every physical bank. `RockwellL39Loader.java` does this for >64 KiB images via `BANK_HIGH_n` overlays.
2. **Analyser** — tracks `STI #imm,$0018-$001F` writes and recognises which physical bank the firmware just switched into which logical window. **Not implemented**, see `open-points.md`.
3. **Manual** — the user picks the right overlay block in the listing.

Each `BSRn` is one byte. Per the L39 TRM Table 3-2b, the bit layout is `[ES3 ES2 ES1 ES0 A16 A15 A14 A13]` — four chip-select pins on the high nibble and four address bits on the low nibble. The four address bits would in principle cover sixteen 8 KiB physical banks (= 128 KiB) on a chip that's wired to use all of them. In practice, the value-to-resource mapping a given firmware sees is determined by the board: the L3902's `ES0`-`ES3` pins drive chip-select decode logic that the schematic designer chose, and the firmware writes BSR values that the schematic decodes into a particular physical bank within a particular memory device.

The `binary/elsa_microlink_336tqv.md` analysis walks through one such firmware in detail and shows how its boot is a three-stage trampoline that finally settles into a runtime banking scheme with **four named configurations** (`Cfg1`-`Cfg4`) plus four always-mapped windows for external SRAM and the persistent code bank. The four configurations swap fixed sets of 8 KiB ROM banks into the lower four CPU windows. A future BSR-aware analyser doesn't need to model arbitrary BSR writes — recognising calls to a small number of `switch_rom_cfgX()`-style entry points and following the cross-references they imply is enough to cover real firmware.

## pspec / cspec

`RockwellL39.pspec` declares the full vector table at `$FFE0-$FFFF`, all eight `JSB#` indirect-call targets, and ~50 peripheral register names at `$0000-$003F`, `$05FE-$05FF`. The vector at `$FFFE` is marked `entry="true"` so analysis kicks in there.

`RockwellL39.cspec` is straightforward: A/X/Y as register-passed parameters (1 byte each), A as the return register, SP unaffected by calls. The decompiler uses this to display routines as `f(byte a, byte x, byte y) -> byte`.
