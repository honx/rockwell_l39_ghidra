# ELSA MicroLink 33.6 TQV firmware v1.26 — analysis

A reverse-engineering walkthrough of `elsa_microlink_336tqv_v1.26.bin`, the
mask-ROM image of the ELSA MicroLink 33.6 TQV consumer modem. All findings
here come from static analysis with the in-tree `RockwellL39:LE:16:default`
Ghidra processor module, cross-referenced against the L39 / R65C19 / RC240VFC
datasheets in `reference/`. Where I'm guessing rather than reading I say so.

> Many thanks to the contributor who corrected an early version of this
> analysis on the BSR encoding — the file *is* a single banked image, not
> two chips. The corrected interpretation is below.

## TL;DR

- ELSA MicroLink 33.6 TQV, German external modem, build dated `18.07.97 12:34`,
  manufactured by ELSA in Aachen, branded "Rockwell" inside.
- 128 KiB single EPROM, sliced into sixteen 8 KiB physical banks numbered
  0-15 (file offsets `0x00000-0x1FFFF`). The L3902's eight bank-select
  registers (`BSR0`-`BSR7`, at `$0018-$001F`) each map one of those physical
  banks into one of eight 8 KiB windows in the CPU's 64 KiB logical address
  space. The firmware uses all 16 physical banks.
- Boot is a **three-stage trampoline**: `$FFC0` (1st stage) banks bank 0 in,
  jumps to `$6200` (= file `0x0200`); `$0200` (2nd stage) banks bank 3 in
  over `$E000-$FFFF`, jumps to `$E7B6` (= file `0x67B6`); `$67B6` (3rd stage,
  the real hardware initialiser) programs all eight BSRs to the runtime
  memory map and continues into the main firmware.
- Same firmware image services three product variants: 14.4 TQ, 28.8 TQ and
  33.6 TQ. The MicroLink-33.6-TQV claim ships with V.34 modulation, V.42bis
  compression, V.42/MNP error correction, **Class 2 fax (T.30)**, **+V voice
  mode (V.253)**, and **H.324 video conferencing**.
- The on-chip Rockwell Digital Modem Processor is driven through the
  dual-port host bus at `$0020-$0032` in 16550A-emulation mode — the
  firmware presents itself to the host PC as a 16550A UART regardless of
  the underlying signalling.

## Hardware platform

The L3902 is a single-chip modem MCU: it pairs a Rockwell-extended 6502
core (the R65C19 ISA) with a 16550A-emulating dual-port FIFO, two 16-bit
timers, two 17-bit precision time generators, a USART, and an 8-register
bank-switching unit that lets the 16-bit CPU address up to 512 KiB of
external memory in 8 KiB pages. The ELSA board pairs the L3902 with the
RC240VFC analog modem front-end (carrier modulator/demodulator + DAA
interface), a single 128 KiB EPROM holding the firmware, and roughly
32 KiB of external SRAM for the modem's working set.

The CPU here is conventionally clocked at one of 15 MHz (`3/3` mask
option), 16.5 MHz (`5/3`), or 20.5 MHz (`5/5`) per the L39 TRM §3.6.2.

### Memory map (CPU view, after reset, before the boot stubs run)

```
$0000-$001F   I/O & bank-select registers (ports, BSR0..7, EIR/CIR, PTGB, timers)
$0020-$0032   Host-bus dual-port (16550A emulation: TX/RX FIFO, LSR/MSR/LCR/MCR/FCR, ...)
$0033-$003F   ESS, PTGA, USART (SMR/SLC/SSR/SFR, divider latches)
$0040-$00FF   page 0 RAM (192 bytes)
$0100-$01FF   page 1 RAM / 6502 stack
$0200-$04FF   pages 2-4 RAM (3 × 256 bytes)
$0500-$05FD   page 5 RAM (254 bytes)
$05FE-$05FF   on-chip CRC: $05FE r=CRC-L w=feed input, $05FF r=CRC-H w=initialise
$0600-$07FF   ES4 region (or RAM if BSR.PBS1=1)
$0800-$DFFF   seven 8 KiB external windows (BSR0..BSR6 in $0018..$001E)
$E000-$FFFF   8 KiB internal ROM, or external via BSR7 ($001F)
```

The ELSA firmware **disables the L3902's internal ROM** (probably by tying
`TSTP` low at startup) and runs entirely from the external 128 KiB EPROM
that the BSRs map into the CPU's address space.

### How banking actually works on the L3902

Each `BSRn` register at `$0018+n` is one byte:

```
| ES3 | ES2 | ES1 | ES0 | A16 | A15 | A14 | A13 |
  bit7  bit6  bit5  bit4  bit3  bit2  bit1  bit0
```

Critically, `A13-A16` is **four bits** — sixteen possible 8 KiB physical
banks, exactly enough to address the entire 128 KiB EPROM. Whatever value
the firmware writes into the `A13-A16` field is the physical bank number
that gets exposed in that 8 KiB window of the CPU view. The `ES0-ES3` bits
are chip-select assertions that the L3902 drives onto its bus during
accesses to that window — they support multi-chip topologies but, with a
single EPROM, they're really just "tell the EPROM whether this is a normal
or extended-cycle access" (the L3902 uses ES patterns to differentiate
fast vs slow memory cycles, per L39 TRM §3.6.2).

So when you see `STI #$70, $1B` (write `$70` to `BSR3`):

```
$70 = 0111 0000
        |||| ++++ A13-A16 = 0000 → physical bank 0 (file offset 0x0000)
        ||++----- ES1 + ES0 not asserted? actually:
        ++------- ES3 bits are asserted depending on convention
```

`A13-A16 = 0000` means **bank 0**, i.e. file offsets `0x0000-0x1FFF` are
exposed in whichever logical window this BSR controls. `BSR3` controls
`$6000-$7FFF`. So after the write, accesses to logical `$6000-$7FFF` read
file `0x0000-0x1FFF`; in particular `$6200` reads file **`0x0200`**. (My
first reading of this analysis had it backwards; the correct
interpretation is what makes the boot chain work.)

### Reset banking convention

Per L39 TRM Table 3-3, all BSRs reset to zero. With every BSR = `0`, every
8 KiB window reads from physical bank 0. That cannot be the actual
power-on state for this firmware — it would loop the entire 64 KiB CPU
view onto file `0x0000-0x1FFF` and the boot stub couldn't run. The
hardware must apply some initial mapping at reset that exposes the
bank holding the reset vectors at `$E000-$FFFF`, and either the L39 TRM
glosses over it or the ELSA board provides it externally (e.g. the EPROM
is wired so that its A13-A16 pins are pulled to a particular pattern
when no BSR has been programmed).

What we *know* from the firmware is that immediately after reset, the
CPU is fetching from file `0xFFC0` — i.e. file offset == logical address,
or equivalently "physical bank 7 mapped at `$E000-$FFFF`" (since file
`0xE000-0xFFFF` is bank 7, which the third boot stub later confirms by
writing `BSR7 ← $73` to keep that window stable). The simplest consistent
model is: at reset, BSRs default to 1:1 identity (logical 8 KiB window
*n* maps to physical bank *n*) for at least the upper half of the
address space; the boot stubs then pin that mapping into the BSRs
explicitly so it doesn't depend on the reset behaviour.

## Boot sequence — three stages

### Stage 1 — `$FFC0` (file `0xFFC0`)

```
$FFC0  78           SEI                    ; mask all IRQs
$FFC1  B2 70 1B     STI #$70, $1B          ; BSR3 := $70 — bank 0 → $6000-$7FFF
$FFC4  4C 00 62     JMP $6200              ; jump to second-stage stub
       FF FF ... FF                        ; 41 bytes of $FF padding ($FFC7-$FFEF)
$FFEF  58           CLI                    ; (unreachable; padding artefact)
$FFF0  C0 FF C0 FF C0 FF C0 FF             ; IRQ6/IRQ5/IRQ4/IRQ3 → $FFC0
$FFF8  C0 FF C0 FF C0 FF C0 FF             ; IRQ2/IRQ1/NMI/RESET → $FFC0
```

The static boot vectors at `$FFE0-$FFFF` all point at `$FFC0`. They are
only consulted in the tiny window between reset and the third stub
finishing — once it programs `BSR3 ← $77`, the bank holding the
*runtime* vectors gets swapped in over `$E000-$FFFF` and from then on
the IRQ table at file `0x7FF0-0x7FFF` (see below) is what the CPU sees.

### Stage 2 — `$6200` (which is file `0x0200` after stage 1)

```
$6200 = file 0x0200   B2 73 1F   STI #$73, $1F   ; BSR7 := $73 — bank 3 → $E000-$FFFF
                      4C B6 E7   JMP $E7B6        ; jump to third-stage stub
```

`BSR7 = $73` → `A13-A16 = 0011` → bank 3 → file `0x06000-0x07FFF` mapped
into `$E000-$FFFF`. So `$E7B6` after this swap reads from file
`0x6000 + ($E7B6 - $E000) = 0x67B6`.

### Stage 3 — `$E7B6` (= file `0x67B6`) — the actual hardware initialiser

```
file 0x67B6:
  78               SEI
  B2 00 32         STI #$00, $32   ; HCR    := 0     host-control: GP mode, no FIFO IRQs
  D8               CLD              ; binary mode
  B2 00 0B         STI #$00, $0B   ; CIR    := 0     clear all edge-detect flags
  B2 03 0A         STI #$03, $0A   ; EIR    := $03   PD7+PB2 edge polarity = positive
  B2 00 09         STI #$00, $09   ; LPR    := 0     low-power off
  B2 58 14         STI #$58, $14   ; TBM    := $58   Timer B mode bits
  B2 C0 05         STI #$C0, $05   ; PBSEL  := $C0   PB7+PB6 → special function
  B2 0C 33         STI #$0C, $33   ; ESS    := $0C   ES1+ES2 fast cycles

  ;-- final BSR layout for the running firmware --
  B2 70 18         STI #$70, $18   ; BSR0 := $70   $0800-$1FFF → file 0x00000-0x01FFF (bank 0)
  B2 71 19         STI #$71, $19   ; BSR1 := $71   $2000-$3FFF → file 0x02000-0x03FFF (bank 1)
  B2 72 1A         STI #$72, $1A   ; BSR2 := $72   $4000-$5FFF → file 0x04000-0x05FFF (bank 2)
  B2 77 1B         STI #$77, $1B   ; BSR3 := $77   $6000-$7FFF → file 0x0E000-0x0FFFF (bank 7)
  B2 B0 1C         STI #$B0, $1C   ; BSR4 := $B0   $8000-$9FFF → file 0x10000-0x11FFF (bank 8 + ES2+3)
  B2 B1 1D         STI #$B1, $1D   ; BSR5 := $B1   $A000-$BFFF → file 0x12000-0x13FFF (bank 9 + ES2+3)
  B2 B2 1E         STI #$B2, $1E   ; BSR6 := $B2   $C000-$DFFF → file 0x14000-0x15FFF (bank 10 + ES2+3)
  B2 73 1F         STI #$73, $1F   ; BSR7 := $73   $E000-$FFFF → file 0x06000-0x07FFF (bank 3, where this code is)
  ...                              ; further port and timer init follows
```

After this third stub finishes, **the runtime memory map is**:

```
$0000-$07FF  on-chip I/O + RAM (page 0..5, registers, FIFO, etc.)
$0800-$1FFF  file 0x00000-0x01FFF   ─┐
$2000-$3FFF  file 0x02000-0x03FFF    │  "low ROM" — strings, V.8 INFO
$4000-$5FFF  file 0x04000-0x05FFF   ─┘   tables, Rockwell ADPCM descriptors
$6000-$7FFF  file 0x0E000-0x0FFFF       boot ROM + jump table (now lives here)
$8000-$9FFF  file 0x10000-0x11FFF   ─┐
$A000-$BFFF  file 0x12000-0x13FFF    │  "high ROM" — fax response set,
$C000-$DFFF  file 0x14000-0x15FFF   ─┘   AT result codes, modem state machines
$E000-$FFFF  file 0x06000-0x07FFF       hardware-init bank + runtime IRQ vectors
```

Three things drop out of this layout:

1. **All the German/V.42bis label strings live in low ROM** (the bank
   we read at file `0x0000-0x05FF` etc.) and at runtime appear at logical
   `$0800-$1FFF`. So a `LDA $1C18` at runtime reads the "Hey, it's an
   ELSA!" string at file `0x1C18`.

2. **All the AT command result codes and the Class 2 fax response set
   live in high ROM** at file `0x10000-0x15FFF`, accessible at runtime
   via `LDA $80xx`-`LDA $D7xx`. So when the firmware emits "CONNECT" or
   "+FHS:" to the host, it's reading from physical banks 8-10.

3. **The runtime IRQ vector table lives at file `0x7FE0-0x7FFF`**, the
   top of the bank that BSR3 maps to `$6000-$7FFF` after init. Wait —
   that doesn't match: BSR3 maps to `$6000-$7FFF` and the vectors *should*
   live at `$FFE0-$FFFF`, mapped from BSR7. The reality is BSR7 = `$73`
   maps to file `0x6000-0x7FFF` (bank 3), so the bytes at the top of that
   bank (file `0x7FE0-0x7FFF`) appear at logical `$FFE0-$FFFF`. That
   matters because the IRQ vectors there *do* point to real handlers
   (next paragraph), unlike the all-`$FFC0` vectors in bank 7 that we
   saw earlier.

### Runtime IRQ vector table (file `0x7FE0-0x7FFF`, visible at `$FFE0-$FFFF` after init)

```
JSB0-JSB7  $FFFF $FFFF $FFFF $FFFF $FFFF $FFFF $FFFF $FFFF   (unused)
IRQ6        $E3C2     RXD/PA7-edge/PTGA/PTGB
IRQ5        $E3AB     PA1-edge/Timer A ROM/TXD-status
IRQ4        $E3A5     TXD-buf-full/PA3-edge
IRQ3        $E398     16550 host-IRQ family / Timer B (FIFO half-empty etc.)
IRQ2        $E381     PA4-edge
IRQ1        $E2F8     PD7-edge
NMI         $E2E7
RESET       $E7B6     ; same target as the third boot stub — software reset
                       ;  re-runs hardware-init from scratch
```

So the real IRQ dispatchers cluster in `$E2E7-$E3C2` (= file
`0x62E7-0x63C2`), a 220-byte block holding eight short stubs. Looking up
the bytes at file `0x62F8` (IRQ1) confirms it's a dense sequence of
push/branch-on-bit instructions — i.e. the firmware does its own
priority resolution from the External Interrupt Register at `$0A` after
each entry, dispatching to per-source handlers from there.

## What the firmware does, by string evidence

A scan for printable runs of ≥6 characters turns up 435 strings in the
low half (`0x00000-0x0FFFF`) and 193 in the high half (`0x10000-0x1FFFF`).
The interesting ones, grouped by purpose. **Addresses below are file
offsets**; convert to runtime logical addresses by:

| File offset | Runtime logical |
|---|---|
| `0x0000-0x07FF` | `$0800-$0FFF` (BSR0) — actually the lower half of bank 0 |
| `0x0800-0x1FFF` | `$0800+0x800-$1FFF` (still BSR0) |
| `0x2000-0x3FFF` | `$2000-$3FFF` (BSR1) |
| `0x4000-0x5FFF` | `$4000-$5FFF` (BSR2) |
| `0x6000-0x7FFF` | `$E000-$FFFF` (BSR7) |
| `0xE000-0xFFFF` | `$6000-$7FFF` (BSR3) |
| `0x10000-0x15FFF` | `$8000-$DFFF` (BSR4-6) |
| `0x16000-0x1FFFF` | not mapped at default runtime — banks 11-15 |

### Branding and build identifiers (file `0x0000-0x01A0`)

```
0x0000  (C) ROCKWELL
0x000D  -CP steht hier ausschliesslich aus programmiertechnichen Gruenden.
        Es gilt: (C) ELSA
0x0062  18.07.97 12:34
0x0102  !MicroLink 14.4TQ
0x0126  !MicroLink 28.8TQ
0x014A  !MicroLink 33.6TQ
0x016E  !ELSA, Aachen (Germany)
```

The German banner translates to "-CP appears here for purely technical
reasons; the actual copyright is ELSA's" — i.e. the Rockwell copyright
string is required by the licensing terms of Rockwell's modem firmware
kit, but the substantive code is ELSA's. The three product strings
confirm one image services all three models; the leading `!` byte is a
build-system marker.

### Modem capability advertisement (file `0x1C18-0x1C70`)

```
0x1C18  Hey, it's an ELSA!
0x1C2B  V42bis Werte des fernen Modems     ; "values from the remote modem"
0x1C4A  Werte der letzten Verbindung        ; "values from the last connection"
```

Headings in an `AT&V`-style status report.

### V.34 / V.42bis statistics labels (file `0x1DBC-0x1F99`)

A dense table of physical-layer parameter names:

```
0x1DBC  K-Far tx        0x1DC9  K-Far rx       ; V.42bis dictionary size, far end
0x1DD6  Bits/Fr tx      0x1DE5  Bits/Fr rx     ; codeword bit width
0x1DF4  Codewords       0x1E02  MaxStrLen      ; V.42bis codeword count / max string
0x1E10  RTD 10ms                               ; round-trip delay, 10 ms units
0x1E1D  TxSymRa Bd      0x1E2C  RxSymRa Bd     ; V.34 symbol rate (baud)
0x1E3B  TxFreq Hz       0x1E49  RxFreq Hz      ; V.34 carrier frequency
0x1E57  UBand Hz        0x1E64  LBand Hz       ; V.34 upper/lower band edges
0x1E71  TxPrecoding     0x1E81  RxPrecoding    ; V.34 precoder settings
0x1E91  TxWarping       0x1E9F  RxWarping      ; V.34 frequency warping
0x1EAC  0TxShaping      0x1EBA  0RxShaping     ; V.34 spectrum shaping
0x1EC9  PreEmphFilt     0x1ED9  V34PwrRed      ; pre-emphasis / power reduction
0x1EE7  SNR 0.1 dB      0x1EF6  RxPegel dB     ; SNR / RX level
0x1F16  Bad Frames                             ; HDLC frame error counter
0x1F25  I-Fr tx         0x1F31  I-Fr rx        ; LAPM I-frame counts
0x1F3D  Rtrn loc        0x1F4B  Rtrn rem       ; LAPM retransmits
0x1F59  RNego loc       0x1F67  RNego rem      ; renegotiations
0x1F75  Rej tx          0x1F81  Rej rx         ; LAPM REJ frames
0x1F8D  SRej tx         0x1F99  SRej rx        ; selective REJ
```

V.34 with the full precoding/warping/shaping toolkit (all added in 1996),
V.42bis compression, LAPM error correction with retransmit /
renegotiation counters. `Pegel` is German for "level".

### V.8 / V.34 capability descriptors (file `0x2FF0-0x31D1`)

V.8 INFO frames the modem advertises during modulation negotiation:

```
0x2FF0  "(20-3A,3C-7E)"          ; ASCII range declarations
0x3000  "(32-58,60-127)"
0x3011  3,24,48,72,73,74,96,97,98,121,122,145,146   ; modulation list
0x303B  ,2,2.0
0x3048  ROCKWELL;ADPCM;16        ; non-standard modulation: Rockwell ADPCM at 16 kbps
0x307E  (33600-300)              ; rate range
0x3170  131,"ADPCM4\ROCKWELL",4,0,(7200),(124-132),(0)
0x31A2  130,"ADPCM3\ROCKWELL",3,0,(7200),(124-132),(0)
0x31D1  129,"ADPCM2\ROCKWELL",2,0,(7200),(124-132),(0)
```

The "ROCKWELL ADPCM" mode is a non-standard modulation used inside `+V`
voice mode to carry compressed audio between two Rockwell-chipset
modems for voice-mail / answering-machine applications.

### AT command result codes (file `0x156EF-0x15A32`)

```
0x156EF  OK
0x156F2  CONNECT
0x156FA  RING
0x156FF  NO CARRIER
0x1570A  ERROR
0x15710  NO DIALTONE
0x1571E  BUSY
0x15721  DIAL LOCKED
0x15733  NO ANSWER
0x15741  +FCERROR
0x1574B  ATA
0x1574E  DATA
0x15753  VCON
0x15754  NO H324 DETECTED
0x15A11  /V42BIS
0x15A1A  /FAX
0x15A1F  +VCON
```

Standard Hayes/V.250 result codes plus `+FCERROR` (fax errors),
`+VCON` (V.253 voice connection), `NO H324 DETECTED` (H.324 video over
POTS). `DIAL LOCKED` is German-market specific — child-lock / dial PIN.

These appear at runtime via `LDA $D6EF` etc. — they're in BSR6's bank
(file `0x14000-0x15FFF` → logical `$C000-$DFFF`).

### Class 2 fax (T.30) response set (file `0x18CFC-0x18DBC`)

```
+FHNG: +FHS:  +FCON  +FCO   +FVOICE +FVO   +FCFR  +FIS:  +FDIS:
+FTC:  +FCS:  +FDCS: +FTI:  +FTSI:  +FCI:  +FCSI: +FPI:  +FCIG:
+FPTS: +FET:  +FPS:  +FPO   +FPOLL  +FNF:  +FNSF: +FNS:  +FNSS:
+FNC:  +FNSC: +FHR:  +FHT:
```

The full Class 2 fax response set per ITU-T Rec. T.31/T.32: connection
status (`+FCON`, `+FHNG` for hangup with cause), DIS/DCS frame exchange
(`+FDIS`/`+FDCS`), training control, transmitter/receiver/caller IDs,
page transfer (`+FPTS`/`+FET`/`+FPS`), polling, non-standard facilities
(`+FNF`/`+FNSF`/`+FNS`/`+FNSS`), HDLC framing diagnostics. The presence
of `+FNSC` (the colon-suffixed variant) implies T.32 Class 2.0.

### Voice mode and configuration (file `0x1B7F6-0x1D968`)

```
0x1B7F6  Clocks, Mode, Format:
0x1C8E1  #WA46 ARA TAB:           ; AppleTalk Remote Access dispatch table?
0x1D721  RLSD-Offset:             ; RLSD = Received Line Signal Detect
0x1D72F  RX-Gain:
0x1D968  Konfiguration:
```

Internal-debug printouts emitted when the firmware's verbose-diagnostic
flag is set. Mix of English keys (`Clocks`, `Format`, `RX-Gain`) and
German labels — consistent with the German user interface around an
English Rockwell core.

## Code architecture

### Boot bank disassembly (the upper 8 KiB of file `0xE000-0xFFFF`)

204 functions auto-discovered from the boot-time view, total 2,179
instructions. About 10 KiB of code packed into the upper bank that's
visible at reset, the rest of the 64 KiB CPU view at that moment is the
"low ROM" data half plus on-chip RAM.

#### Top-of-table functions (boot-time view)

| Entry | Size | Inbound xrefs | Likely purpose |
|---|---:|---:|---|
| `FUN_5ceb` (`$5CEB`) | 2 | **27** | Helper macro — likely an `RTS` thunk |
| `FUN_5749` (`$5749`) | 27 | 16 | Common-tail return wrapper |
| `FUN_5764` (`$5764`) | 52 | 14 | Frequent worker, called from many command handlers |
| `FUN_FFC0` (`$FFC0`) | 7 | **14** | The reset stub itself |
| `FUN_E00D` (`$E00D`) | 7 | 12 | Bank-call trampoline |
| `FUN_57F6` (`$57F6`) | 6 | 12 | Helper, flag-setting wrapper |
| `FUN_E50B` (`$E50B`) | 6 | 9 | Bank-shared helper |
| `FUN_8D4A` (`$8D4A`) | 233 | 1 | **Largest function in the bank** — touches 24 distinct on-chip registers (`$00 $01 $02 $03 $06 $07 $08 $09 $0C $0D $0E $0F $10 $11 $1C $25 $27 $29 $2C $2E $2F $36 $37 $3B`) |
| `FUN_145A` (`$145A`) | 183 | 6 | Touches port direction regs and edge-detect flags — IRQ demux |
| `FUN_2229` (`$2229`) | 153 | 4 | Touches FIFO ($20), MCR ($24), FCR ($25), DLAB ($28/$29), GPFS ($2E), FSR ($30) — host-bus driver |

`FUN_8D4A`'s register footprint — Port A through F + their direction
registers, the LPR (`$09`), Timer A registers (`$10/$11`), one BSR
(`$1C`), FIFO control (`$25`), DLAB (`$29`), the two scratchpad RAM
slots, GPFS, HHR, and the USART (`$36/$37/$3B`) — make this
unambiguously the **system initialisation routine**: an L3902 equivalent
of `setup_hardware()` / `cold_init()`.

`FUN_2229` is the **host-bus driver core**: register footprint is the
16550A emulation register file plus the FIFO at `$20` and the FIFO
status register at `$30`.

`FUN_145A` is the **IRQ demultiplexer**: it touches both EIR (`$0A`)
and CIR (`$0B`) plus several port direction registers. This is where
the upper-bank IRQ stubs at `$E2F8`-`$E3C2` ultimately call into to
identify the source.

### Inter-bank trampoline templates

The boot bank contains many entries of this form:

```
$0819  JSR $E00D
$081C  JSR $1546
$081F  JMP $E00D
```

Three instructions, one tail-call. This is the **bank-call thunk**
template: enter through `$E00D` ("save context, bank in target"), do work
via a helper (`JSR $1546` returns once the operation is done), then
re-enter `$E00D` via `JMP` to "restore context, unbank". The same
template repeats for `$E01A`, `$E027`, and several other 13-byte windows
in the `$E000-$E060` block.

### Command-dispatch trampolines (in the bank that BSR7 maps after init)

The bytes at file `0x6200` onwards (= logical `$E200` after init), seen
through Ghidra's first-half view as the `FUN_6200` function, are a
dense run of small command stubs:

```
$E200  LDY $85
$E202  RND
$E203  STI #$03,$41
$E206  STI #$12,$40
$E209  JSR $E81B           ; shared dispatcher
$E20C  RTS
```

`$41` and `$40` are the conventional "command" / "sub-command" cells in
this firmware's calling convention. The 6-byte stub stuffs them with
opcode-like control bytes and calls `$E81B`, which dispatches by lookup.
Decoding the bytes immediately after confirms the pattern repeats — the
next 30+ entries are all 2-3-instruction stubs that vary only in the
two `STI` operands. This is how mid-1990s Rockwell modem firmwares
squeezed dozens of AT-command handlers into a tight ROM budget: each
command is a 6-byte stub, the 1.5 kB or so of dispatch code lives once.

### Mnemonic distribution (boot-time view, 2,179 instructions)

```
JSR   301  | AND  30 | PLA 23 | PHX  8
LDA   202  | LDY  30 | BCS 22 | PLX  8
STI   181  | BCC  27 | CPX 19 | ROR  8
STA   120  | BBR  26 | EOR 18 | DEY  7
RTS   109  | SBA  26 | CLC 17 | SED  6
JMP    84  | INX  25 | SMB 17 | CLI  5
CMP    80  | RBA  25 | STX 17 | ...
BEQ    69  | PLA  23 | ROL 16
LDX    66  | BCS  22 | SEC 15
BRA    57  | CPX  19 | STY 15
BNE    55  | EOR  18 | ORA 14
BAR    51  | CLC  17 | ASL 13
BAS    49  | SMB  17 | BRK 13
PUL    36  | STX  17 | PHA 13
PSH    33  | ROL  16 | ADC 12
BBS    31  | SEC  15 | RMB 12
```

Two things stand out:

1. **`STI` is the third-most-common instruction** (181 of 2179, 8.3 %).
   This is the R65C19 store-immediate-to-zero-page op. Its prevalence
   here is the trampoline pattern at work: every command stub is two
   `STI`s plus a `JSR`/`JMP`, so each stub contributes two `STI`s.

2. **The bit-manipulation family is enormous**: 51 `BAR`+`BAS`
   (branch-on-bits-in-memory), 26 `SBA` (set-bits-in-memory), 25 `RBA`
   (reset-bits-in-memory), 17 `SMB`, 12 `RMB`, 26 `BBR`, 31 `BBS`. That's
   **188 bit-test/set/clear operations** out of 2,179 (8.6 %), all
   hitting either control registers (port direction bits, IRQ-enable
   masks, FCR fields, USART mode bits) or in-RAM flag words. This is
   exactly the workload profile of an MCU firmware that mostly
   interacts with memory-mapped peripherals. Compare to a typical 6502
   firmware where `LDA`+`STA` dominate at 35-40 % and bit-manipulation
   is barely visible (~1-2 %) — here `LDA`+`STA` is 14.7 % and bit-ops
   are 8.6 %. The Rockwell extensions are doing real work.

`SED` shows up 6 times — i.e. the firmware does briefly enter BCD mode
for certain arithmetic. The `RockwellL39` SLEIGH spec models `SED`/`CLD`
as flag toggles only; `ADC`/`SBC` between them will look right in
disassembly but won't decimal-correct in the decompiler. Documented in
`docs/open-points.md`.

### Peripheral hotspots (boot-time view)

```
$0020 RX/TX FIFO        16 accesses    bulk data transfer
$0029 DLAB MSB            4            baud-rate config
$0021 LSR                 3            line-status reads
$0030 FSR                 3            FIFO status polls
$0031 FIER                3            FIFO IRQ enable
$003A SMR                 3            USART mode setup
$0024 MCR                 2
$0028 DLAB LSB            2
$002F HHR                 2            host-handshake
$003B SLC                 2            serial line control
$003F SIDL                2            SIN divider latch
```

Quiet by absolute volume — these are mostly init touches. The runtime
loop in the `BSR4-6`-mapped banks does the real driving, and that code
isn't statically reachable from the boot-time view alone.

## Open questions

1. **What `(command, sub-command) = ($03, $12)` means.** That's the
   selector the command stub at `$E200` issues to the dispatcher at
   `$E81B`. Determining the dispatcher's table format would unlock the
   meaning of every other command stub in the firmware.
2. **Cross-bank disassembly.** The current Ghidra import only shows the
   boot-time view. Re-importing with the runtime BSR layout (BSR0-2 →
   banks 0-2, BSR3 → bank 7, BSR4-6 → banks 8-10, BSR7 → bank 3) and
   stitching the listings together would give a unified call graph for
   the whole firmware. This is what the "BSR-aware analysis" entry in
   `docs/open-points.md` is asking for.
3. **The runtime IRQ handler bodies.** We located the vector table at
   `$E2E7-$E3C2` (file `0x62E7-0x63C2`) but didn't disassemble each
   handler. The 220-byte block is small enough to walk by hand once you
   set up Ghidra to view file `0x6000-0x7FFF` at logical `$E000-$FFFF`.
4. **The `0x33` byte at file `0x1FFFF`.** Positioned like a checksum
   byte but its algorithm is undocumented here. The L3902 has an on-chip
   16-bit CRC unit at `$05FE/F`; the firmware probably uses it both for
   runtime validation of received HDLC frames and for boot-time
   self-check, but neither use site has been identified.
5. **The ARA / `#WA46` block.** AppleTalk Remote Access support is
   referenced (the dispatch tables and the diagnostic string both
   exist), but the actual ARA negotiator isn't located. Almost certainly
   it lives behind one of the command stubs.

## Summary

A textbook example of a mid-90s commodity modem firmware: small
6502-derived MCU with custom ISA extensions, single-EPROM 16-bank
swap-mapping for 128 KiB of code/data accessible through a 64 KiB
window, all-singing-all-dancing feature support (V.34 + V.42bis + LAPM
+ Class 2 fax + V.253 voice + H.324 video), shared firmware across three
retail SKUs, dispatch-table-driven AT command handler. The R65C19
instruction extensions are doing exactly the work they were designed
for — bit manipulation against tightly-packed control registers — at
roughly 8 % of the instruction stream. The author/translator notes in
German at the very start of the image (`Es gilt: (C) ELSA`) are
charming.

The boot is a beautiful three-stage trampoline: the upper-bank reset
stub bank-switches its successor in, that successor bank-switches its
own successor in, and the third stage finally programs all eight BSRs to
the runtime layout and starts the firmware proper. None of the three
stubs is more than three instructions before its `JMP`. It's the kind of
ROM economy you only see when every byte costs money.
