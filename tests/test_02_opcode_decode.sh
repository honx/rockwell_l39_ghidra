#!/usr/bin/env bash
# Test 02: build a synthetic 64 KiB binary that exercises a curated set of
# R65C19 / 65C02 / 6502 opcodes at known addresses, import it under the
# RockwellL39 language, and assert that disassembly matches expectations.
#
# This is the fast path for catching SLEIGH-spec regressions: it doesn't
# depend on any vendor binary, so it can run in CI.

set -u
cd "$(dirname "$0")"
source lib/common.sh

require_ghidra
ensure_module

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fixture="$work/opcodes.bin"
expect="$work/opcodes.expect"

# Build a 64 KiB image. Instructions live starting at $FF00; the reset
# vector at $FFFE points at $FF00.
python3 - "$fixture" <<'PY'
import struct, sys

img = bytearray(b"\xFF" * 0x10000)

# Sequence of (bytes, expected mnemonic) tuples placed back-to-back at $FF00.
# The expected mnemonic is a case-insensitive prefix of the disassembly.
seq = [
    (b"\xA9\x42",          "LDA #0x42"),       # standard LDA imm
    (b"\x18",              "CLC"),             # standard CLC
    (b"\x80\x02",          "BRA"),             # 65C02 branch always
    (b"\xDA",              "PHX"),             # 65C02 push X
    (b"\x5A",              "PHY"),             # 65C02 push Y
    (b"\xFA",              "PLX"),             # 65C02 pull X
    (b"\x7A",              "PLY"),             # 65C02 pull Y
    (b"\x07\x10",          "RMB"),             # 65C02 reset memory bit (bitindex format may vary)
    (b"\x87\x10",          "SMB"),             # 65C02 set memory bit
    (b"\xB2\x70\x1B",      "STI #0x70,0x1b"),  # R65C19 store imm to ZP
    (b"\x89\x05",          "ADD #0x5"),        # R65C19 add no-carry imm
    (b"\x3A",              "ASR"),             # R65C19 arith shift right A
    (b"\x1A",              "NEG"),             # R65C19 negate A
    (b"\x13",              "LAB"),             # R65C19 absolute value of A
    (b"\x22",              "PSH"),             # R65C19 push A,X,Y
    (b"\x32",              "PUL"),             # R65C19 pull Y,X,A
    (b"\x23",              "PHW"),             # R65C19 push W
    (b"\x33",              "PLW"),             # R65C19 pull W
    (b"\x62",              "TAW"),             # R65C19 transfer A to W
    (b"\x72",              "TWA"),             # R65C19 transfer W high to A
    (b"\x43",              "CLW"),             # R65C19 clear W and V
    (b"\x42",              "RND"),             # R65C19 round W
    (b"\x02",              "MPY"),             # R65C19 multiply
    (b"\x12",              "MPA"),             # R65C19 multiply-accumulate
    (b"\x0B",              "JSB0"),            # R65C19 fixed-vector subroutine
    (b"\x1B",              "JSB1"),
    (b"\x7B",              "JSB7"),
    (b"\xC2\x00\x06\xAA",  "RBA"),             # R65C19 reset bits in memory
    (b"\xD2\x00\x06\x55",  "SBA"),             # R65C19 set bits in memory
    (b"\xE2\x00\x06\x01\x02", "BAR"),          # R65C19 branch on bits clear
    (b"\xF2\x00\x06\x01\x02", "BAS"),          # R65C19 branch on bits set
    (b"\xD4\x12",          "EXC 0x12,X"),      # R65C19 exchange A,M
    (b"\x7C\x00\x80",      "JMP"),             # R65C19 indexed-indirect JMP
    (b"\x8B",              "NXT"),             # R65C19 threaded next
    (b"\x9B",              "LII"),             # R65C19 load I indirect
    (b"\xAB",              "LAN"),             # R65C19 load A then inc I
    (b"\xBB",              "INI"),             # R65C19 increment I
    (b"\xCB",              "PHI"),             # R65C19 push I
    (b"\xDB",              "PLI"),             # R65C19 pull I
    (b"\xEB",              "LAI"),             # R65C19 load A from (I)
    (b"\xFB",              "PIA"),             # R65C19 pull I, then load A
    (b"\x03",              "TIP"),             # R65C19 transfer I to PC
    (b"\x60",              "RTS"),             # standard return - terminates
]

addr = 0xFF00
expectations = []
for opbytes, mnemonic in seq:
    img[addr:addr+len(opbytes)] = opbytes
    expectations.append((addr, mnemonic))
    addr += len(opbytes)
    if addr > 0xFFE0:
        sys.exit("ran out of room in fixture region")

# Reset vector points to $FF00 so analysis starts there.
img[0xFFFE] = 0x00
img[0xFFFF] = 0xFF

# Other vectors point harmlessly into the same region.
for v in (0xFFFC, 0xFFFA, 0xFFF8, 0xFFF6, 0xFFF4, 0xFFF2, 0xFFF0):
    img[v] = 0x00
    img[v+1] = 0xFF

# JSB# fixed targets at $FFE0/E2/.../EE — point them at $FF00 too so the
# call resolves to a known address.
for v in range(0xFFE0, 0xFFEF, 2):
    img[v] = 0x00
    img[v+1] = 0xFF

with open(sys.argv[1], "wb") as f:
    f.write(img)

# Write the expectations sidecar that the GhidraScript reads.
with open(sys.argv[1].rsplit(".", 1)[0] + ".expect", "w") as f:
    for addr, mnem in expectations:
        f.write(f"0x{addr:04X}  {mnem}\n")
PY

if [ ! -s "$fixture" ]; then
    fail "fixture builder produced an empty file"
fi
if [ ! -s "$expect" ]; then
    fail "fixture builder did not write expectations file"
fi

project="$work/proj"
mkdir -p "$project"

# Run analyzeHeadless. -scriptPath points at the assertion script, which is
# invoked with the expectations file path as its single argument.
log="$work/headless.log"
set +e
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$project" Test \
    -import "$fixture" \
    -loader BinaryLoader \
    -loader-baseAddr 0x0000 \
    -processor "RockwellL39:LE:16:default" \
    -scriptPath "$REPO_ROOT/tests/scripts" \
    -postScript AssertOpcodes.java "$expect" \
    -noanalysis >"$log" 2>&1
status=$?
set -e

# Surface assertion output regardless of status, both for visibility on
# failure and to confirm the OK lines on success.
grep -E '(AssertOpcodes\.java>|MISMATCH)' "$log" || true

if [ "$status" -ne 0 ]; then
    cat "$log" >&2
    fail "analyzeHeadless / AssertOpcodes exited with status $status"
fi

if grep -q 'MISMATCH' "$log"; then
    fail "one or more opcode expectations failed (see lines above)"
fi

ok_count=$(grep -c 'AssertOpcodes\.java> OK' "$log" || true)
pass "$ok_count opcode expectations satisfied"
