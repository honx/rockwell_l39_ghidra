#!/usr/bin/env bash
# Test 03: end-to-end against the ELSA MicroLink firmware.
#
# Imports binary/elsa_microlink_336tqv_v1.26.bin under the RockwellL39
# language, runs auto-analysis, and asserts on invariants known from manual
# inspection (reset vector, boot-stub disassembly, mnemonic distribution,
# function count). The reference binary is gitignored — if it isn't present
# this test SKIPs rather than FAILs, so CI without the file still goes green.

set -u
cd "$(dirname "$0")"
source lib/common.sh

require_ghidra
ensure_module

firmware="$REPO_ROOT/binary/elsa_microlink_336tqv_v1.26.bin"
if [ ! -f "$firmware" ]; then
    skip "reference firmware not present at $firmware (it is gitignored)"
fi

# Sanity-check the file before paying the import cost. Any other 128 KiB blob
# would obviously break the assertions about $FFC0 disassembly.
size=$(stat -c%s "$firmware")
if [ "$size" -ne 131072 ]; then
    fail "reference firmware is $size bytes; expected exactly 131072"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
project="$work/proj"
mkdir -p "$project"

log="$work/headless.log"
set +e
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$project" E2E \
    -import "$firmware" \
    -loader BinaryLoader \
    -loader-baseAddr 0x0000 \
    -processor "RockwellL39:LE:16:default" \
    -scriptPath "$REPO_ROOT/tests/scripts" \
    -postScript AssertFirmware.java \
    >"$log" 2>&1
status=$?
set -e

# Echo only the assertion script's output; the rest of analyzeHeadless'
# log is verbose and irrelevant unless we're debugging a failure.
grep -E '(AssertFirmware\.java>|FAIL|MISMATCH)' "$log" || true

if [ "$status" -ne 0 ]; then
    cat "$log" >&2
    fail "analyzeHeadless / AssertFirmware exited with status $status"
fi

ok_count=$(grep -c 'AssertFirmware\.java> OK' "$log" || true)
pass "$ok_count e2e assertions satisfied against the reference firmware"
