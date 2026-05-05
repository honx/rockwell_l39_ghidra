#!/usr/bin/env bash
# Test 04: bank-aware analyser, Phase 1+2.
#
# Imports the ELSA reference firmware, runs the L3902BankingSetup script
# (creates four configuration overlays, detects the four
# switch_rom_cfgX entry points), then runs an assertion script that
# checks the overlays exist with the expected sizes/contents and the
# four functions were named correctly.
#
# Like test_03, this depends on the gitignored firmware blob and SKIPs
# cleanly when it isn't present.

set -u
cd "$(dirname "$0")"
source lib/common.sh

require_ghidra
ensure_module

firmware="$REPO_ROOT/binary/elsa_microlink_336tqv_v1.26.bin"
if [ ! -f "$firmware" ]; then
    skip "reference firmware not present at $firmware (it is gitignored)"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
project="$work/proj"
mkdir -p "$project"

log="$work/headless.log"
set +e
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$project" P12 \
    -import "$firmware" \
    -loader BinaryLoader \
    -loader-baseAddr 0x0000 \
    -processor "RockwellL39:LE:16:default" \
    -scriptPath "$REPO_ROOT/ghidra/RockwellL39/ghidra_scripts;$REPO_ROOT/tests/scripts" \
    -preScript L3902BankingSetup.java \
    -postScript L3902ResolveRom6.java \
    -postScript AssertBankingSetup.java \
    >"$log" 2>&1
status=$?
set -e

# Echo only the script outputs; full headless log is verbose.
grep -E '(L3902BankingSetup\.java>|AssertBankingSetup\.java>|FAIL|MISMATCH)' "$log" || true

if [ "$status" -ne 0 ]; then
    cat "$log" >&2
    fail "analyzeHeadless / banking-setup assertions exited with status $status"
fi

ok_count=$(grep -c 'AssertBankingSetup\.java> OK' "$log" || true)
pass "$ok_count banking-setup assertions satisfied"
