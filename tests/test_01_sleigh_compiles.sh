#!/usr/bin/env bash
# Test 01: the SLEIGH spec must compile without errors.
#
# Catches regressions in the spec the moment they're saved, well before any
# headless import would surface them as a stack trace.

set -u
cd "$(dirname "$0")"
source lib/common.sh

require_ghidra

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$MODULE_DIR/data/languages/RockwellL39.slaspec" "$work/"
# Ldefs / pspec / cspec are referenced by sleigh during validation.
cp "$MODULE_DIR/data/languages/"*.{ldefs,pspec,cspec} "$work/"

log="$work/sleigh.log"
if ! "$GHIDRA_INSTALL_DIR/support/sleigh" "$work/RockwellL39.slaspec" >"$log" 2>&1; then
    cat "$log" >&2
    fail "sleigh exited non-zero"
fi

if grep -E '^ERROR' "$log" >/dev/null; then
    cat "$log" >&2
    fail "sleigh emitted ERROR lines"
fi

if [ ! -s "$work/RockwellL39.sla" ]; then
    fail "sleigh did not produce RockwellL39.sla"
fi

# A handful of WARN lines is fine (e.g. the deliberate NOP constructor), but
# warn the user if the count grows so unintentional new warnings get noticed.
warn_count=$(grep -c '^WARN' "$log" || true)
if [ "$warn_count" -gt 2 ]; then
    cat "$log" >&2
    fail "sleigh emitted $warn_count WARN lines (expected ≤2)"
fi

pass "SLEIGH spec compiles cleanly ($warn_count warnings, $(stat -c%s "$work/RockwellL39.sla") byte .sla)"
