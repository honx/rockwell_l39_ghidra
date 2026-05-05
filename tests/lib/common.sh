#!/usr/bin/env bash
# Shared helpers for the test suite. Sourced by each test_NN_*.sh script.
#
# Provides:
#   GHIDRA_INSTALL_DIR  resolved path to the Ghidra install (default /home/honx/ghidra)
#   REPO_ROOT           absolute path to the repo root
#   MODULE_DIR          absolute path to ghidra/RockwellL39
#   pass MSG            print a green PASS line
#   fail MSG            print a red FAIL line and exit 1
#   skip MSG            print a yellow SKIP line and exit 0
#   require_ghidra      fail if Ghidra isn't available
#   ensure_module       copy the module into the Ghidra install (idempotent)
#   headless ...        wrapper around analyzeHeadless that swallows banner noise

set -u

# Resolve the repo root from the script's location so tests work no matter where
# they are invoked from.
__common_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$__common_dir/../.." && pwd)"
MODULE_DIR="$REPO_ROOT/ghidra/RockwellL39"

GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/home/honx/ghidra}"

# Colour helpers — use colour only if stdout is a TTY.
if [ -t 1 ]; then
    __c_red=$'\e[31m'
    __c_grn=$'\e[32m'
    __c_yel=$'\e[33m'
    __c_rst=$'\e[0m'
else
    __c_red=''; __c_grn=''; __c_yel=''; __c_rst=''
fi

pass() { printf '  %sPASS%s %s\n' "$__c_grn" "$__c_rst" "$*"; }
fail() { printf '  %sFAIL%s %s\n' "$__c_red" "$__c_rst" "$*" >&2; exit 1; }
skip() { printf '  %sSKIP%s %s\n' "$__c_yel" "$__c_rst" "$*"; exit 0; }

require_ghidra() {
    if [ ! -x "$GHIDRA_INSTALL_DIR/support/sleigh" ]; then
        fail "Ghidra not found at GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR (no support/sleigh)"
    fi
    if [ ! -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]; then
        fail "Ghidra at $GHIDRA_INSTALL_DIR is missing support/analyzeHeadless"
    fi
}

ensure_module() {
    require_ghidra
    local dest="$GHIDRA_INSTALL_DIR/Ghidra/Processors/RockwellL39"
    mkdir -p "$dest/data/languages"
    cp "$MODULE_DIR"/Module.manifest      "$dest/" 2>/dev/null || true
    cp "$MODULE_DIR"/extension.properties "$dest/" 2>/dev/null || true
    cp "$MODULE_DIR"/data/languages/*.cspec   "$dest/data/languages/"
    cp "$MODULE_DIR"/data/languages/*.ldefs   "$dest/data/languages/"
    cp "$MODULE_DIR"/data/languages/*.pspec   "$dest/data/languages/"
    cp "$MODULE_DIR"/data/languages/*.slaspec "$dest/data/languages/"
    if [ -f "$MODULE_DIR/data/languages/RockwellL39.sla" ]; then
        cp "$MODULE_DIR"/data/languages/*.sla  "$dest/data/languages/"
    fi
}

# Run analyzeHeadless and stream output. Caller is responsible for any grepping.
headless() {
    "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$@"
}
