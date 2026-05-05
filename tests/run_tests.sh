#!/usr/bin/env bash
# Run every test_NN_*.sh in this directory in order. Each test is a standalone
# script that prints PASS/FAIL/SKIP lines and exits with 0 on success, 1 on
# failure (or 0 on skip). This driver aggregates them and exits non-zero if
# any test failed.
#
# Usage:
#   tests/run_tests.sh                 # run everything
#   GHIDRA_INSTALL_DIR=/path tests/run_tests.sh

set -u
cd "$(dirname "$0")"

shopt -s nullglob
tests=( test_*.sh )
shopt -u nullglob

if [ ${#tests[@]} -eq 0 ]; then
    echo "no tests found" >&2
    exit 1
fi

failed=0
total=0
for t in "${tests[@]}"; do
    total=$((total + 1))
    echo
    echo "=== $t ==="
    if ! bash "$t"; then
        failed=$((failed + 1))
    fi
done

echo
echo "==============================="
if [ "$failed" -eq 0 ]; then
    echo "All $total test(s) passed"
    exit 0
fi
echo "$failed of $total test(s) FAILED"
exit 1
