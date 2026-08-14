#!/usr/bin/env bash
#
# Runs junos-interface-poe-bounce.sh unmodified against the mock CLI in this
# directory instead of a real switch, by shadowing `ssh` on PATH. Requires
# `expect` to be installed (same requirement as the real script).
#
# Usage: ./test/run-mock-test.sh

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"

if ! command -v expect >/dev/null 2>&1; then
    echo "Error: 'expect' is required to run this test." >&2
    exit 1
fi

export PATH="$DIR/bin:$PATH"
export JUNOS_PASSWORD="testpass"

echo "=== running junos-interface-poe-bounce.sh against mock switch ==="
echo

output="$("$ROOT/junos-interface-poe-bounce.sh" -u testuser -H mock-switch -i ge-0/0/1 -w 1 2>&1)"
status=$?

echo "$output"
echo
echo "=== end of script output ==="
echo

if [[ $status -ne 0 ]]; then
    echo "TEST FAILED: script exited with status $status"
    exit 1
fi

if echo "$output" | grep -q "current state of ge-0/0/1" \
    && echo "$output" | grep -q "PoE: Disabled by admin: no" \
    && echo "$output" | grep -qc "commit complete" \
    && echo "$output" | grep -q "^Done\.$"
then
    echo "TEST PASSED"
else
    echo "TEST FAILED: expected output not found in script run"
    exit 1
fi
