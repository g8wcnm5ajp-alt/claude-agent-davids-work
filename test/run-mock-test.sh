#!/usr/bin/env bash
#
# Runs junos-interface-poe-bounce.sh unmodified against the mock CLI in this
# directory instead of a real switch, by shadowing `ssh` on PATH. Requires
# `expect` to be installed (same requirement as the real script).
#
# Exercises multiple scenarios: a real state change, and the skip-if-
# already-in-desired-state path, for both interface and PoE independently.
#
# Usage: ./test/run-mock-test.sh

set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"

if ! command -v expect >/dev/null 2>&1; then
    echo "Error: 'expect' is required to run this test." >&2
    exit 1
fi

export PATH="$DIR/bin:$PATH"
export JUNOS_PASSWORD="testpass"

FAILURES=0

# args: name, MOCK_IFACE_STATE, MOCK_POE_STATE, script-args..., then --expect / --refute lists
run_case() {
    local name="$1" iface_state="$2" poe_state="$3"
    shift 3

    local script_args=()
    while [[ "$1" != "--expect" && "$1" != "--refute" ]]; do
        script_args+=("$1")
        shift
    done

    local expect_list=() refute_list=()
    local target="none"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --expect) target="expect" ;;
            --refute) target="refute" ;;
            *)
                if [[ "$target" == "expect" ]]; then expect_list+=("$1"); else refute_list+=("$1"); fi
                ;;
        esac
        shift
    done

    echo "--- case: $name ---"
    output="$(MOCK_IFACE_STATE="$iface_state" MOCK_POE_STATE="$poe_state" \
        "$ROOT/junos-interface-poe-bounce.sh" "${script_args[@]}" 2>&1)"
    status=$?

    local ok=1
    if [[ $status -ne 0 ]]; then
        echo "  FAIL: script exited $status"
        ok=0
    fi
    for pat in "${expect_list[@]:-}"; do
        [[ -z "$pat" ]] && continue
        if ! grep -qF -- "$pat" <<<"$output"; then
            echo "  FAIL: expected output not found: $pat"
            ok=0
        fi
    done
    for pat in "${refute_list[@]:-}"; do
        [[ -z "$pat" ]] && continue
        if grep -qF -- "$pat" <<<"$output"; then
            echo "  FAIL: unexpected output present: $pat"
            ok=0
        fi
    done

    if [[ $ok -eq 1 ]]; then
        echo "  PASS"
    else
        echo "$output" | sed 's/^/    | /'
        FAILURES=$((FAILURES + 1))
    fi
    echo
}

# 1. Both enabled -> request disable both: both should change.
run_case "both enabled, disable both -> both act" Enabled Enabled \
    -u testuser -H mock-switch -i ge-0/0/1 -a disable -m both -w 1 \
    --expect "set interfaces ge-0/0/1 disable" "set poe interface ge-0/0/1 disable" "commit complete" \
    --refute "already disabled -- skipping"

# 2. Both already disabled -> request disable both: both should skip.
run_case "both disabled, disable both -> both skip" Disabled Disabled \
    -u testuser -H mock-switch -i ge-0/0/1 -a disable -m both -w 1 \
    --expect "Interface ge-0/0/1 is already disabled -- skipping interface action." \
             "PoE on ge-0/0/1 is already disabled -- skipping PoE action." \
    --refute "set interfaces ge-0/0/1 disable" "set poe interface ge-0/0/1 disable" "commit complete"

# 3. Interface disabled, PoE enabled -> request enable both: only interface should act.
run_case "mixed state, enable both -> only interface acts" Disabled Enabled \
    -u testuser -H mock-switch -i ge-0/0/1 -a enable -m both -w 1 \
    --expect "delete interfaces ge-0/0/1 disable" "already enabled -- skipping PoE action" "commit complete" \
    --refute "set poe interface ge-0/0/1 disable" "delete poe interface ge-0/0/1 disable"

# 4. mode=interface only: PoE should never even be queried.
run_case "mode=interface -> PoE untouched" Enabled Enabled \
    -u testuser -H mock-switch -i ge-0/0/1 -a disable -m interface -w 1 \
    --expect "set interfaces ge-0/0/1 disable" "commit complete" \
    --refute "show poe interface" "PoE"

# 5. mode=poe only: interface should never even be queried/changed.
run_case "mode=poe -> interface untouched" Enabled Enabled \
    -u testuser -H mock-switch -i ge-0/0/1 -a disable -m poe -w 1 \
    --expect "set poe interface ge-0/0/1 disable" "commit complete" \
    --refute "set interfaces ge-0/0/1 disable" "delete interfaces ge-0/0/1 disable"

echo "=== end of test run ==="
echo

if [[ $FAILURES -eq 0 ]]; then
    echo "TEST PASSED"
    exit 0
else
    echo "TEST FAILED: $FAILURES case(s) failed"
    exit 1
fi
