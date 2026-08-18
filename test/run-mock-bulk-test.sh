#!/usr/bin/env bash
#
# Runs junos-interface-poe-bulk.sh unmodified against the mock CLI in this
# directory instead of a real switch/appliance, by shadowing `ssh` on PATH
# (the double-hop's outer ssh call resolves to the mock directly, which is
# fine for exercising this script's own command sequencing -- the actual
# double-hop mechanism itself was validated separately against real
# infrastructure). Requires `expect`.
#
# Exercises the multi-port-per-switch grouping behavior specifically: one
# login, at most one commit, and only the ports that actually need a
# change are included in it.
#
# Usage: ./test/run-mock-bulk-test.sh

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
CSV="$(mktemp)"
trap 'rm -f "$CSV"' EXIT

# args: name, MOCK_IFACE_STATES, MOCK_POE_STATES, csv-rows(pipe-separated), script-args..., then --expect / --refute / --count lists
# --count "pattern" N   -- pattern must appear exactly N times
run_case() {
    local name="$1" iface_states="$2" poe_states="$3" csv_rows="$4"
    shift 4

    local script_args=()
    while [[ "$1" != "--expect" && "$1" != "--refute" && "$1" != "--count" ]]; do
        script_args+=("$1")
        shift
    done

    local expect_list=() refute_list=()
    local count_pats=() count_vals=()
    local target="none"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --expect) target="expect" ;;
            --refute) target="refute" ;;
            --count)
                target="count"
                count_pats+=("$2")
                count_vals+=("$3")
                shift 2
                ;;
            *)
                if [[ "$target" == "expect" ]]; then expect_list+=("$1"); else refute_list+=("$1"); fi
                ;;
        esac
        shift
    done

    IFS='|' read -ra rows <<< "$csv_rows"
    printf '%s\n' "${rows[@]}" > "$CSV"

    echo "--- case: $name ---"
    output="$(MOCK_IFACE_STATES="$iface_states" MOCK_POE_STATES="$poe_states" \
        "$ROOT/junos-interface-poe-bulk.sh" -f "$CSV" "${script_args[@]}" 2>&1)"
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
    for ((i = 0; i < ${#count_pats[@]}; i++)); do
        pat="${count_pats[$i]}"
        want="${count_vals[$i]}"
        got=$(grep -cF -- "$pat" <<<"$output")
        if [[ "$got" != "$want" ]]; then
            echo "  FAIL: expected '$pat' to appear $want time(s), got $got"
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

# 1. Three ports, same switch, all enabled -> request disable: all three
#    should be included in exactly ONE commit.
run_case "3 ports same switch, all act -> one commit" \
    "" "" \
    "192.168.1.10,mock-switch,ge-0/0/1|192.168.1.10,mock-switch,ge-0/0/2|192.168.1.10,mock-switch,ge-0/0/3" \
    -s testuser -a disable -m interface -w 1 \
    --expect "set interfaces ge-0/0/1 disable" "set interfaces ge-0/0/2 disable" "set interfaces ge-0/0/3 disable" \
    --count "commit complete" 1

# 2. Same three ports, all already disabled -> request disable: no
#    configure/commit at all.
run_case "3 ports same switch, none need change -> no commit" \
    "ge-0/0/1=Disabled,ge-0/0/2=Disabled,ge-0/0/3=Disabled" "" \
    "192.168.1.10,mock-switch,ge-0/0/1|192.168.1.10,mock-switch,ge-0/0/2|192.168.1.10,mock-switch,ge-0/0/3" \
    -s testuser -a disable -m interface -w 1 \
    --expect "already disabled -- skipping" \
    --refute "configure" "commit complete"

# 3. Mixed: port1 already disabled, port2+port3 enabled -> request disable:
#    only port2/port3 in the single commit, port1 left alone.
run_case "mixed states -> only the ports that need it are committed" \
    "ge-0/0/1=Disabled,ge-0/0/2=Enabled,ge-0/0/3=Enabled" "" \
    "192.168.1.10,mock-switch,ge-0/0/1|192.168.1.10,mock-switch,ge-0/0/2|192.168.1.10,mock-switch,ge-0/0/3" \
    -s testuser -a disable -m interface -w 1 \
    --expect "[ge-0/0/1] Interface is already disabled -- skipping interface action." \
             "set interfaces ge-0/0/2 disable" "set interfaces ge-0/0/3 disable" \
    --refute "set interfaces ge-0/0/1 disable" \
    --count "commit complete" 1

echo "=== end of test run ==="
echo

if [[ $FAILURES -eq 0 ]]; then
    echo "TEST PASSED"
    exit 0
else
    echo "TEST FAILED: $FAILURES case(s) failed"
    exit 1
fi
