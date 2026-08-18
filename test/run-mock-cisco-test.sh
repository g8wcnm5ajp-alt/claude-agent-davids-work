#!/usr/bin/env bash
#
# Runs cisco-interface-poe-bounce.sh and cisco-interface-poe-bulk.sh
# unmodified against the mock Cisco CLI in this directory instead of a
# real switch/appliance, by shadowing `ssh` on PATH. Requires `expect`.
#
# This validates the expect scripts' own logic (the "enable" login step,
# skip-if-already-correct, multi-port grouping into one write memory) --
# it does NOT validate that the command syntax or show-output wording
# matches real Cisco hardware, since that hasn't been tested. A pass here
# means "the logic is sound", not "this works on a real switch".
#
# Usage: ./test/run-mock-cisco-test.sh

set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"

if ! command -v expect >/dev/null 2>&1; then
    echo "Error: 'expect' is required to run this test." >&2
    exit 1
fi

export PATH="$DIR/bin-cisco:$PATH"
export CISCO_PASSWORD="testpass"

FAILURES=0
CSV="$(mktemp)"
trap 'rm -f "$CSV"' EXIT

# args: name, MOCK_IFACE_STATES, MOCK_POE_STATES, script-args..., then --expect / --refute / --count lists
run_bounce_case() {
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
        "$ROOT/cisco-interface-poe-bounce.sh" "${script_args[@]}" 2>&1)"
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

# args: name, MOCK_IFACE_STATES, MOCK_POE_STATES, csv-rows(pipe-separated), script-args..., then --expect / --refute / --count
run_bulk_case() {
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
        "$ROOT/cisco-interface-poe-bulk.sh" -f "$CSV" "${script_args[@]}" 2>&1)"
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

# === bounce.sh cases ===

# 1. Login via "enable" from user exec, both enabled -> disable both.
run_bounce_case "enable-mode login, both enabled -> both act" Enabled Enabled \
    -u testuser -H mock-switch -i Gi1/0/1 -a disable -m both -w 1 \
    --expect "shutdown" "power inline never" "write memory" \
             "Line protocol: Down" "PoE operational status: OFF" \
    --refute "already disabled -- skipping"

# 2. Already disabled -> skip both, no config/write at all.
run_bounce_case "both disabled, disable both -> both skip" Disabled Disabled \
    -u testuser -H mock-switch -i Gi1/0/1 -a disable -m both -w 1 \
    --expect "Interface Gi1/0/1 is already disabled -- skipping interface action." \
             "PoE on Gi1/0/1 is already disabled -- skipping PoE action." \
    --refute "configure terminal" "write memory"

# 3. Landing directly at privileged exec (no "enable" needed) still works.
MOCK_SKIP_ENABLE=1 CISCO_PASSWORD=testpass PATH="$DIR/bin-cisco:$PATH" \
    "$ROOT/cisco-interface-poe-bounce.sh" -u testuser -H mock-switch -i Gi1/0/1 -a enable -m interface -w 1 \
    > /tmp/cisco_skipenable_out.$$ 2>&1
status=$?
echo "--- case: already-privileged login (no enable needed) ---"
if [[ $status -eq 0 ]] && grep -qF "already enabled -- skipping" /tmp/cisco_skipenable_out.$$; then
    echo "  PASS"
else
    echo "  FAIL: exit=$status"
    sed 's/^/    | /' /tmp/cisco_skipenable_out.$$
    FAILURES=$((FAILURES + 1))
fi
rm -f /tmp/cisco_skipenable_out.$$
echo

# === bulk.sh grouping cases ===

# 4. Three ports, same switch, all enabled -> disable: one write memory only.
run_bulk_case "3 ports same switch, all act -> one write memory" \
    "" "" \
    "192.168.1.10,mock-switch,Gi1/0/1|192.168.1.10,mock-switch,Gi1/0/2|192.168.1.10,mock-switch,Gi1/0/3" \
    -s testuser -a disable -m interface -w 1 \
    --expect "interface Gi1/0/1" "interface Gi1/0/2" "interface Gi1/0/3" \
    --count "Building configuration..." 1

# 5. All three already disabled -> no config/write at all.
run_bulk_case "3 ports same switch, none need change -> no write" \
    "Gi1/0/1=Disabled,Gi1/0/2=Disabled,Gi1/0/3=Disabled" "" \
    "192.168.1.10,mock-switch,Gi1/0/1|192.168.1.10,mock-switch,Gi1/0/2|192.168.1.10,mock-switch,Gi1/0/3" \
    -s testuser -a disable -m interface -w 1 \
    --expect "already disabled -- skipping" \
    --refute "configure terminal" "Building configuration..."

echo "=== end of test run ==="
echo

if [[ $FAILURES -eq 0 ]]; then
    echo "TEST PASSED"
    exit 0
else
    echo "TEST FAILED: $FAILURES case(s) failed"
    exit 1
fi
