#!/usr/bin/env bash
#
# Runs junos-pull-logs-bulk.sh/.py and cisco-pull-logs-bulk.sh/.py against
# their respective mock CLIs, by shadowing `ssh` on PATH (the double-hop's
# outer ssh call resolves straight to the mock, which is fine for
# exercising this script's own command sequencing -- the actual double-hop
# mechanism itself was validated separately against real infrastructure).
# The .sh scripts require `expect`; the .py scripts require python3
# (skipped if missing).
#
# Usage: ./test/run-mock-pull-logs-bulk-test.sh

set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"

HAVE_EXPECT=0
command -v expect >/dev/null 2>&1 && HAVE_EXPECT=1
HAVE_PY=0
command -v python3 >/dev/null 2>&1 && HAVE_PY=1

if [[ $HAVE_EXPECT -eq 0 && $HAVE_PY -eq 0 ]]; then
    echo "Error: neither 'expect' nor 'python3' is available -- nothing to test." >&2
    exit 1
fi

FAILURES=0
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# args: name, bindir, "VAR=value" for password, csv-rows(pipe-separated),
#       expected-outfile-basename, fakeline, command...
run_case() {
    local name="$1" bindir="$2" pwassign="$3" csv_rows="$4" expected_file="$5" fakeline="$6"
    shift 6

    local csv="$WORKDIR/rows.csv"
    IFS='|' read -ra rows <<< "$csv_rows"
    printf '%s\n' "${rows[@]}" > "$csv"

    echo "--- case: $name ---"
    PATH="$bindir:$PATH" env "$pwassign" "$@" -f "$csv" -o "$WORKDIR" > "$WORKDIR/run.out" 2>&1
    status=$?

    local outfile="$WORKDIR/$expected_file"
    if [[ $status -ne 0 ]]; then
        echo "  FAIL: script exited $status"
        sed 's/^/    | /' "$WORKDIR/run.out"
        FAILURES=$((FAILURES + 1))
    elif [[ ! -s "$outfile" ]]; then
        echo "  FAIL: output file missing or empty: $outfile"
        sed 's/^/    | /' "$WORKDIR/run.out"
        FAILURES=$((FAILURES + 1))
    elif ! grep -qF "$fakeline" "$outfile"; then
        echo "  FAIL: expected log content not found in $outfile"
        sed 's/^/    | /' "$outfile"
        FAILURES=$((FAILURES + 1))
    else
        echo "  PASS"
    fi
    rm -f "$outfile"
    echo
}

# Duplicate-switch-row skip: two rows for the same switch, same appliance
# -- exactly one file should be produced (via a single log pull), and the
# script should warn about the skipped duplicate rather than pulling twice.
run_dup_case() {
    local name="$1" bindir="$2" pwassign="$3" expected_file="$4"
    shift 4

    local csv="$WORKDIR/dup_rows.csv"
    printf '192.168.1.10,mock-switch\n192.168.1.10,mock-switch\n' > "$csv"

    echo "--- case: $name (duplicate switch row) ---"
    PATH="$bindir:$PATH" env "$pwassign" "$@" -f "$csv" -o "$WORKDIR" > "$WORKDIR/dup.out" 2>&1
    status=$?

    local outfile="$WORKDIR/$expected_file"
    if [[ $status -ne 0 ]]; then
        echo "  FAIL: script exited $status"
        sed 's/^/    | /' "$WORKDIR/dup.out"
        FAILURES=$((FAILURES + 1))
    elif ! grep -qF "skipping duplicate row" "$WORKDIR/dup.out"; then
        echo "  FAIL: expected duplicate-row warning not found"
        sed 's/^/    | /' "$WORKDIR/dup.out"
        FAILURES=$((FAILURES + 1))
    elif [[ ! -s "$outfile" ]]; then
        echo "  FAIL: output file missing or empty: $outfile"
        FAILURES=$((FAILURES + 1))
    else
        echo "  PASS"
    fi
    rm -f "$outfile"
    echo
}

if [[ $HAVE_EXPECT -eq 1 ]]; then
    run_case "junos-pull-logs-bulk.sh" "$DIR/bin" 'JUNOS_PASSWORD=testpass' \
        "192.168.1.10,mock-switch" "SwitchLog-192.168.1.10-mock-switch.log" "fake log line 1" \
        "$ROOT/junos-pull-logs-bulk.sh" -s testuser

    run_case "cisco-pull-logs-bulk.sh" "$DIR/bin-cisco" 'CISCO_PASSWORD=testpass' \
        "192.168.1.10,mock-switch" "SwitchLog-192.168.1.10-mock-switch.log" "fake log line 1" \
        "$ROOT/cisco-pull-logs-bulk.sh" -s testuser

    run_dup_case "junos-pull-logs-bulk.sh" "$DIR/bin" 'JUNOS_PASSWORD=testpass' \
        "SwitchLog-192.168.1.10-mock-switch.log" \
        "$ROOT/junos-pull-logs-bulk.sh" -s testuser
else
    echo "Skipping .sh cases -- 'expect' not available."
    echo
fi

if [[ $HAVE_PY -eq 1 ]]; then
    run_case "junos-pull-logs-bulk.py" "$DIR/bin" 'JUNOS_PASSWORD=testpass' \
        "192.168.1.10,mock-switch" "SwitchLog-192.168.1.10-mock-switch.log" "fake log line 1" \
        python3 "$ROOT/junos-pull-logs-bulk.py" -s testuser

    run_case "cisco-pull-logs-bulk.py" "$DIR/bin-cisco" 'CISCO_PASSWORD=testpass' \
        "192.168.1.10,mock-switch" "SwitchLog-192.168.1.10-mock-switch.log" "fake log line 1" \
        python3 "$ROOT/cisco-pull-logs-bulk.py" -s testuser

    run_dup_case "junos-pull-logs-bulk.py" "$DIR/bin" 'JUNOS_PASSWORD=testpass' \
        "SwitchLog-192.168.1.10-mock-switch.log" \
        python3 "$ROOT/junos-pull-logs-bulk.py" -s testuser
else
    echo "Skipping .py cases -- 'python3' not available."
    echo
fi

echo "=== end of test run ==="
echo

if [[ $FAILURES -eq 0 ]]; then
    echo "TEST PASSED"
    exit 0
else
    echo "TEST FAILED: $FAILURES case(s) failed"
    exit 1
fi
