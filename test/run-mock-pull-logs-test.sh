#!/usr/bin/env bash
#
# Runs junos-pull-logs.sh/.py and cisco-pull-logs.sh/.py unmodified against
# their respective mock CLIs, by shadowing `ssh` on PATH. The .sh scripts
# require `expect`; the .py scripts require python3 (skipped if missing).
#
# Usage: ./test/run-mock-pull-logs-test.sh

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

# args: name, outfile, ssh-shim-dir, "VAR=value" for the ssh password env,
#       expected-fake-line, echoed-command-text, prompt-substring, command...
run_case() {
    local name="$1" outfile="$2" bindir="$3" pwassign="$4" fakeline="$5" echotext="$6" promptsub="$7"
    shift 7

    echo "--- case: $name ---"
    PATH="$bindir:$PATH" env "$pwassign" "$@" > "$WORKDIR/run.out" 2>&1
    status=$?

    if [[ $status -ne 0 ]]; then
        echo "  FAIL: script exited $status"
        sed 's/^/    | /' "$WORKDIR/run.out"
        FAILURES=$((FAILURES + 1))
    elif [[ ! -s "$outfile" ]]; then
        echo "  FAIL: output file missing or empty: $outfile"
        FAILURES=$((FAILURES + 1))
    elif ! grep -qF "$fakeline" "$outfile"; then
        echo "  FAIL: expected log content not found in $outfile"
        sed 's/^/    | /' "$outfile"
        FAILURES=$((FAILURES + 1))
    elif [[ "$(head -n1 "$outfile")" == "$echotext" ]]; then
        echo "  FAIL: echoed command leaked into saved file (found as first line)"
        FAILURES=$((FAILURES + 1))
    elif [[ "$(tail -n1 "$outfile")" == *"$promptsub"* ]]; then
        echo "  FAIL: trailing prompt leaked into saved file (found as last line)"
        FAILURES=$((FAILURES + 1))
    elif [[ "$(tail -n1 "$outfile")" == "{master:"* || -z "$(tail -n1 "$outfile")" ]]; then
        echo "  FAIL: trailing {master:N}/blank block leaked into saved file (found as last line)"
        FAILURES=$((FAILURES + 1))
    else
        echo "  PASS"
    fi
    echo
}

if [[ $HAVE_EXPECT -eq 1 ]]; then
    run_case "junos-pull-logs.sh" "$WORKDIR/junos_sh.log" "$DIR/bin" 'JUNOS_PASSWORD=testpass' \
        "fake log line 1" "show log messages" "mock-switch>" \
        "$ROOT/junos-pull-logs.sh" -u testuser -H mock-switch -o "$WORKDIR/junos_sh.log"

    run_case "cisco-pull-logs.sh" "$WORKDIR/cisco_sh.log" "$DIR/bin-cisco" 'CISCO_PASSWORD=testpass' \
        "fake log line 1" "show logging" "mock-switch#" \
        "$ROOT/cisco-pull-logs.sh" -u testuser -H mock-switch -o "$WORKDIR/cisco_sh.log"
else
    echo "Skipping .sh cases -- 'expect' not available."
    echo
fi

if [[ $HAVE_PY -eq 1 ]]; then
    run_case "junos-pull-logs.py" "$WORKDIR/junos_py.log" "$DIR/bin" 'JUNOS_PASSWORD=testpass' \
        "fake log line 1" "show log messages" "mock-switch>" \
        python3 "$ROOT/junos-pull-logs.py" -u testuser -H mock-switch -o "$WORKDIR/junos_py.log"

    run_case "cisco-pull-logs.py" "$WORKDIR/cisco_py.log" "$DIR/bin-cisco" 'CISCO_PASSWORD=testpass' \
        "fake log line 1" "show logging" "mock-switch#" \
        python3 "$ROOT/cisco-pull-logs.py" -u testuser -H mock-switch -o "$WORKDIR/cisco_py.log"
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
