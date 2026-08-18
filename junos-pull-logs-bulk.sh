#!/usr/bin/env bash
#
# junos-pull-logs-bulk.sh
#
# Bulk / CSV-driven version of junos-pull-logs.sh. Requires expect -- if
# that's not available and can't be installed (e.g. a locked-down EM/
# appliance host), use junos-pull-logs-bulk.py instead, which is
# functionally identical but uses only python3 stdlib.
#
# Reads a CSV file where each row is:
#
#   appliance_ip,switch_ip
#
# For each row, SSHes to the appliance first, then hops from there to the
# Juniper switch, pulls "show log messages", and saves it to a local file
# (local to wherever this script runs -- e.g. the EM) named:
#
#   SwitchLog-<appliance_ip>-<switch_ip>.log
#
# The appliance hop is always root@<appliance-ip>, run from the root
# account on the EM (Enterprise Manager) this script itself runs on --
# that account's public key is already trusted by every appliance, so it
# needs neither a username flag nor a password. Only the switch hop (an
# operator-class Junos CLI account, e.g. "claude") needs a username and
# password.
#
# Requires: expect
#
# Usage:
#   ./junos-pull-logs-bulk.sh -s <switch-username> -f <csv-file> [-p <password>] [-o <output-dir>]
#
# CSV format: one row per line, no header, e.g.:
#   192.168.1.10,192.168.22.223
#   192.168.1.11,192.168.22.224
# Blank lines and lines starting with # are skipped. If the same switch IP
# appears more than once, later rows are skipped with a warning -- one log
# pull per switch.
#
# One row failing (bad login, unreachable host, etc.) does not stop the
# rest of the batch -- failures are collected and reported in a summary at
# the end, and the script exits non-zero if any row failed.
#
# Password resolution order: -p flag, then JUNOS_PASSWORD env var, then an
# interactive prompt. Prefer the env var or the prompt over -p where
# possible -- a password passed on the command line is visible to anyone on
# the box running `ps`. This password is only ever needed for the switch
# login; the appliance hop is passwordless (key-based).

set -uo pipefail   # no -e: one row failing must not abort the batch

VERSION="1.0.0"

SSH_TIMEOUT=20
CSV_FILE=""
OUTPUT_DIR="."

usage() {
    cat <<USAGE
Usage: $0 -s <switch-username> -f <csv-file> [-p <password>] [-o <output-dir>]

  -s  Username to log into the switch with (via the appliance)
  -f  CSV file: one row per line, "appliance_ip,switch_ip"
  -p  Password (visible via \`ps\` to anyone on the box -- prefer \$JUNOS_PASSWORD or the prompt)
  -o  Directory to save logs into (default: current directory)
  -h  Show this help

The appliance hop is always root@<appliance-ip> via pre-shared keys (no
username or password needed for it). -s / the password are only for the
switch login. Blank lines and lines starting with # in the CSV are
skipped. Each switch's log is saved as SwitchLog-<appliance>-<switch>.log.

Password resolution order: -p flag, then \$JUNOS_PASSWORD, then an interactive prompt.
USAGE
    exit 1
}

SWITCH_USERNAME=""
PASSWORD_ARG=""

while getopts "s:f:p:o:h" opt; do
    case "$opt" in
        s) SWITCH_USERNAME="$OPTARG" ;;
        f) CSV_FILE="$OPTARG" ;;
        p) PASSWORD_ARG="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$SWITCH_USERNAME" ]] && { echo "Error: -s <switch-username> is required" >&2; usage; }
[[ -z "$CSV_FILE" ]] && { echo "Error: -f <csv-file> is required" >&2; usage; }
[[ -f "$CSV_FILE" ]] || { echo "Error: file not found: $CSV_FILE" >&2; exit 1; }
[[ -d "$OUTPUT_DIR" ]] || { echo "Error: output directory not found: $OUTPUT_DIR" >&2; exit 1; }

echo "junos-pull-logs-bulk.sh v${VERSION}"

if ! command -v expect >/dev/null 2>&1; then
    echo "Error: this script requires 'expect' to be installed." >&2
    exit 1
fi

if [[ -n "$PASSWORD_ARG" ]]; then
    JUNOS_PASSWORD="$PASSWORD_ARG"
elif [[ -z "${JUNOS_PASSWORD:-}" ]]; then
    read -r -s -p "Password for ${SWITCH_USERNAME}@switch: " JUNOS_PASSWORD
    echo
fi
export JUNOS_PASSWORD

export JUNOS_SWITCH_USER="$SWITCH_USERNAME"
export JUNOS_SSH_TIMEOUT="$SSH_TIMEOUT"

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

run_switch() {
    local appliance="$1" switch="$2" outfile="$3"
    export JUNOS_APPLIANCE="$appliance"
    export JUNOS_HOST="$switch"
    export JUNOS_OUTFILE="$outfile"

    expect -f - <<'EXPECT_SCRIPT'
        set timeout $env(JUNOS_SSH_TIMEOUT)
        log_user 1

        set switch_user $env(JUNOS_SWITCH_USER)
        set appliance   $env(JUNOS_APPLIANCE)
        set host        $env(JUNOS_HOST)
        set pass        $env(JUNOS_PASSWORD)
        set outfile     $env(JUNOS_OUTFILE)

        set op_prompt {[%>] $}

        puts "\n=== $appliance -> $host ==="

        # Hop 1: ssh to the appliance, whose remote command is itself an ssh
        # to the switch -- avoids ever needing to match the appliance's own
        # (unknown) shell prompt. "no" rather than "accept-new" for
        # compatibility with older OpenSSH clients; UserKnownHostsFile=
        # /dev/null since fleet devices get reimaged/reassigned IPs and
        # StrictHostKeyChecking=no alone still refuses a *changed* key.
        set ssh_opts {-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null}
        spawn ssh -tt {*}$ssh_opts root@$appliance ssh -tt {*}$ssh_opts $switch_user@$host

        # Default match_max is 2000 bytes -- far too small for a switch
        # log, which silently truncates to just the last 2000 bytes
        # received. Raise it generously so a full "show log messages" is
        # never cut short. Must be set on the current spawn (after spawn,
        # no -d) -- `match_max -d` (set-as-default, used before any spawn
        # exists) segfaults on some older expect/Tcl builds (observed:
        # expect 5.45 on CentOS 7).
        match_max 20000000

        # Tolerant of 0, 1, or 2 password prompts -- some appliances have
        # pre-existing key trust to the switch and skip straight from the
        # appliance login to the Junos operational prompt with no second
        # password prompt at all.
        set pw_sent 0
        while 1 {
            expect {
                -re $op_prompt { break }
                -re {[Pp]assword:} {
                    incr pw_sent
                    if {$pw_sent > 2} {
                        puts "\nERROR: too many password prompts, aborting"; exit 1
                    }
                    send -- "$pass\r"
                }
                -re {[Pp]ermission [Dd]enied|[Aa]uthentication [Ff]ailed} {
                    puts "\nERROR: login failed ($pw_sent password(s) sent)"; exit 1
                }
                timeout { puts "\nERROR: timed out waiting for login prompt ($pw_sent password(s) sent)"; exit 1 }
                eof     { puts "\nERROR: connection closed before login ($pw_sent password(s) sent)"; exit 1 }
            }
        }

        # Disable the CLI's "---(more)---" pager -- without it, output
        # taller than the terminal stalls waiting for a keypress.
        send -- "set cli screen-length 0\r"
        expect -re $op_prompt

        send -- "show log messages\r"
        expect -re $op_prompt
        set raw $expect_out(buffer)

        send -- "exit\r"
        expect { eof {} timeout {} }

        # Strip the echoed command (first line) and the trailing prompt
        # (last line). Normalize \r\n to \n first since the device sends
        # CRLF line endings.
        set raw [string map {"\r\n" "\n" "\r" "\n"} $raw]
        set lines [split $raw "\n"]
        set lines [lrange $lines 1 end-1]
        # Some Junos platforms (e.g. dual-RE-style EX/QFX) print a routing-
        # engine mastership indicator ("{master:0}") plus a blank line
        # right before every prompt; strip that trailing block too if
        # present, so it doesn't end up as noise at the end of the saved
        # log.
        if {[llength $lines] > 0 && [regexp {^\{master:\d+\}$} [lindex $lines end]]} {
            set lines [lrange $lines 0 end-1]
        }
        if {[llength $lines] > 0 && [string trim [lindex $lines end]] eq ""} {
            set lines [lrange $lines 0 end-1]
        }
        set clean [join $lines "\n"]

        set fh [open $outfile w]
        puts $fh $clean
        close $fh

        set nlines [llength [split $clean "\n"]]
        puts "Saved $nlines line(s) to $outfile"
EXPECT_SCRIPT
}

TOTAL=0
OK=0
FAILED=0
FAILED_ROWS=()
SEEN_SWITCHES=()

while IFS=',' read -r raw_appliance raw_switch || [[ -n "${raw_appliance:-}" ]]; do
    appliance="$(trim "${raw_appliance:-}")"
    switch="$(trim "${raw_switch:-}")"

    [[ -z "$appliance" ]] && continue
    [[ "$appliance" == \#* ]] && continue

    if [[ -z "$switch" ]]; then
        echo "Error: malformed row (need appliance_ip,switch_ip): $raw_appliance,$raw_switch" >&2
        FAILED=$((FAILED + 1))
        FAILED_ROWS+=("$raw_appliance,$raw_switch (malformed)")
        continue
    fi

    already_seen=0
    for s in "${SEEN_SWITCHES[@]:-}"; do
        [[ "$s" == "$switch" ]] && already_seen=1 && break
    done
    if [[ $already_seen -eq 1 ]]; then
        echo "Warning: switch $switch already processed -- skipping duplicate row" >&2
        continue
    fi
    SEEN_SWITCHES+=("$switch")

    TOTAL=$((TOTAL + 1))
    OUTFILE="${OUTPUT_DIR}/SwitchLog-${appliance}-${switch}.log"

    status=0
    run_switch "$appliance" "$switch" "$OUTFILE" || status=$?
    if [[ $status -eq 0 ]]; then
        OK=$((OK + 1))
    else
        FAILED=$((FAILED + 1))
        FAILED_ROWS+=("$appliance,$switch")
    fi
done < "$CSV_FILE"

echo
echo "=== summary: $OK/$TOTAL switch(es) succeeded ==="
if [[ ${#FAILED_ROWS[@]} -gt 0 ]]; then
    echo "Failed rows:"
    for row in "${FAILED_ROWS[@]}"; do
        echo "  - $row"
    done
    exit 1
fi

exit 0
