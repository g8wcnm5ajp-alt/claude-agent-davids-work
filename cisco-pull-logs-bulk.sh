#!/usr/bin/env bash
#
# cisco-pull-logs-bulk.sh
#
# Bulk / CSV-driven version of cisco-pull-logs.sh. Requires expect -- if
# that's not available and can't be installed (e.g. a locked-down EM/
# appliance host), use cisco-pull-logs-bulk.py instead, which is
# functionally identical but uses only python3 stdlib.
#
# Reads a CSV file where each row is:
#
#   appliance_ip,switch_ip
#
# For each row, SSHes to the appliance first, then hops from there to the
# Cisco switch, pulls "show logging", and saves it to a local file (local
# to wherever this script runs -- e.g. the EM) named:
#
#   SwitchLog-<appliance_ip>-<switch_ip>.log
#
# The appliance hop is always root@<appliance-ip>, run from the root
# account on the EM (Enterprise Manager) this script itself runs on --
# that account's public key is already trusted by every appliance, so it
# needs neither a username flag nor a password. Only the switch hop needs
# a username and password (and possibly an enable password -- this script
# assumes it's the same as the login password).
#
# Requires: expect
#
# Usage:
#   ./cisco-pull-logs-bulk.sh -s <switch-username> -f <csv-file> [-p <password>] [-o <output-dir>]
#
# CSV format: one row per line, no header, e.g.:
#   192.168.1.10,192.168.22.221
#   192.168.1.11,192.168.22.222
# Blank lines and lines starting with # are skipped. If the same switch IP
# appears more than once, later rows are skipped with a warning -- one log
# pull per switch.
#
# One row failing (bad login, unreachable host, etc.) does not stop the
# rest of the batch -- failures are collected and reported in a summary at
# the end, and the script exits non-zero if any row failed.
#
# Password resolution order: -p flag, then CISCO_PASSWORD env var, then an
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
  -p  Password (visible via \`ps\` to anyone on the box -- prefer \$CISCO_PASSWORD or the prompt)
  -o  Directory to save logs into (default: current directory)
  -h  Show this help

The appliance hop is always root@<appliance-ip> via pre-shared keys (no
username or password needed for it). -s / the password are only for the
switch login. Blank lines and lines starting with # in the CSV are
skipped. Each switch's log is saved as SwitchLog-<appliance>-<switch>.log.

Password resolution order: -p flag, then \$CISCO_PASSWORD, then an interactive prompt.
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

echo "cisco-pull-logs-bulk.sh v${VERSION}"

if ! command -v expect >/dev/null 2>&1; then
    echo "Error: this script requires 'expect' to be installed." >&2
    exit 1
fi

if [[ -n "$PASSWORD_ARG" ]]; then
    CISCO_PASSWORD="$PASSWORD_ARG"
elif [[ -z "${CISCO_PASSWORD:-}" ]]; then
    read -r -s -p "Password for ${SWITCH_USERNAME}@switch: " CISCO_PASSWORD
    echo
fi
export CISCO_PASSWORD

export CISCO_SWITCH_USER="$SWITCH_USERNAME"
export CISCO_SSH_TIMEOUT="$SSH_TIMEOUT"

# Some Cisco switches (older IOS, e.g. Catalyst 3560) present a legacy RSA
# host key under 1024 bits. Modern OpenSSH (8.5+) hard-rejects that with
# "Bad server host key: Invalid key length" and there's no negotiable
# workaround except RequiredRSASize -- which is itself only understood by
# OpenSSH new enough to need it. Detect support with `ssh -G` (a config
# dry-run, no network needed) rather than assuming, since this script may
# run from appliances with a range of OpenSSH versions and an unrecognized
# -o option is a hard failure, not a no-op. Only ever applied to the
# switch hop -- the appliance's own host key is normal-sized.
CISCO_SWITCH_KEY_OPT=""
if ssh -o RequiredRSASize=512 -G localhost >/dev/null 2>&1; then
    CISCO_SWITCH_KEY_OPT="-o RequiredRSASize=512"
fi
export CISCO_SWITCH_KEY_OPT

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

run_switch() {
    local appliance="$1" switch="$2" outfile="$3"
    export CISCO_APPLIANCE="$appliance"
    export CISCO_HOST="$switch"
    export CISCO_OUTFILE="$outfile"

    expect -f - <<'EXPECT_SCRIPT'
        set timeout $env(CISCO_SSH_TIMEOUT)
        log_user 1

        set switch_user   $env(CISCO_SWITCH_USER)
        set appliance     $env(CISCO_APPLIANCE)
        set host          $env(CISCO_HOST)
        set pass          $env(CISCO_PASSWORD)
        set outfile       $env(CISCO_OUTFILE)
        set switch_key_opt $env(CISCO_SWITCH_KEY_OPT)

        # User exec ">", privileged exec "#"
        set user_prompt {[^)]>\s*$}
        set exec_prompt {[^)]#\s*$}

        puts "\n=== $appliance -> $host ==="

        set ssh_opts {-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null}
        set switch_ssh_opts [concat $ssh_opts [split $switch_key_opt]]
        spawn ssh -tt {*}$ssh_opts root@$appliance ssh -tt {*}$switch_ssh_opts $switch_user@$host

        # Default match_max is 2000 bytes -- far too small for a switch
        # log. Must be set on the current spawn (after spawn, no -d) --
        # `match_max -d` segfaults on some older expect/Tcl builds
        # (observed: expect 5.45 on CentOS 7).
        match_max 20000000

        # Tolerant of however many password prompts appear (appliance
        # login, possibly enable mode, possibly a separate enable secret)
        # and of landing directly at privileged exec with no "enable" step
        # needed at all.
        set pw_sent 0
        while 1 {
            expect {
                -re $exec_prompt { break }
                -re $user_prompt { send -- "enable\r" }
                -re {[Pp]assword:} {
                    incr pw_sent
                    if {$pw_sent > 3} {
                        puts "\nERROR: too many password prompts, aborting"; exit 1
                    }
                    send -- "$pass\r"
                }
                -re {[Pp]ermission [Dd]enied|[Aa]uthentication [Ff]ailed|% ?[Ll]ogin invalid|% ?[Bb]ad (secrets|passwords)} {
                    puts "\nERROR: login failed ($pw_sent password(s) sent)"; exit 1
                }
                timeout { puts "\nERROR: timed out waiting for login prompt ($pw_sent password(s) sent)"; exit 1 }
                eof     { puts "\nERROR: connection closed before login ($pw_sent password(s) sent)"; exit 1 }
            }
        }

        # Disable the CLI pager -- without it, output taller than the
        # terminal stalls waiting for a keypress.
        send -- "terminal length 0\r"
        expect -re $exec_prompt

        send -- "show logging\r"
        expect -re $exec_prompt
        set raw $expect_out(buffer)

        send -- "exit\r"
        expect { eof {} timeout {} }

        # Strip the echoed command (first line) and the trailing prompt
        # (last line). Normalize \r\n to \n first since the device sends
        # CRLF line endings.
        set raw [string map {"\r\n" "\n" "\r" "\n"} $raw]
        set lines [split $raw "\n"]
        set clean [join [lrange $lines 1 end-1] "\n"]

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
