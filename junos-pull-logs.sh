#!/usr/bin/env bash
#
# junos-pull-logs.sh
#
# Logs into a Juniper switch over SSH, pulls "show log messages", and saves
# the raw output to a local file (local to wherever this script runs, not
# the switch).
#
# Requires: expect
#
# Usage:
#   ./junos-pull-logs.sh -u <username> -H <switch-ip> [-p <password>] [-o <output-file>]
#
# Password resolution, in order of preference: -p flag, then JUNOS_PASSWORD
# env var, then an interactive prompt. Prefer the env var or the prompt over
# -p where possible -- a password passed on the command line is visible to
# anyone on the box running `ps`.

set -euo pipefail

VERSION="1.0.0"

SSH_TIMEOUT=20
OUTPUT_ARG=""

usage() {
    cat <<USAGE
Usage: $0 -u <username> -H <switch-ip> [-p <password>] [-o <output-file>]

  -u  Username to log into the switch with
  -H  Switch management IP or hostname
  -p  Password (visible via \`ps\` to anyone on the box -- prefer \$JUNOS_PASSWORD or the prompt)
  -o  Local file to save the log to (default: <switch-ip>-junos-log-<timestamp>.txt)
  -h  Show this help

Password resolution order: -p flag, then \$JUNOS_PASSWORD, then an interactive prompt.
USAGE
    exit 1
}

USERNAME=""
SWITCH_IP=""
PASSWORD_ARG=""

while getopts "u:H:p:o:h" opt; do
    case "$opt" in
        u) USERNAME="$OPTARG" ;;
        H) SWITCH_IP="$OPTARG" ;;
        p) PASSWORD_ARG="$OPTARG" ;;
        o) OUTPUT_ARG="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$USERNAME"  ]] && { echo "Error: -u <username> is required"  >&2; usage; }
[[ -z "$SWITCH_IP" ]] && { echo "Error: -H <switch-ip> is required" >&2; usage; }

OUTPUT_FILE="${OUTPUT_ARG:-${SWITCH_IP}-junos-log-$(date +%Y%m%d-%H%M%S).txt}"

echo "junos-pull-logs.sh v${VERSION}"

if ! command -v expect >/dev/null 2>&1; then
    echo "Error: this script requires 'expect' to be installed." >&2
    exit 1
fi

if [[ -n "$PASSWORD_ARG" ]]; then
    JUNOS_PASSWORD="$PASSWORD_ARG"
elif [[ -z "${JUNOS_PASSWORD:-}" ]]; then
    read -r -s -p "Password for ${USERNAME}@${SWITCH_IP}: " JUNOS_PASSWORD
    echo
fi
export JUNOS_PASSWORD

export JUNOS_USER="$USERNAME"
export JUNOS_HOST="$SWITCH_IP"
export JUNOS_SSH_TIMEOUT="$SSH_TIMEOUT"
export JUNOS_OUTFILE="$OUTPUT_FILE"

expect -f - <<'EXPECT_SCRIPT'
    set timeout $env(JUNOS_SSH_TIMEOUT)
    log_user 1

    set user    $env(JUNOS_USER)
    set host    $env(JUNOS_HOST)
    set pass    $env(JUNOS_PASSWORD)
    set outfile $env(JUNOS_OUTFILE)

    set op_prompt {[%>] $}

    # "no" rather than "accept-new" for compatibility -- accept-new needs
    # OpenSSH 7.6+, and some management hosts still ship 7.4.
    spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $user@$host

    # Default match_max is 2000 bytes -- far too small for a switch log,
    # which silently truncates to just the last 2000 bytes received. Raise
    # it generously so a full "show log messages" is never cut short. Must
    # be set on the current spawn (after spawn, no -d) -- `match_max -d`
    # (set-as-default, used before any spawn exists) segfaults on some
    # older expect/Tcl builds (observed: expect 5.45 on CentOS 7).
    match_max 20000000

    expect {
        -re {[Pp]assword:} { send -- "$pass\r" }
        timeout             { puts "\nERROR: timed out waiting for password prompt"; exit 1 }
        eof                 { puts "\nERROR: connection closed before login"; exit 1 }
    }

    expect {
        -re $op_prompt { }
        -re {[Pp]ermission [Dd]enied|[Aa]uthentication [Ff]ailed} {
            puts "\nERROR: login failed"; exit 1
        }
        timeout { puts "\nERROR: timed out waiting for login prompt"; exit 1 }
    }

    # Disable the CLI's "---(more)---" pager -- without it, output taller
    # than the terminal stalls waiting for a keypress.
    send -- "set cli screen-length 0\r"
    expect -re $op_prompt

    puts "\nPulling log from $host ...\n"
    send -- "show log messages\r"
    expect -re $op_prompt
    set raw $expect_out(buffer)

    send -- "exit\r"
    expect eof

    # Strip the echoed command (first line) and the trailing prompt (last
    # line) so the saved file is just the log content itself. Normalize
    # \r\n to \n first since the device sends CRLF line endings.
    set raw [string map {"\r\n" "\n" "\r" "\n"} $raw]
    set lines [split $raw "\n"]
    set lines [lrange $lines 1 end-1]
    # Some Junos platforms (e.g. dual-RE-style EX/QFX) print a routing-
    # engine mastership indicator ("{master:0}") plus a blank line right
    # before every prompt; strip that trailing block too if present, so it
    # doesn't end up as noise at the end of the saved log.
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

echo "Done."
