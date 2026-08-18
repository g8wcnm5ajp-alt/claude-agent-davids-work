#!/usr/bin/env bash
#
# cisco-pull-logs.sh
#
# Cisco IOS/IOS-XE equivalent of junos-pull-logs.sh. Logs into a Cisco
# switch over SSH, pulls "show logging", and saves the raw output to a
# local file (local to wherever this script runs, not the switch).
#
# *** UNVALIDATED AGAINST REAL CISCO HARDWARE ***
# The "show logging" command itself is standard across IOS/IOS-XE, but the
# exact banner text before the log entries varies some by platform/version.
# This only affects the stripping logic's line count, not correctness of
# the saved content -- validate against real hardware before trusting it
# unattended.
#
# Requires: expect
#
# Usage:
#   ./cisco-pull-logs.sh -u <username> -H <switch-ip> [-p <password>] [-o <output-file>]
#
# Password resolution, in order of preference: -p flag, then CISCO_PASSWORD
# env var, then an interactive prompt. Prefer the env var or the prompt over
# -p where possible -- a password passed on the command line is visible to
# anyone on the box running `ps`. The same password is tried for enable
# mode if the switch prompts for one.

set -euo pipefail

VERSION="1.0.0"

SSH_TIMEOUT=20
OUTPUT_ARG=""

usage() {
    cat <<USAGE
Usage: $0 -u <username> -H <switch-ip> [-p <password>] [-o <output-file>]

  -u  Username to log into the switch with
  -H  Switch management IP or hostname
  -p  Password (visible via \`ps\` to anyone on the box -- prefer \$CISCO_PASSWORD or the prompt)
  -o  Local file to save the log to (default: <switch-ip>-cisco-log-<timestamp>.txt)
  -h  Show this help

Password resolution order: -p flag, then \$CISCO_PASSWORD, then an interactive prompt.
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

OUTPUT_FILE="${OUTPUT_ARG:-${SWITCH_IP}-cisco-log-$(date +%Y%m%d-%H%M%S).txt}"

echo "cisco-pull-logs.sh v${VERSION}"

if ! command -v expect >/dev/null 2>&1; then
    echo "Error: this script requires 'expect' to be installed." >&2
    exit 1
fi

if [[ -n "$PASSWORD_ARG" ]]; then
    CISCO_PASSWORD="$PASSWORD_ARG"
elif [[ -z "${CISCO_PASSWORD:-}" ]]; then
    read -r -s -p "Password for ${USERNAME}@${SWITCH_IP}: " CISCO_PASSWORD
    echo
fi
export CISCO_PASSWORD

export CISCO_USER="$USERNAME"
export CISCO_HOST="$SWITCH_IP"
export CISCO_SSH_TIMEOUT="$SSH_TIMEOUT"
export CISCO_OUTFILE="$OUTPUT_FILE"

expect -f - <<'EXPECT_SCRIPT'
    set timeout $env(CISCO_SSH_TIMEOUT)
    log_user 1

    set user    $env(CISCO_USER)
    set host    $env(CISCO_HOST)
    set pass    $env(CISCO_PASSWORD)
    set outfile $env(CISCO_OUTFILE)

    # User exec ">", privileged exec "#", any config level "(config...)#"
    set user_prompt {[^)]>\s*$}
    set exec_prompt {[^)]#\s*$}

    # "no" rather than "accept-new" for compatibility -- accept-new needs
    # OpenSSH 7.6+, and some management hosts still ship 7.4.
    spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $user@$host

    # Default match_max is 2000 bytes -- far too small for a switch log,
    # which silently truncates to just the last 2000 bytes received. Raise
    # it generously so a full "show logging" is never cut short. Must be
    # set on the current spawn (after spawn, no -d) -- `match_max -d`
    # (set-as-default, used before any spawn exists) segfaults on some
    # older expect/Tcl builds (observed: expect 5.45 on CentOS 7).
    match_max 20000000

    # Same tolerant single-loop login as cisco-interface-poe-bounce.sh:
    # handles however many password prompts appear (login, and possibly a
    # separate enable password) and landing directly at privileged exec
    # with no "enable" step needed at all.
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

    # Disable the CLI pager -- without it, output taller than the terminal
    # stalls waiting for a keypress.
    send -- "terminal length 0\r"
    expect -re $exec_prompt

    puts "\nPulling log from $host ...\n"
    send -- "show logging\r"
    expect -re $exec_prompt
    set raw $expect_out(buffer)

    send -- "exit\r"
    expect eof

    # Strip the echoed command (first line) and the trailing prompt (last
    # line) so the saved file is just the log content itself. Normalize
    # \r\n to \n first since the device sends CRLF line endings.
    set raw [string map {"\r\n" "\n" "\r" "\n"} $raw]
    set lines [split $raw "\n"]
    set clean [join [lrange $lines 1 end-1] "\n"]

    set fh [open $outfile w]
    puts $fh $clean
    close $fh

    set nlines [llength [split $clean "\n"]]
    puts "Saved $nlines line(s) to $outfile"
EXPECT_SCRIPT

echo "Done."
