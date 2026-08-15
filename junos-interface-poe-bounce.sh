#!/usr/bin/env bash
#
# junos-interface-poe-bounce.sh
#
# Logs into a Juniper switch over SSH, enters configuration mode, then:
#   1. disables the given interface, waits, re-enables it
#   2. disables PoE on the same interface, waits, re-enables it
#   3. exits configuration mode and prints the interface's current state
#
# Requires: expect
#
# Usage:
#   ./junos-interface-poe-bounce.sh -u <username> -H <switch-ip> -i <interface> [-w <wait-seconds>]
#
# Password is read from the JUNOS_PASSWORD env var if set, otherwise prompted
# for interactively (never pass it as a bare CLI argument -- it would be
# visible to anyone running `ps`).

set -euo pipefail

WAIT_SECS=5
SSH_TIMEOUT=20

usage() {
    cat <<USAGE
Usage: $0 -u <username> -H <switch-ip> -i <interface> [-w <wait-seconds>]

  -u  Username to log into the switch with
  -H  Switch management IP or hostname
  -i  Interface name to bounce (e.g. ge-0/0/5)
  -w  Seconds to wait between disable/enable steps (default: ${WAIT_SECS})
  -h  Show this help

Password is taken from \$JUNOS_PASSWORD if set, otherwise you'll be prompted.
USAGE
    exit 1
}

USERNAME=""
SWITCH_IP=""
INTERFACE=""

while getopts "u:H:i:w:h" opt; do
    case "$opt" in
        u) USERNAME="$OPTARG" ;;
        H) SWITCH_IP="$OPTARG" ;;
        i) INTERFACE="$OPTARG" ;;
        w) WAIT_SECS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$USERNAME"  ]] && { echo "Error: -u <username> is required"  >&2; usage; }
[[ -z "$SWITCH_IP" ]] && { echo "Error: -H <switch-ip> is required" >&2; usage; }
[[ -z "$INTERFACE" ]] && { echo "Error: -i <interface> is required" >&2; usage; }

if ! command -v expect >/dev/null 2>&1; then
    echo "Error: this script requires 'expect' to be installed." >&2
    exit 1
fi

if [[ -z "${JUNOS_PASSWORD:-}" ]]; then
    read -r -s -p "Password for ${USERNAME}@${SWITCH_IP}: " JUNOS_PASSWORD
    echo
fi
export JUNOS_PASSWORD

export JUNOS_USER="$USERNAME"
export JUNOS_HOST="$SWITCH_IP"
export JUNOS_IFACE="$INTERFACE"
export JUNOS_WAIT="$WAIT_SECS"
export JUNOS_SSH_TIMEOUT="$SSH_TIMEOUT"

expect -f - <<'EXPECT_SCRIPT'
    set timeout $env(JUNOS_SSH_TIMEOUT)
    log_user 1

    set user  $env(JUNOS_USER)
    set host  $env(JUNOS_HOST)
    set iface $env(JUNOS_IFACE)
    set wait  $env(JUNOS_WAIT)
    set pass  $env(JUNOS_PASSWORD)

    # Operational-mode and configuration-mode prompts both end in these chars
    set op_prompt  {[%>] $}
    set cfg_prompt {[%#] $}

    spawn ssh -o StrictHostKeyChecking=accept-new $user@$host

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

    send -- "configure\r"
    expect -re $cfg_prompt

    # --- bounce the interface ---
    send -- "set interfaces $iface disable\r"
    expect -re $cfg_prompt
    send -- "commit\r"
    expect -re $cfg_prompt

    puts "\n--- interface $iface disabled, waiting ${wait}s ---\n"
    sleep $wait

    send -- "delete interfaces $iface disable\r"
    expect -re $cfg_prompt
    send -- "commit\r"
    expect -re $cfg_prompt

    # --- bounce PoE on the same interface ---
    send -- "set poe interface $iface disable\r"
    expect -re $cfg_prompt
    send -- "commit\r"
    expect -re $cfg_prompt

    puts "\n--- PoE on $iface disabled, waiting ${wait}s ---\n"
    sleep $wait

    send -- "delete poe interface $iface disable\r"
    expect -re $cfg_prompt
    send -- "commit\r"
    expect -re $cfg_prompt

    send -- "exit\r"
    expect -re $op_prompt

    puts "\n--- current state of $iface ---\n"
    send -- "show interfaces $iface\r"
    expect -re $op_prompt

    send -- "exit\r"
    expect eof
EXPECT_SCRIPT

echo "Done."
