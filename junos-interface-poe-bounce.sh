#!/usr/bin/env bash
#
# junos-interface-poe-bounce.sh
#
# Logs into a Juniper switch over SSH and drives an interface and/or its PoE
# to a desired administrative state (enable or disable). Before making any
# change, it checks the current state on the switch -- if the interface (or
# PoE) is already in the requested state, that part is skipped rather than
# reissuing the command. Always reports the resulting state at the end.
#
# Requires: expect
#
# Usage:
#   ./junos-interface-poe-bounce.sh -u <username> -H <switch-ip> -i <interface> -a enable|disable [-m both|interface|poe] [-w <settle-seconds>]
#
# Password is read from the JUNOS_PASSWORD env var if set, otherwise prompted
# for interactively (never pass it as a bare CLI argument -- it would be
# visible to anyone running `ps`).

set -euo pipefail

SETTLE_SECS=3
SSH_TIMEOUT=20
MODE="both"
ACTION=""

usage() {
    cat <<USAGE
Usage: $0 -u <username> -H <switch-ip> -i <interface> -a enable|disable [-m both|interface|poe] [-w <settle-seconds>]

  -u  Username to log into the switch with
  -H  Switch management IP or hostname
  -i  Interface name to act on (e.g. ge-0/0/5)
  -a  Desired state: enable or disable
  -m  What to apply it to: both (default), interface, or poe
  -w  Seconds to wait after a change before reporting final status (default: ${SETTLE_SECS})
  -h  Show this help

If the interface (or PoE) is already in the requested state, that part is
skipped -- no command is sent for it.

Password is taken from \$JUNOS_PASSWORD if set, otherwise you'll be prompted.
USAGE
    exit 1
}

USERNAME=""
SWITCH_IP=""
INTERFACE=""

while getopts "u:H:i:m:a:w:h" opt; do
    case "$opt" in
        u) USERNAME="$OPTARG" ;;
        H) SWITCH_IP="$OPTARG" ;;
        i) INTERFACE="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        a) ACTION="$OPTARG" ;;
        w) SETTLE_SECS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$USERNAME"  ]] && { echo "Error: -u <username> is required"  >&2; usage; }
[[ -z "$SWITCH_IP" ]] && { echo "Error: -H <switch-ip> is required" >&2; usage; }
[[ -z "$INTERFACE" ]] && { echo "Error: -i <interface> is required" >&2; usage; }
[[ -z "$ACTION"    ]] && { echo "Error: -a <enable|disable> is required" >&2; usage; }

case "$MODE" in
    both|interface|poe) ;;
    *) echo "Error: -m must be one of: both, interface, poe" >&2; usage ;;
esac

case "$ACTION" in
    enable|disable) ;;
    *) echo "Error: -a must be one of: enable, disable" >&2; usage ;;
esac

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
export JUNOS_MODE="$MODE"
export JUNOS_ACTION="$ACTION"
export JUNOS_SETTLE="$SETTLE_SECS"
export JUNOS_SSH_TIMEOUT="$SSH_TIMEOUT"

expect -f - <<'EXPECT_SCRIPT'
    set timeout $env(JUNOS_SSH_TIMEOUT)
    log_user 1

    set user   $env(JUNOS_USER)
    set host   $env(JUNOS_HOST)
    set iface  $env(JUNOS_IFACE)
    set mode   $env(JUNOS_MODE)
    set action $env(JUNOS_ACTION)
    set settle $env(JUNOS_SETTLE)
    set pass   $env(JUNOS_PASSWORD)

    set do_iface [expr {$mode eq "both" || $mode eq "interface"}]
    set do_poe   [expr {$mode eq "both" || $mode eq "poe"}]
    set desired  [expr {$action eq "enable" ? "enabled" : "disabled"}]

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

    set need_iface_change 0
    set need_poe_change 0

    # --- check current interface state ---
    if {$do_iface} {
        send -- "show interfaces $iface\r"
        expect -re $op_prompt
        if {[regexp -nocase {Physical interface: [^,]+, (Enabled|Disabled)} $expect_out(buffer) -> m]} {
            set iface_state [string tolower $m]
        } else {
            set iface_state "unknown"
        }
        puts "\nCurrent interface state: $iface_state\n"
        if {$iface_state eq $desired} {
            puts "Interface $iface is already $desired -- skipping interface action.\n"
        } else {
            set need_iface_change 1
        }
    }

    # --- check current PoE state ---
    if {$do_poe} {
        send -- "show poe interface $iface\r"
        expect -re $op_prompt
        if {[regexp -nocase {administrative status:\s*(Enabled|Disabled)} $expect_out(buffer) -> m]} {
            set poe_state [string tolower $m]
        } else {
            set poe_state "unknown"
        }
        puts "\nCurrent PoE state: $poe_state\n"
        if {$poe_state eq $desired} {
            puts "PoE on $iface is already $desired -- skipping PoE action.\n"
        } else {
            set need_poe_change 1
        }
    }

    # --- apply whatever changes are actually needed, in one commit ---
    if {$need_iface_change || $need_poe_change} {
        send -- "configure\r"
        expect -re $cfg_prompt

        if {$need_iface_change} {
            if {$desired eq "disabled"} {
                send -- "set interfaces $iface disable\r"
            } else {
                send -- "delete interfaces $iface disable\r"
            }
            expect -re $cfg_prompt
        }

        if {$need_poe_change} {
            if {$desired eq "disabled"} {
                send -- "set poe interface $iface disable\r"
            } else {
                send -- "delete poe interface $iface disable\r"
            }
            expect -re $cfg_prompt
        }

        send -- "commit\r"
        expect -re $cfg_prompt

        send -- "exit\r"
        expect -re $op_prompt

        puts "\nWaiting ${settle}s for the change to take effect...\n"
        sleep $settle
    }

    # --- always report final status ---
    puts "\n--- current state of $iface ---\n"
    send -- "show interfaces $iface\r"
    expect -re $op_prompt

    if {$do_poe} {
        send -- "show poe interface $iface\r"
        expect -re $op_prompt
    }

    send -- "exit\r"
    expect eof
EXPECT_SCRIPT

echo "Done."
