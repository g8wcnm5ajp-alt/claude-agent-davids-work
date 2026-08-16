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
#   ./junos-interface-poe-bounce.sh -u <username> -H <switch-ip> -i <interface> -a enable|disable [-m both|interface|poe] [-w <settle-seconds>] [-p <password>]
#
# Password resolution, in order of preference: -p flag, then JUNOS_PASSWORD
# env var, then an interactive prompt. Prefer the env var or the prompt over
# -p where possible -- a password passed on the command line is visible to
# anyone on the box running `ps`.

set -euo pipefail

SETTLE_SECS=9
SSH_TIMEOUT=20
MODE="both"
ACTION=""

usage() {
    cat <<USAGE
Usage: $0 -u <username> -H <switch-ip> -i <interface> -a enable|disable [-m both|interface|poe] [-w <settle-seconds>] [-p <password>]

  -u  Username to log into the switch with
  -H  Switch management IP or hostname
  -i  Interface name to act on (e.g. ge-0/0/5)
  -a  Desired state: enable or disable
  -m  What to apply it to: both (default), interface, or poe
  -w  Seconds to wait after a change before reporting final status (default: ${SETTLE_SECS})
  -p  Password (visible via \`ps\` to anyone on the box -- prefer \$JUNOS_PASSWORD or the prompt)
  -h  Show this help

If the interface (or PoE) is already in the requested state, that part is
skipped -- no command is sent for it.

Password resolution order: -p flag, then \$JUNOS_PASSWORD, then an interactive prompt.
USAGE
    exit 1
}

USERNAME=""
SWITCH_IP=""
INTERFACE=""
PASSWORD_ARG=""

while getopts "u:H:i:m:a:w:p:h" opt; do
    case "$opt" in
        u) USERNAME="$OPTARG" ;;
        H) SWITCH_IP="$OPTARG" ;;
        i) INTERFACE="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        a) ACTION="$OPTARG" ;;
        w) SETTLE_SECS="$OPTARG" ;;
        p) PASSWORD_ARG="$OPTARG" ;;
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

if [[ -n "$PASSWORD_ARG" ]]; then
    JUNOS_PASSWORD="$PASSWORD_ARG"
elif [[ -z "${JUNOS_PASSWORD:-}" ]]; then
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

    # "no" rather than "accept-new" for compatibility -- accept-new needs
    # OpenSSH 7.6+, and some management hosts still ship 7.4.
    spawn ssh -o StrictHostKeyChecking=no $user@$host

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

    # Disable the CLI's "---(more)---" pager for this session. Without this,
    # any output taller than the terminal (e.g. a full "show interfaces")
    # stalls waiting for a keypress, and our subsequent blind sends get
    # consumed as pager navigation keystrokes instead of reaching the CLI --
    # corrupting every command after it.
    send -- "set cli screen-length 0\r"
    expect -re $op_prompt

    set need_iface_change 0
    set need_poe_change 0

    # --- check current interface state ---
    if {$do_iface} {
        log_user 0
        send -- "show interfaces $iface\r"
        expect -re $op_prompt
        log_user 1
        # Real Junos reports a disabled interface as "Administratively down",
        # not "Disabled" -- only enabled interfaces actually say "Enabled".
        if {[regexp -nocase {Administratively down} $expect_out(buffer)]} {
            set iface_state "disabled"
        } elseif {[regexp -nocase {Physical interface: [^,]+, Enabled} $expect_out(buffer)]} {
            set iface_state "enabled"
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
        log_user 0
        send -- "show poe interface $iface\r"
        expect -re $op_prompt
        log_user 1
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

    # --- always report final status (physical link only, not the full dump) ---
    puts "\n--- current state of $iface ---\n"

    log_user 0
    send -- "show interfaces $iface\r"
    expect -re $op_prompt
    log_user 1
    if {[regexp -nocase {Physical link is (Up|Down)} $expect_out(buffer) -> link]} {
        puts "Physical link: $link"
    } else {
        puts "Physical link: unknown"
    }

    if {$do_poe} {
        log_user 0
        send -- "show poe interface $iface\r"
        expect -re $op_prompt
        log_user 1
        if {[regexp -nocase {operational status:\s*(ON|OFF)} $expect_out(buffer) -> oper]} {
            puts "PoE operational status: $oper"
        } else {
            puts "PoE operational status: unknown"
        }
    }

    send -- "exit\r"
    expect eof
EXPECT_SCRIPT

echo "Done."
