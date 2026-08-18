#!/usr/bin/env bash
#
# cisco-interface-poe-bounce.sh
#
# Cisco IOS/IOS-XE equivalent of junos-interface-poe-bounce.sh. Logs into a
# Cisco switch over SSH and drives an interface and/or its PoE to a desired
# administrative state (enable or disable). Checks the switch's real current
# state first -- if the interface (or PoE) is already in the requested
# state, that part is skipped rather than reissuing the command. Always
# reports the resulting state at the end.
#
# *** UNVALIDATED AGAINST REAL CISCO HARDWARE ***
# The command syntax and state-detection regexes below are best-effort,
# based on standard Cisco IOS/Catalyst conventions ("show interfaces",
# "show power inline", "shutdown"/"no shutdown", "power inline never/auto").
# Unlike the Junos scripts in this repo -- which only reached their current
# reliability after live-device testing turned up real surprises (a CLI
# pager corrupting commands, non-obvious status wording) -- this has not
# been run against a real Cisco device. Validate against real hardware (or
# at least the bundled mock, test/run-mock-cisco-test.sh) before trusting
# it on production switches. Likely soft spots: enable-mode password (may
# differ from the login password -- this assumes they're the same), exact
# "show interfaces"/"show power inline" wording (varies some by IOS
# version and platform), and PoE command support (not all Cisco switches
# have PoE-capable ports at all).
#
# Requires: expect
#
# Usage:
#   ./cisco-interface-poe-bounce.sh -u <username> -H <switch-ip> -i <interface> -a enable|disable [-m both|interface|poe] [-w <settle-seconds>] [-p <password>] [-c]
#
# Password resolution, in order of preference: -p flag, then CISCO_PASSWORD
# env var, then an interactive prompt. Prefer the env var or the prompt over
# -p where possible -- a password passed on the command line is visible to
# anyone on the box running `ps`. The same password is tried for enable
# mode if the switch prompts for one (some setups use a separate enable
# secret -- if so, this will fail at that step and say so).
#
# -c: after logging in and checking current state, print exactly which
# commands are about to be sent (or that nothing needs to change) and pause
# for a y/N confirmation before actually applying anything.

set -euo pipefail

VERSION="1.0.0"

SETTLE_SECS=9
SSH_TIMEOUT=20
MODE="both"
ACTION=""

usage() {
    cat <<USAGE
Usage: $0 -u <username> -H <switch-ip> -i <interface> -a enable|disable [-m both|interface|poe] [-w <settle-seconds>] [-p <password>] [-c]

  -u  Username to log into the switch with
  -H  Switch management IP or hostname
  -i  Interface name to act on (e.g. GigabitEthernet1/0/5, Gi1/0/5)
  -a  Desired state: enable or disable
  -m  What to apply it to: both (default), interface, or poe
  -w  Seconds to wait after a change before reporting final status (default: ${SETTLE_SECS})
  -p  Password (visible via \`ps\` to anyone on the box -- prefer \$CISCO_PASSWORD or the prompt)
  -c  Preview the exact commands to be run and pause for y/N confirmation before applying them
  -h  Show this help

If the interface (or PoE) is already in the requested state, that part is
skipped -- no command is sent for it.

Password resolution order: -p flag, then \$CISCO_PASSWORD, then an interactive prompt.
USAGE
    exit 1
}

USERNAME=""
SWITCH_IP=""
INTERFACE=""
PASSWORD_ARG=""
CONFIRM=0

while getopts "u:H:i:m:a:w:p:ch" opt; do
    case "$opt" in
        u) USERNAME="$OPTARG" ;;
        H) SWITCH_IP="$OPTARG" ;;
        i) INTERFACE="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        a) ACTION="$OPTARG" ;;
        w) SETTLE_SECS="$OPTARG" ;;
        p) PASSWORD_ARG="$OPTARG" ;;
        c) CONFIRM=1 ;;
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

echo "cisco-interface-poe-bounce.sh v${VERSION}"

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
export CISCO_IFACE="$INTERFACE"
export CISCO_MODE="$MODE"
export CISCO_ACTION="$ACTION"
export CISCO_SETTLE="$SETTLE_SECS"
export CISCO_SSH_TIMEOUT="$SSH_TIMEOUT"
export CISCO_CONFIRM="$CONFIRM"

expect -f - <<'EXPECT_SCRIPT'
    set timeout $env(CISCO_SSH_TIMEOUT)
    log_user 1

    set user    $env(CISCO_USER)
    set host    $env(CISCO_HOST)
    set iface   $env(CISCO_IFACE)
    set mode    $env(CISCO_MODE)
    set action  $env(CISCO_ACTION)
    set settle  $env(CISCO_SETTLE)
    set pass    $env(CISCO_PASSWORD)
    set confirm $env(CISCO_CONFIRM)

    set do_iface [expr {$mode eq "both" || $mode eq "interface"}]
    set do_poe   [expr {$mode eq "both" || $mode eq "poe"}]
    set desired  [expr {$action eq "enable" ? "enabled" : "disabled"}]

    # User exec ">", privileged exec "#", any config level "(config...)#"
    set user_prompt {[^)]>\s*$}
    set exec_prompt {[^)]#\s*$}
    set cfg_prompt  {\(config[^)]*\)#\s*$}

    # "no" rather than "accept-new" for compatibility -- accept-new needs
    # OpenSSH 7.6+, and some management hosts still ship 7.4.
    # UserKnownHostsFile=/dev/null since fleet devices get reimaged/
    # reassigned IPs and StrictHostKeyChecking=no alone still refuses a
    # *changed* host key.
    spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $user@$host

    # Single loop, tolerant of however many password prompts appear (the
    # initial login, and possibly a separate enable-mode password) and of
    # landing directly at privileged exec with no "enable" step needed at
    # all. Breaking out only once $exec_prompt actually matches avoids a
    # subtler bug an earlier version of this script had: a sequence of
    # separate expect blocks that each re-checked for the same prompt
    # against an already-drained buffer, hanging until timeout whenever no
    # "enable" was needed in the first place.
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

    # Disable the CLI pager for this session -- same rationale as Junos's
    # "set cli screen-length 0": without it, tall output stalls waiting for
    # a keypress and subsequent blind sends get eaten as pager navigation.
    send -- "terminal length 0\r"
    expect -re $exec_prompt

    set need_iface_change 0
    set need_poe_change 0

    # --- check current interface state ---
    if {$do_iface} {
        log_user 0
        send -- "show interfaces $iface\r"
        expect -re $exec_prompt
        log_user 1
        if {[regexp -nocase {administratively down} $expect_out(buffer)]} {
            set iface_state "disabled"
        } elseif {[regexp -nocase {is (up|down), line protocol} $expect_out(buffer)]} {
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
        send -- "show power inline $iface\r"
        expect -re $exec_prompt
        log_user 1
        if {[regexp -nocase {\y(auto|never|static)\y} $expect_out(buffer) -> m]} {
            set poe_state [expr {[string tolower $m] eq "never" ? "disabled" : "enabled"}]
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

    # --- preview + confirm, if -c was given ---
    if {$confirm} {
        set n 1
        puts "\nFull command sequence for $host:"
        puts "  $n. ssh $user@$host                          (done -- logged in)"
        incr n
        puts "  $n. terminal length 0                        (done)"
        incr n
        if {$do_iface} {
            puts "  $n. show interfaces $iface                (done -- current state: $iface_state)"
            incr n
        }
        if {$do_poe} {
            puts "  $n. show power inline $iface              (done -- current state: $poe_state)"
            incr n
        }
        if {!$need_iface_change && !$need_poe_change} {
            puts "  $n. (nothing to change -- $iface already $desired)"
            incr n
            if {$do_iface} {
                puts "     would have run: interface $iface / [expr {$desired eq {disabled}} ? {shutdown} : {no shutdown}]"
            }
            if {$do_poe} {
                puts "     would have run: interface $iface / power inline [expr {$desired eq {disabled}} ? {never} : {auto}]"
            }
            if {$do_iface || $do_poe} {
                puts "                      write memory"
            }
        } else {
            puts "  $n. configure terminal"
            incr n
            puts "  $n. interface $iface"
            incr n
            if {$need_iface_change} {
                if {$desired eq "disabled"} {
                    puts "  $n. shutdown"
                } else {
                    puts "  $n. no shutdown"
                }
                incr n
            } elseif {$do_iface} {
                puts "     (interface already $desired -- would have run: [expr {$desired eq {disabled}} ? {shutdown} : {no shutdown}])"
            }
            if {$need_poe_change} {
                if {$desired eq "disabled"} {
                    puts "  $n. power inline never"
                } else {
                    puts "  $n. power inline auto"
                }
                incr n
            } elseif {$do_poe} {
                puts "     (PoE already $desired -- would have run: power inline [expr {$desired eq {disabled}} ? {never} : {auto}])"
            }
            puts "  $n. end                                       (leave configuration mode)"
            incr n
            puts "  $n. write memory                             (save to startup-config)"
            incr n
        }
        puts "  $n. show interfaces $iface                   (final report)"
        incr n
        if {$do_poe} {
            puts "  $n. show power inline $iface                 (final report)"
            incr n
        }
        puts "  $n. exit                                     (log out)"
        # expect's own script came in via a heredoc on stdin, so plain
        # stdin is already exhausted at this point -- read the answer from
        # the controlling terminal directly instead.
        set answer ""
        if {[catch {set tty [open "/dev/tty" "r+"]} err]} {
            puts "Cannot prompt for confirmation (no controlling terminal: $err) -- aborting, no changes made."
            set need_iface_change 0
            set need_poe_change 0
        } else {
            puts -nonewline $tty "\nContinue? \[y/N\]: "
            flush $tty
            gets $tty answer
            close $tty
            if {![regexp -nocase {^y} $answer]} {
                puts "Aborted by user -- no changes made."
                set need_iface_change 0
                set need_poe_change 0
            }
        }
    }

    # --- apply whatever changes are actually needed, then one save ---
    if {$need_iface_change || $need_poe_change} {
        send -- "configure terminal\r"
        expect -re $cfg_prompt

        send -- "interface $iface\r"
        expect -re $cfg_prompt

        if {$need_iface_change} {
            if {$desired eq "disabled"} {
                send -- "shutdown\r"
            } else {
                send -- "no shutdown\r"
            }
            expect -re $cfg_prompt
        }

        if {$need_poe_change} {
            if {$desired eq "disabled"} {
                send -- "power inline never\r"
            } else {
                send -- "power inline auto\r"
            }
            expect -re $cfg_prompt
        }

        send -- "end\r"
        expect -re $exec_prompt

        send -- "write memory\r"
        expect -re $exec_prompt

        puts "\nWaiting ${settle}s for the change to take effect...\n"
        sleep $settle
    }

    # --- always report final status (link state only, not the full dump) ---
    puts "\n--- current state of $iface ---\n"

    log_user 0
    send -- "show interfaces $iface\r"
    expect -re $exec_prompt
    log_user 1
    if {[regexp -nocase {line protocol is (up|down)} $expect_out(buffer) -> link]} {
        puts "Line protocol: [string totitle $link]"
    } else {
        puts "Line protocol: unknown"
    }

    if {$do_poe} {
        log_user 0
        send -- "show power inline $iface\r"
        expect -re $exec_prompt
        log_user 1
        if {[regexp -nocase {\y(on|off|faulty|deny)\y} $expect_out(buffer) -> oper]} {
            puts "PoE operational status: [string toupper $oper]"
        } else {
            puts "PoE operational status: unknown"
        }
    }

    send -- "exit\r"
    expect eof
EXPECT_SCRIPT

echo "Done."
