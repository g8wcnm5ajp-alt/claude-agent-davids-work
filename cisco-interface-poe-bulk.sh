#!/usr/bin/env bash
#
# cisco-interface-poe-bulk.sh
#
# Cisco IOS/IOS-XE equivalent of junos-interface-poe-bulk.sh. Requires
# expect -- if that's not available and can't be installed (e.g. a locked-
# down EM/appliance host), use cisco-interface-poe-bulk.py instead, which
# is intended to be functionally identical but uses only python3 stdlib.
#
# *** UNVALIDATED AGAINST REAL CISCO HARDWARE -- see cisco-interface-poe-
# bounce.sh's header for the specific assumptions (enable-mode password,
# show-command wording, PoE command support). Validate before production use.
#
# Reads a CSV file where each row is:
#
#   appliance_ip,switch_ip,switch_port
#
# Rows are grouped by switch IP first: every port listed for the same
# switch is handled in a single login and, if anything on that switch
# actually needs to change, a single "write memory" covering all of them --
# not one connection and save per port. A switch where every listed port is
# already in the desired state gets no config/save at all. For each switch
# group, SSHes to the appliance first, then hops from there to the Cisco
# switch, applying the same idempotent enable/disable logic (interface
# and/or PoE, skip-if-already-in-desired-state per port) as the
# single-target script. Switch username, password, mode, action, and settle
# delay are the same for every row and are given on the command line --
# only the appliance IP, switch IP, and port vary per row.
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
#   ./cisco-interface-poe-bulk.sh -s <switch-username> -f <csv-file> -a enable|disable [-m both|interface|poe] [-w <settle-seconds>] [-p <password>] [-c]
#
# -c: for each switch group, after logging in and checking current state
# for every port on it, print exactly which commands are about to be sent
# (or that nothing needs to change) and pause for one y/N confirmation
# covering the whole switch before applying them. A "no" skips that
# switch's changes but continues the batch -- it's tracked separately from
# real failures in the summary (applied to every port on that switch).
#
# CSV format: one row per line, no header, e.g.:
#   192.168.1.10,192.168.22.223,GigabitEthernet1/0/11
#   192.168.1.10,192.168.22.223,GigabitEthernet1/0/12
#   192.168.1.11,192.168.22.224,Gi1/0/5
# Blank lines and lines starting with # are skipped. If the same switch IP
# appears with a different appliance IP on a later row, the first
# appliance seen for that switch wins and a warning is printed.
#
# One switch group failing (bad login, unreachable host, etc.) does not
# stop the rest of the batch -- failures are collected and reported in a
# summary at the end, and the script exits non-zero if any group failed.
#
# Password resolution order: -p flag, then CISCO_PASSWORD env var, then an
# interactive prompt. Prefer the env var or the prompt over -p where
# possible -- a password passed on the command line is visible to anyone on
# the box running `ps`. This password is only ever needed for the switch
# login (and enable mode); the appliance hop is passwordless (key-based).

set -uo pipefail   # no -e: one row failing must not abort the batch

VERSION="1.0.0"

SETTLE_SECS=9
SSH_TIMEOUT=20
MODE="both"
ACTION=""
CSV_FILE=""

usage() {
    cat <<USAGE
Usage: $0 -s <switch-username> -f <csv-file> -a enable|disable [-m both|interface|poe] [-w <settle-seconds>] [-p <password>] [-c]

  -s  Username to log into the switch with (via the appliance)
  -f  CSV file: one row per line, "appliance_ip,switch_ip,switch_port"
  -a  Desired state: enable or disable
  -m  What to apply it to: both (default), interface, or poe
  -w  Seconds to wait after a change before reporting final status (default: ${SETTLE_SECS})
  -p  Password (visible via \`ps\` to anyone on the box -- prefer \$CISCO_PASSWORD or the prompt)
  -c  Preview the exact commands to be run per switch and pause for y/N confirmation before applying them
  -h  Show this help

The appliance hop is always root@<appliance-ip> via pre-shared keys (no
username or password needed for it). -s / the password are only for the
switch login (and enable mode, assumed to use the same password). Blank
lines and lines starting with # in the CSV are skipped. If the interface
(or PoE) is already in the requested state, that part is skipped for that
port -- no command is sent for it.

Password resolution order: -p flag, then \$CISCO_PASSWORD, then an interactive prompt.
USAGE
    exit 1
}

SWITCH_USERNAME=""
PASSWORD_ARG=""
CONFIRM=0

while getopts "s:f:m:a:w:p:ch" opt; do
    case "$opt" in
        s) SWITCH_USERNAME="$OPTARG" ;;
        f) CSV_FILE="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        a) ACTION="$OPTARG" ;;
        w) SETTLE_SECS="$OPTARG" ;;
        p) PASSWORD_ARG="$OPTARG" ;;
        c) CONFIRM=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$SWITCH_USERNAME" ]] && { echo "Error: -s <switch-username> is required" >&2; usage; }
[[ -z "$CSV_FILE" ]] && { echo "Error: -f <csv-file> is required" >&2; usage; }
[[ -f "$CSV_FILE" ]] || { echo "Error: file not found: $CSV_FILE" >&2; exit 1; }
[[ -z "$ACTION"   ]] && { echo "Error: -a <enable|disable> is required" >&2; usage; }

case "$MODE" in
    both|interface|poe) ;;
    *) echo "Error: -m must be one of: both, interface, poe" >&2; usage ;;
esac

case "$ACTION" in
    enable|disable) ;;
    *) echo "Error: -a must be one of: enable, disable" >&2; usage ;;
esac

echo "cisco-interface-poe-bulk.sh v${VERSION}"

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
export CISCO_MODE="$MODE"
export CISCO_ACTION="$ACTION"
export CISCO_SETTLE="$SETTLE_SECS"
export CISCO_SSH_TIMEOUT="$SSH_TIMEOUT"
export CISCO_CONFIRM="$CONFIRM"

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# Handles every port on one switch in a single login and, at most, one
# save. A single group-level outcome (ok/declined/failed exit code) is
# applied by the caller to every port in the group in the batch summary --
# see junos-interface-poe-bulk.sh's run_switch_group for the same rationale.
run_switch_group() {
    local appliance="$1" switch="$2" ports_csv="$3"
    export CISCO_APPLIANCE="$appliance"
    export CISCO_HOST="$switch"
    export CISCO_PORTS="$ports_csv"

    expect -f - <<'EXPECT_SCRIPT'
        set timeout $env(CISCO_SSH_TIMEOUT)
        log_user 1

        set switch_user $env(CISCO_SWITCH_USER)
        set appliance $env(CISCO_APPLIANCE)
        set host      $env(CISCO_HOST)
        set ports     [split $env(CISCO_PORTS) ","]
        set mode      $env(CISCO_MODE)
        set action    $env(CISCO_ACTION)
        set settle    $env(CISCO_SETTLE)
        set pass      $env(CISCO_PASSWORD)
        set confirm   $env(CISCO_CONFIRM)

        set do_iface [expr {$mode eq "both" || $mode eq "interface"}]
        set do_poe   [expr {$mode eq "both" || $mode eq "poe"}]
        set desired  [expr {$action eq "enable" ? "enabled" : "disabled"}]

        set user_prompt {[^)]>\s*$}
        set exec_prompt {[^)]#\s*$}
        set cfg_prompt  {\(config[^)]*\)#\s*$}

        puts "\n=== $appliance -> $host \[[join $ports {, }]\] ===\n"

        set ssh_opts {-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null}
        # Appliance hop is always root, via the pre-shared key.
        spawn ssh -tt {*}$ssh_opts root@$appliance ssh -tt {*}$ssh_opts $switch_user@$host

        # Tolerant of 0, 1, or 2 password prompts on the way in -- same
        # rationale as the Junos bulk script's login loop.
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

        send -- "terminal length 0\r"
        expect -re $exec_prompt

        # --- check current state of every port up front ---
        array set need_iface_map {}
        array set need_poe_map {}
        array set iface_state_map {}
        array set poe_state_map {}
        set any_change 0

        foreach port $ports {
            set need_iface_map($port) 0
            set need_poe_map($port) 0

            if {$do_iface} {
                log_user 0
                send -- "show interfaces $port\r"
                expect -re $exec_prompt
                log_user 1
                if {[regexp -nocase {administratively down} $expect_out(buffer)]} {
                    set st "disabled"
                } elseif {[regexp -nocase {is (up|down), line protocol} $expect_out(buffer)]} {
                    set st "enabled"
                } else {
                    set st "unknown"
                }
                set iface_state_map($port) $st
                puts "\n\[$port\] Current interface state: $st\n"
                if {$st eq $desired} {
                    puts "\[$port\] Interface is already $desired -- skipping interface action.\n"
                } else {
                    set need_iface_map($port) 1
                    set any_change 1
                }
            }

            if {$do_poe} {
                log_user 0
                send -- "show power inline $port\r"
                expect -re $exec_prompt
                log_user 1
                if {[regexp -nocase {\y(auto|never|static)\y} $expect_out(buffer) -> m]} {
                    set st [expr {[string tolower $m] eq "never" ? "disabled" : "enabled"}]
                } else {
                    set st "unknown"
                }
                set poe_state_map($port) $st
                puts "\n\[$port\] Current PoE state: $st\n"
                if {$st eq $desired} {
                    puts "\[$port\] PoE is already $desired -- skipping PoE action.\n"
                } else {
                    set need_poe_map($port) 1
                    set any_change 1
                }
            }
        }

        # --- preview + confirm, if -c was given -- one combined plan for
        # every port on this switch, not one prompt per port ---
        set declined_by_user 0
        if {$confirm} {
            set n 1
            puts "\nFull command sequence for $appliance -> $host:"
            puts "  $n. ssh root@$appliance -> ssh $switch_user@$host   (done -- logged in, $pw_sent password(s) sent)"
            incr n
            puts "  $n. terminal length 0                              (done)"
            incr n
            foreach port $ports {
                if {$do_iface} {
                    puts "  $n. show interfaces $port                      (done -- current state: $iface_state_map($port))"
                    incr n
                }
                if {$do_poe} {
                    puts "  $n. show power inline $port                    (done -- current state: $poe_state_map($port))"
                    incr n
                }
            }
            if {!$any_change} {
                puts "  $n. (nothing to change -- all ports already $desired)"
                incr n
                foreach port $ports {
                    if {$do_iface} {
                        puts "     would have run: interface $port / [expr {$desired eq {disabled}} ? {shutdown} : {no shutdown}]"
                    }
                    if {$do_poe} {
                        puts "     would have run: interface $port / power inline [expr {$desired eq {disabled}} ? {never} : {auto}]"
                    }
                }
                if {$do_iface || $do_poe} {
                    puts "                      write memory"
                }
            } else {
                puts "  $n. configure terminal"
                incr n
                foreach port $ports {
                    if {$need_iface_map($port) || $need_poe_map($port)} {
                        puts "  $n. interface $port"
                        incr n
                    }
                    if {$need_iface_map($port)} {
                        puts "  $n. [expr {$desired eq {disabled}} ? {shutdown} : {no shutdown}]"
                        incr n
                    } elseif {$do_iface} {
                        puts "     (interface $port already $desired -- would have run: [expr {$desired eq {disabled}} ? {shutdown} : {no shutdown}])"
                    }
                    if {$need_poe_map($port)} {
                        puts "  $n. power inline [expr {$desired eq {disabled}} ? {never} : {auto}]"
                        incr n
                    } elseif {$do_poe} {
                        puts "     (PoE $port already $desired -- would have run: power inline [expr {$desired eq {disabled}} ? {never} : {auto}])"
                    }
                }
                puts "  $n. end                                             (leave configuration mode)"
                incr n
                puts "  $n. write memory                                   (one save for all ports on this switch)"
                incr n
            }
            foreach port $ports {
                puts "  $n. show interfaces $port                        (final report)"
                incr n
                if {$do_poe} {
                    puts "  $n. show power inline $port                       (final report)"
                    incr n
                }
            }
            puts "  $n. exit                                           (log out, unwinds both hops)"
            set answer ""
            if {[catch {set tty [open "/dev/tty" "r+"]} err]} {
                puts "Cannot prompt for confirmation (no controlling terminal: $err) -- skipping this switch, no changes made."
                set any_change 0
                set declined_by_user 1
            } else {
                puts -nonewline $tty "\nContinue with $host \[[join $ports {, }]\]? \[y/N\]: "
                flush $tty
                gets $tty answer
                close $tty
                if {![regexp -nocase {^y} $answer]} {
                    puts "Skipped by user -- no changes made on $host."
                    set any_change 0
                    set declined_by_user 1
                }
            }
        }

        # --- apply every port's pending change, then exactly one save for
        # the whole switch ---
        if {$any_change} {
            send -- "configure terminal\r"
            expect -re $cfg_prompt

            foreach port $ports {
                if {$need_iface_map($port) || $need_poe_map($port)} {
                    send -- "interface $port\r"
                    expect -re $cfg_prompt
                }
                if {$need_iface_map($port)} {
                    if {$desired eq "disabled"} {
                        send -- "shutdown\r"
                    } else {
                        send -- "no shutdown\r"
                    }
                    expect -re $cfg_prompt
                }
                if {$need_poe_map($port)} {
                    if {$desired eq "disabled"} {
                        send -- "power inline never\r"
                    } else {
                        send -- "power inline auto\r"
                    }
                    expect -re $cfg_prompt
                }
            }

            send -- "end\r"
            expect -re $exec_prompt

            send -- "write memory\r"
            expect -re $exec_prompt

            puts "\nWaiting ${settle}s for the change to take effect...\n"
            sleep $settle
        }

        # --- always report final status for every port ---
        foreach port $ports {
            puts "\n--- current state of $port on $host ---\n"

            log_user 0
            send -- "show interfaces $port\r"
            expect -re $exec_prompt
            log_user 1
            if {[regexp -nocase {line protocol is (up|down)} $expect_out(buffer) -> link]} {
                puts "Line protocol: [string totitle $link]"
            } else {
                puts "Line protocol: unknown"
            }

            if {$do_poe} {
                log_user 0
                send -- "show power inline $port\r"
                expect -re $exec_prompt
                log_user 1
                if {[regexp -nocase {\y(on|off|faulty|deny)\y} $expect_out(buffer) -> oper]} {
                    puts "PoE operational status: [string toupper $oper]"
                } else {
                    puts "PoE operational status: unknown"
                }
            }
        }

        send -- "exit\r"
        expect eof

        if {$declined_by_user} {
            exit 2
        }
EXPECT_SCRIPT
}

# Group rows by switch IP, preserving first-seen order, so every port on
# the same switch is handled in one login and (at most) one save instead
# of reconnecting and saving per port. Parallel arrays keyed by the same
# index since bash has no native nested data structures.
GROUP_SWITCHES=()
GROUP_APPLIANCES=()
GROUP_PORTS=()

find_group_index() {
    local target="$1" i
    for i in "${!GROUP_SWITCHES[@]}"; do
        if [[ "${GROUP_SWITCHES[$i]}" == "$target" ]]; then
            echo "$i"
            return 0
        fi
    done
    echo "-1"
}

TOTAL=0
FAILED=0
FAILED_ROWS=()

while IFS=',' read -r raw_appliance raw_switch raw_port || [[ -n "${raw_appliance:-}" ]]; do
    appliance="$(trim "${raw_appliance:-}")"
    switch="$(trim "${raw_switch:-}")"
    port="$(trim "${raw_port:-}")"

    [[ -z "$appliance" ]] && continue
    [[ "$appliance" == \#* ]] && continue

    if [[ -z "$switch" || -z "$port" ]]; then
        echo "Error: malformed row (need appliance_ip,switch_ip,switch_port): $raw_appliance,$raw_switch,$raw_port" >&2
        FAILED=$((FAILED + 1))
        FAILED_ROWS+=("$raw_appliance,$raw_switch,$raw_port (malformed)")
        continue
    fi

    TOTAL=$((TOTAL + 1))
    idx="$(find_group_index "$switch")"
    if [[ "$idx" == "-1" ]]; then
        GROUP_SWITCHES+=("$switch")
        GROUP_APPLIANCES+=("$appliance")
        GROUP_PORTS+=("$port")
    else
        if [[ "${GROUP_APPLIANCES[$idx]}" != "$appliance" ]]; then
            echo "Warning: switch $switch listed with different appliances (${GROUP_APPLIANCES[$idx]} vs $appliance) -- using ${GROUP_APPLIANCES[$idx]}" >&2
        fi
        GROUP_PORTS[$idx]="${GROUP_PORTS[$idx]},${port}"
    fi
done < "$CSV_FILE"

OK=0
DECLINED=0
DECLINED_ROWS=()

for i in "${!GROUP_SWITCHES[@]}"; do
    switch="${GROUP_SWITCHES[$i]}"
    appliance="${GROUP_APPLIANCES[$i]}"
    ports_csv="${GROUP_PORTS[$i]}"
    port_count=$(($(grep -o ',' <<<"$ports_csv" | wc -l) + 1))

    group_status=0
    run_switch_group "$appliance" "$switch" "$ports_csv" || group_status=$?
    if [[ $group_status -eq 0 ]]; then
        OK=$((OK + port_count))
    elif [[ $group_status -eq 2 ]]; then
        DECLINED=$((DECLINED + port_count))
        DECLINED_ROWS+=("$appliance,$switch,[${ports_csv}]")
    else
        FAILED=$((FAILED + port_count))
        FAILED_ROWS+=("$appliance,$switch,[${ports_csv}]")
    fi
done

echo
echo "=== summary: $OK/$TOTAL rows succeeded ($DECLINED declined by user) ==="
if [[ $DECLINED -gt 0 ]]; then
    echo "Declined rows:"
    for row in "${DECLINED_ROWS[@]}"; do
        echo "  - $row"
    done
fi
if [[ $FAILED -gt 0 ]]; then
    echo "Failed rows:"
    for row in "${FAILED_ROWS[@]}"; do
        echo "  - $row"
    done
    exit 1
fi

exit 0
