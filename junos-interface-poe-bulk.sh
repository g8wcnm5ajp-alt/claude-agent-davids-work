#!/usr/bin/env bash
#
# junos-interface-poe-bulk.sh
#
# Bulk / CSV-driven version of junos-interface-poe-bounce.sh. Reads a CSV
# file where each row is:
#
#   appliance_ip,switch_ip,switch_port
#
# and for every row, SSHes to the appliance first, then hops from there to
# the Juniper switch, applying the same idempotent enable/disable logic
# (interface and/or PoE, skip-if-already-in-desired-state) as the
# single-target script. Switch username, password, mode, action, and settle
# delay are the same for every row and are given on the command line --
# only the appliance IP, switch IP, and port vary per row.
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
#   ./junos-interface-poe-bulk.sh -s <switch-username> -f <csv-file> -a enable|disable [-m both|interface|poe] [-w <settle-seconds>] [-p <password>]
#
# CSV format: one row per line, no header, e.g.:
#   192.168.1.10,192.168.22.223,ge-0/0/11
#   192.168.1.11,192.168.22.224,ge-0/0/5
# Blank lines and lines starting with # are skipped.
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

SETTLE_SECS=9
SSH_TIMEOUT=20
MODE="both"
ACTION=""
CSV_FILE=""

usage() {
    cat <<USAGE
Usage: $0 -s <switch-username> -f <csv-file> -a enable|disable [-m both|interface|poe] [-w <settle-seconds>] [-p <password>]

  -s  Username to log into the switch with (via the appliance)
  -f  CSV file: one row per line, "appliance_ip,switch_ip,switch_port"
  -a  Desired state: enable or disable
  -m  What to apply it to: both (default), interface, or poe
  -w  Seconds to wait after a change before reporting final status (default: ${SETTLE_SECS})
  -p  Password (visible via \`ps\` to anyone on the box -- prefer \$JUNOS_PASSWORD or the prompt)
  -h  Show this help

The appliance hop is always root@<appliance-ip> via pre-shared keys (no
username or password needed for it). -s / the password are only for the
switch login. Blank lines and lines starting with # in the CSV are
skipped. If the interface (or PoE) is already in the requested state,
that part is skipped for that row -- no command is sent for it.

Password resolution order: -p flag, then \$JUNOS_PASSWORD, then an interactive prompt.
USAGE
    exit 1
}

SWITCH_USERNAME=""
PASSWORD_ARG=""

while getopts "s:f:m:a:w:p:h" opt; do
    case "$opt" in
        s) SWITCH_USERNAME="$OPTARG" ;;
        f) CSV_FILE="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        a) ACTION="$OPTARG" ;;
        w) SETTLE_SECS="$OPTARG" ;;
        p) PASSWORD_ARG="$OPTARG" ;;
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
export JUNOS_MODE="$MODE"
export JUNOS_ACTION="$ACTION"
export JUNOS_SETTLE="$SETTLE_SECS"
export JUNOS_SSH_TIMEOUT="$SSH_TIMEOUT"

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

run_row() {
    local appliance="$1" switch="$2" port="$3"
    export JUNOS_APPLIANCE="$appliance"
    export JUNOS_HOST="$switch"
    export JUNOS_IFACE="$port"

    expect -f - <<'EXPECT_SCRIPT'
        set timeout $env(JUNOS_SSH_TIMEOUT)
        log_user 1

        set switch_user $env(JUNOS_SWITCH_USER)
        set appliance $env(JUNOS_APPLIANCE)
        set host      $env(JUNOS_HOST)
        set iface     $env(JUNOS_IFACE)
        set mode      $env(JUNOS_MODE)
        set action    $env(JUNOS_ACTION)
        set settle    $env(JUNOS_SETTLE)
        set pass      $env(JUNOS_PASSWORD)

        set do_iface [expr {$mode eq "both" || $mode eq "interface"}]
        set do_poe   [expr {$mode eq "both" || $mode eq "poe"}]
        set desired  [expr {$action eq "enable" ? "enabled" : "disabled"}]

        # Operational-mode and configuration-mode prompts both end in these chars
        set op_prompt  {[%>] $}
        set cfg_prompt {[%#] $}

        puts "\n=== $appliance -> $host $iface ===\n"

        # Hop 1: ssh to the appliance, whose remote command is itself an ssh
        # to the switch. This avoids ever needing to match the appliance's
        # own (unknown) shell prompt -- the switch's Junos CLI just appears
        # directly once both hops are up. "no" rather than "accept-new" for
        # StrictHostKeyChecking for compatibility with older OpenSSH clients.
        # UserKnownHostsFile=/dev/null on top of that: appliances and
        # switches in a fleet get reimaged/reassigned IPs, and
        # StrictHostKeyChecking=no alone still refuses a *changed* key (it
        # only auto-accepts *unknown* ones) -- pointing at an empty file
        # means every run re-trusts on first use instead of ever hitting a
        # stale pinned key.
        set ssh_opts {-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null}
        # Appliance hop is always root, via the pre-shared key -- no
        # password expected for it, but the login loop below tolerates one
        # anyway in case a given appliance isn't key-trusted.
        spawn ssh -tt {*}$ssh_opts root@$appliance ssh -tt {*}$ssh_opts $switch_user@$host

        # Tolerant of 0, 1, or 2 password prompts -- some appliances have
        # pre-existing key trust to the switch and skip straight from the
        # appliance login to the Junos operational prompt with no second
        # password prompt at all, so this can't assume exactly two.
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

        # Disable the CLI's "---(more)---" pager for this session -- without
        # this, any output taller than the terminal stalls waiting for a
        # keypress, and subsequent blind sends get consumed as pager
        # navigation keystrokes instead of reaching the CLI.
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
            # Real Junos reports a disabled interface as "Administratively
            # down", not "Disabled" -- only enabled interfaces say "Enabled".
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
        puts "\n--- current state of $iface on $host ---\n"

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
}

TOTAL=0
OK=0
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
    if run_row "$appliance" "$switch" "$port"; then
        OK=$((OK + 1))
    else
        FAILED=$((FAILED + 1))
        FAILED_ROWS+=("$appliance,$switch,$port")
    fi
done < "$CSV_FILE"

echo
echo "=== summary: $OK/$TOTAL rows succeeded ==="
if [[ $FAILED -gt 0 ]]; then
    echo "Failed rows:"
    for row in "${FAILED_ROWS[@]}"; do
        echo "  - $row"
    done
    exit 1
fi

exit 0
