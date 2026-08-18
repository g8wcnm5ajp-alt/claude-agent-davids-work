#!/usr/bin/env bash
#
# mock-cisco-cli.sh
#
# Fake interactive Cisco IOS CLI for exercising cisco-interface-poe-bounce.sh
# / cisco-interface-poe-bulk.sh without a real switch. Stateful per-port:
# tracks each interface's and its PoE's admin state independently.
# Understands: enable, terminal length 0, configure terminal, interface
# <if>, shutdown/no shutdown, power inline never/auto, end, write memory,
# show interfaces <if>, show power inline <if>, exit.
#
# This mock only proves the expect script's command sequencing (login
# loop, grouping, skip-logic, single-save-per-switch) -- it does NOT
# validate that the command syntax or output wording matches a real Cisco
# device, since that hasn't been tested against real hardware. Treat a
# passing mock run as "the logic is sound", not "this works on a real
# switch".
#
# Initial states, per port, default to Enabled unless overridden:
#   MOCK_IFACE_STATE=Enabled|Disabled          -- default for any port not in MOCK_IFACE_STATES
#   MOCK_POE_STATE=Enabled|Disabled            -- default for any port not in MOCK_POE_STATES
#   MOCK_IFACE_STATES="port1=Enabled,port2=Disabled"  -- per-port overrides
#   MOCK_POE_STATES="port1=Enabled,port2=Disabled"    -- per-port overrides
#   MOCK_SKIP_ENABLE=1  -- land straight at privileged exec (skip the "> "/"enable" step)

PROMPT_HOST="mock-switch"

declare -A IFACE_STATES
declare -A POE_STATES
DEFAULT_IFACE_STATE="${MOCK_IFACE_STATE:-Enabled}"
DEFAULT_POE_STATE="${MOCK_POE_STATE:-Enabled}"

if [[ -n "${MOCK_IFACE_STATES:-}" ]]; then
    IFS=',' read -ra _pairs <<< "$MOCK_IFACE_STATES"
    for pair in "${_pairs[@]}"; do
        IFACE_STATES["${pair%%=*}"]="${pair#*=}"
    done
fi
if [[ -n "${MOCK_POE_STATES:-}" ]]; then
    IFS=',' read -ra _pairs <<< "$MOCK_POE_STATES"
    for pair in "${_pairs[@]}"; do
        POE_STATES["${pair%%=*}"]="${pair#*=}"
    done
fi

get_iface_state() { echo "${IFACE_STATES[$1]:-$DEFAULT_IFACE_STATE}"; }
get_poe_state()   { echo "${POE_STATES[$1]:-$DEFAULT_POE_STATE}"; }

echo -n "Password: "
read -r _
echo

if [[ "${MOCK_SKIP_ENABLE:-0}" == "1" ]]; then
    mode="exec"
else
    mode="user"
fi

prompt() {
    case "$mode" in
        user) printf '%s> ' "$PROMPT_HOST" ;;
        exec) printf '%s# ' "$PROMPT_HOST" ;;
        cfg)  printf '%s(config)# ' "$PROMPT_HOST" ;;
        cfgif) printf '%s(config-if)# ' "$PROMPT_HOST" ;;
    esac
}

cur_iface=""

while true; do
    IFS= read -r -p "$(prompt)" cmd || exit 0

    case "$cmd" in
        enable)
            if [[ "$mode" == "user" ]]; then
                mode="exec"
            fi
            ;;
        "terminal length 0")
            echo ""
            ;;
        "configure terminal")
            mode="cfg"
            ;;
        "interface "*)
            cur_iface="${cmd#interface }"
            mode="cfgif"
            ;;
        shutdown)
            IFACE_STATES["$cur_iface"]="Disabled"
            ;;
        "no shutdown")
            IFACE_STATES["$cur_iface"]="Enabled"
            ;;
        "power inline never")
            POE_STATES["$cur_iface"]="Disabled"
            ;;
        "power inline auto")
            POE_STATES["$cur_iface"]="Enabled"
            ;;
        end)
            mode="exec"
            ;;
        exit)
            case "$mode" in
                cfgif) mode="cfg" ;;
                cfg) mode="exec" ;;
                *) exit 0 ;;
            esac
            ;;
        "write memory")
            echo "Building configuration..."
            echo "[OK]"
            ;;
        "show logging")
            echo "Syslog logging: enabled (0 messages dropped, 0 flushes, 0 overruns)"
            echo "    Console logging: level debugging, 2 messages logged"
            echo ""
            echo "Log Buffer (4096 bytes):"
            echo "*Jan  1 00:00:01.000: %SYS-5-CONFIG_I: Configured from console by testuser"
            echo "*Jan  1 00:00:00.000: %LINK-3-UPDOWN: Interface fake log line 1"
            ;;
        "show interfaces "*)
            iface="${cmd#show interfaces }"
            st="$(get_iface_state "$iface")"
            if [[ "$st" == "Disabled" ]]; then
                echo "${iface} is administratively down, line protocol is down (disabled)"
            else
                echo "${iface} is up, line protocol is up (connected)"
            fi
            echo "  Hardware is Gigabit Ethernet, address is 0000.0000.0000"
            echo "  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,"
            ;;
        "show power inline "*)
            iface="${cmd#show power inline }"
            st="$(get_poe_state "$iface")"
            admin="auto"
            oper="on"
            if [[ "$st" == "Disabled" ]]; then
                admin="never"
                oper="off"
            fi
            echo "Interface  Admin  Oper       Power(Watts)"
            echo "${iface}   ${admin}   ${oper}          30.0"
            ;;
        "")
            ;;
        *)
            echo "% Invalid input detected"
            ;;
    esac
done
