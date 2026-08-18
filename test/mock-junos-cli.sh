#!/usr/bin/env bash
#
# mock-junos-cli.sh
#
# Fake interactive Junos CLI for exercising junos-interface-poe-bounce.sh /
# junos-interface-poe-bulk.sh without a real switch. Stateful per-port:
# tracks each interface's and its PoE's admin state independently and
# reflects it in "show" output, so the skip-if-already-in-desired-state
# logic -- including the multi-port-per-switch grouped-commit behavior --
# can actually be exercised. Understands: configure, set/delete interfaces
# <if> disable, set/delete poe interface <if> disable, commit,
# show interfaces <if>, show poe interface <if>, exit.
#
# Initial states, per port, default to Enabled unless overridden:
#   MOCK_IFACE_STATE=Enabled|Disabled          -- default for any port not in MOCK_IFACE_STATES
#   MOCK_POE_STATE=Enabled|Disabled            -- default for any port not in MOCK_POE_STATES
#   MOCK_IFACE_STATES="port1=Enabled,port2=Disabled"  -- per-port overrides
#   MOCK_POE_STATES="port1=Enabled,port2=Disabled"    -- per-port overrides

PROMPT_USER="testuser@mock-switch"

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

get_iface_state() {
    echo "${IFACE_STATES[$1]:-$DEFAULT_IFACE_STATE}"
}
get_poe_state() {
    echo "${POE_STATES[$1]:-$DEFAULT_POE_STATE}"
}

echo -n "Password: "
read -r _
echo

mode="op"

prompt() {
    if [[ "$mode" == "cfg" ]]; then
        printf '%s# ' "$PROMPT_USER"
    else
        printf '%s> ' "$PROMPT_USER"
    fi
}

while true; do
    IFS= read -r -p "$(prompt)" cmd || exit 0

    case "$cmd" in
        configure)
            mode="cfg"
            ;;
        exit)
            if [[ "$mode" == "cfg" ]]; then
                mode="op"
            else
                exit 0
            fi
            ;;
        "set interfaces "*" disable")
            port="${cmd#set interfaces }"
            port="${port% disable}"
            IFACE_STATES["$port"]="Disabled"
            ;;
        "delete interfaces "*" disable")
            port="${cmd#delete interfaces }"
            port="${port% disable}"
            IFACE_STATES["$port"]="Enabled"
            ;;
        "set poe interface "*" disable")
            port="${cmd#set poe interface }"
            port="${port% disable}"
            POE_STATES["$port"]="Disabled"
            ;;
        "delete poe interface "*" disable")
            port="${cmd#delete poe interface }"
            port="${port% disable}"
            POE_STATES["$port"]="Enabled"
            ;;
        commit)
            echo "commit complete"
            ;;
        "show interfaces "*)
            iface="${cmd#show interfaces }"
            st="$(get_iface_state "$iface")"
            # Real Junos reports a disabled interface as "Administratively
            # down", not "Disabled" -- match that wording here.
            if [[ "$st" == "Disabled" ]]; then
                echo "Physical interface: ${iface}, Administratively down, Physical link is Down"
            else
                echo "Physical interface: ${iface}, Enabled, Physical link is Up"
            fi
            echo "  Interface index: 128, SNMP ifIndex: 501"
            echo "  Link-level type: Ethernet, MTU: 1514, Speed: 1000mbps"
            ;;
        "show log messages")
            echo "Jan  1 00:00:01  mock-switch mgd[1234]: UI_CMDLINE_READ_LINE: User 'testuser', command 'show log messages'"
            echo "Jan  1 00:00:00  mock-switch /kernel: fake log line 1"
            echo "Jan  1 00:00:00  mock-switch /kernel: fake log line 2"
            # Some real Junos platforms (dual-RE-style EX/QFX) print a
            # routing-engine mastership indicator plus a blank line right
            # before the next prompt -- reproduce that here so the
            # pull-logs stripping logic gets regression coverage for it.
            echo ""
            echo "{master:0}"
            ;;
        "show poe interface "*)
            iface="${cmd#show poe interface }"
            st="$(get_poe_state "$iface")"
            oper="ON"
            [[ "$st" == "Disabled" ]] && oper="OFF"
            echo "PoE interface status:"
            echo "    Interface name:                  ${iface}"
            echo "    Interface administrative status: ${st}"
            echo "    Interface operational status:    ${oper}"
            ;;
        "")
            ;;
        *)
            echo "unknown command: \"$cmd\""
            ;;
    esac
done
