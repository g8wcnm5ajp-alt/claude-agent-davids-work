#!/usr/bin/env bash
#
# mock-junos-cli.sh
#
# Fake interactive Junos CLI for exercising junos-interface-poe-bounce.sh
# without a real switch. Stateful: tracks the interface's and PoE's admin
# state and reflects it in "show" output, so the script's skip-if-already-
# in-desired-state logic can actually be exercised. Understands: configure,
# set/delete interfaces <if> disable, set/delete poe interface <if> disable,
# commit, show interfaces <if>, show poe interface <if>, exit.
#
# Initial states are configurable via env vars (default: both enabled):
#   MOCK_IFACE_STATE=Enabled|Disabled
#   MOCK_POE_STATE=Enabled|Disabled

PROMPT_USER="testuser@mock-switch"

iface_state="${MOCK_IFACE_STATE:-Enabled}"
poe_state="${MOCK_POE_STATE:-Enabled}"

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
            iface_state="Disabled"
            ;;
        "delete interfaces "*" disable")
            iface_state="Enabled"
            ;;
        "set poe interface "*" disable")
            poe_state="Disabled"
            ;;
        "delete poe interface "*" disable")
            poe_state="Enabled"
            ;;
        commit)
            echo "commit complete"
            ;;
        "show interfaces "*)
            iface="${cmd#show interfaces }"
            link="Up"
            [[ "$iface_state" == "Disabled" ]] && link="Down"
            echo "Physical interface: ${iface}, ${iface_state}, Physical link is ${link}"
            echo "  Interface index: 128, SNMP ifIndex: 501"
            echo "  Link-level type: Ethernet, MTU: 1514, Speed: 1000mbps"
            ;;
        "show poe interface "*)
            iface="${cmd#show poe interface }"
            oper="ON"
            [[ "$poe_state" == "Disabled" ]] && oper="OFF"
            echo "PoE interface status:"
            echo "    Interface name:                  ${iface}"
            echo "    Interface administrative status: ${poe_state}"
            echo "    Interface operational status:    ${oper}"
            ;;
        "")
            ;;
        *)
            echo "unknown command: \"$cmd\""
            ;;
    esac
done
