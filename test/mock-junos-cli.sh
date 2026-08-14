#!/usr/bin/env bash
#
# mock-junos-cli.sh
#
# Fake interactive Junos CLI for exercising junos-interface-poe-bounce.sh
# without a real switch. Understands just enough of the command set the
# bounce script sends: configure, set/delete interfaces <if> disable,
# set/delete poe interface <if> disable, commit, show interfaces <if>, exit.

PROMPT_USER="testuser@mock-switch"

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
            ;;
        "delete interfaces "*" disable")
            ;;
        "set poe interface "*" disable")
            ;;
        "delete poe interface "*" disable")
            ;;
        commit)
            echo "commit complete"
            ;;
        "show interfaces "*)
            iface="${cmd#show interfaces }"
            echo "Physical interface: ${iface}, Enabled, Physical link is Up"
            echo "  Interface index: 128, SNMP ifIndex: 501"
            echo "  Link-level type: Ethernet, MTU: 1514, Speed: 1000mbps"
            echo "  PoE: Disabled by admin: no"
            ;;
        "")
            ;;
        *)
            echo "unknown command: \"$cmd\""
            ;;
    esac
done
