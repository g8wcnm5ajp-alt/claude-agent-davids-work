#!/usr/bin/env bash
#
# switch-appliance-inventory.sh
#
# Runs ONLY on the EM (queries its local Postgres directly -- no SSH hop
# to any appliance, unlike the other tools in this repo). Produces a CSV
# listing every switch known to the EM's inventory, with the appliance
# that manages it, its type, layer mode, and comment.
#
# Built from the design note at
# Categorise-Switches/List Switches types & Appliances Managing them..md
#
# Data model (as inspected on the real EM): `devinfo` is an EAV table --
# one row per (category, id, field_name) with a `field_value`. Every
# switch shows up as several rows with category='sw' and id=<switch-ip>,
# one row per field (sw_type, sw_layer3, sw_comment, sw_nodeid, etc).
# `reg` has one row per appliance/node, keyed by node_id (bigint), with
# its IP in the `address` column. A switch's `sw_nodeid` field is that
# appliance's node_id (stored as text in devinfo; cast to bigint to join
# against reg.node_id).
#
# CSV columns, in order: Appliance IP, Switch Type, Switch IP,
# Switch Layer Mode, Switch Comment. Switch Layer Mode is derived from
# the raw sw_layer3 boolean: true -> "Layer 3", false -> "Layer 2",
# anything else (field missing, unexpected value) -> "Unknown" rather
# than left blank, since a blank cell there reads as "not filled in" when
# it may just be data the EM doesn't have -- real inventory data seen
# during testing includes exactly this case (missing sw_layer3 for some
# switches). A blank Appliance IP or Switch Type in the output means the
# EM's own devinfo/reg data for that switch is incomplete (seen for real:
# a switch with no sw_nodeid match in reg, and one with no sw_type field
# at all) -- not a bug in this script, a reflection of the source data.
#
# Uses `psql --csv` (proper RFC-4180 quoting/escaping, e.g. a comment
# containing a comma) rather than hand-built comma-joining.
#
# Requires: psql (local, no SSH/expect needed at all).
#
# Usage:
#   ./switch-appliance-inventory.sh [-o <output-file>]
#
# -o defaults to switch-appliance-inventory-<timestamp>.csv in the
# current directory.

set -uo pipefail

VERSION="1.0.0"

OUTPUT_ARG=""

usage() {
    cat <<USAGE
Usage: $0 [-o <output-file>]

  -o  CSV file to write (default: switch-appliance-inventory-<timestamp>.csv)
  -h  Show this help

Run this on the EM -- it queries the EM's own local Postgres directly,
no SSH to any appliance.
USAGE
    exit 1
}

while getopts "o:h" opt; do
    case "$opt" in
        o) OUTPUT_ARG="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

OUTPUT_FILE="${OUTPUT_ARG:-switch-appliance-inventory-$(date +%Y%m%d-%H%M%S).csv}"

echo "switch-appliance-inventory.sh v${VERSION}"

if ! command -v psql >/dev/null 2>&1; then
    echo "Error: this script requires 'psql' to be installed (run it on the EM)." >&2
    exit 1
fi

SQL="WITH sw AS (
    SELECT
        id AS switch_ip,
        MAX(CASE WHEN field_name='sw_type'    THEN field_value END) AS switch_type,
        MAX(CASE WHEN field_name='sw_layer3'  THEN field_value END) AS sw_layer3,
        MAX(CASE WHEN field_name='sw_comment' THEN field_value END) AS switch_comment,
        MAX(CASE WHEN field_name='sw_nodeid'  THEN field_value END) AS node_id
    FROM devinfo
    WHERE category='sw'
    GROUP BY id
)
SELECT
    r.address AS \"Appliance IP\",
    sw.switch_type AS \"Switch Type\",
    sw.switch_ip AS \"Switch IP\",
    CASE
        WHEN sw.sw_layer3='true'  THEN 'Layer 3'
        WHEN sw.sw_layer3='false' THEN 'Layer 2'
        ELSE 'Unknown'
    END AS \"Switch Layer Mode\",
    sw.switch_comment AS \"Switch Comment\"
FROM sw
LEFT JOIN reg r ON r.node_id = sw.node_id::bigint
ORDER BY sw.switch_ip;"

echo "Querying switch inventory ..."

STDERR_FILE="$(mktemp)"
trap 'rm -f "$STDERR_FILE"' EXIT
RESULT="$(psql --csv -c "$SQL" 2>"$STDERR_FILE")"
STATUS=$?
STDERR_CONTENT="$(cat "$STDERR_FILE")"

if [[ $STATUS -ne 0 ]]; then
    echo "Error: query failed (exit $STATUS):" >&2
    [[ -n "$STDERR_CONTENT" ]] && echo "$STDERR_CONTENT" >&2
    exit 1
fi

printf '%s\n' "$RESULT" > "$OUTPUT_FILE"
NROWS=$(( $(printf '%s\n' "$RESULT" | grep -c .) - 1 ))
echo "Saved $NROWS switch(es) to $OUTPUT_FILE"
echo "Done."
