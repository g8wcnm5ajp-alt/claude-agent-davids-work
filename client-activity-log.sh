#!/usr/bin/env bash
#
# client-activity-log.sh
#
# Runs from the EM. Given a client IP, finds which appliance manages it
# (via `fstool hostinfo`, run locally on the EM), then SSHes to that
# appliance and queries its local Postgres database for that client's
# history in either the `np_action` table (policy/NetTool actions like
# sw_block, snow_add_new, goodies_label) or the `source_log` table
# (per-property learn/update events) -- same script, same flags, just a
# different table.
#
# The client IP is stored in these tables as a big-endian uint32 in the
# `primary_id` column, not as text -- this script converts the given IP
# to that integer for the WHERE clause, and asks Postgres to convert it
# straight back to a dotted-quad in the SELECT (via bitwise arithmetic:
# Postgres has no built-in int-to-inet cast that works on this schema),
# so the real IP is what's printed, never the raw integer.
#
# np_action.time is plain Unix epoch seconds. source_log.time is Unix
# epoch MILLISECONDS -- confirmed by inspection against real data (a raw
# np_action.time of ~1.79 billion matches "now" directly via to_timestamp;
# the equivalent source_log.time is ~1000x larger and only converts to a
# sane date after dividing by 1000). Any -s/-e time filter is converted to
# whichever unit the selected table actually uses.
#
# Requires: ssh (no expect needed -- the appliance hop is one
# non-interactive command, not an interactive CLI login).
#
# *** Always bound source_log queries with -s/-e. *** An unbounded
# `-l source_log` query took over 10 minutes against real data for one
# client and was killed rather than waited out; the same client with a
# one-day -s/-e window returned in well under a second. source_log logs
# every per-property learn/update event for every client continuously, so
# it's vastly larger than np_action, and a primary_id-only WHERE (no time
# bound) appears to force a full scan. np_action does not have this
# problem -- an unbounded np_action query for one real client (80+ rows)
# returned immediately.
#
# Usage:
#   ./client-activity-log.sh -i <client-ip> [-l np_action|source_log] [-s <start-time>] [-e <end-time>] [-o <output-file>] [-A <appliance-ip>]
#
# -s / -e accept either a raw Unix epoch (seconds) or anything `date -d`
# understands (e.g. "2026-08-14", "2026-08-14 09:00:00"). -A skips the
# `fstool hostinfo` lookup and queries the given appliance directly, in
# case the lookup's output format ever doesn't match what's parsed here.
#
# The appliance hop is always root@<appliance-ip>, key-based (no username
# or password needed) -- same pre-shared-key model as the other tools in
# this repo (junos-interface-poe-*, cisco-interface-poe-*, *-pull-logs-*).

set -uo pipefail

VERSION="1.0.0"

LOG_TABLE="np_action"
OUTPUT_ARG=""
CLIENT_IP=""
START_ARG=""
END_ARG=""
APPLIANCE_ARG=""

usage() {
    cat <<USAGE
Usage: $0 -i <client-ip> [-l np_action|source_log] [-s <start-time>] [-e <end-time>] [-o <output-file>] [-A <appliance-ip>]

  -i  Client IP address to look up
  -l  Which table to query: np_action (default) or source_log
  -s  Start of time range, UTC (raw epoch seconds, or anything \`date -d\` accepts)
  -e  End of time range, UTC (same format as -s)
  -o  File to save the results to (default: print to stdout)
  -A  Appliance IP to query directly, skipping the \`fstool hostinfo\` lookup
  -h  Show this help

Run this on the EM -- it uses \`fstool hostinfo\` locally to find which
appliance manages the given client, then SSHes there (key-based, no
password) to run the query. The real client IP is printed in the
results, never the raw integer the database stores it as.
USAGE
    exit 1
}

while getopts "i:l:s:e:o:A:h" opt; do
    case "$opt" in
        i) CLIENT_IP="$OPTARG" ;;
        l) LOG_TABLE="$OPTARG" ;;
        s) START_ARG="$OPTARG" ;;
        e) END_ARG="$OPTARG" ;;
        o) OUTPUT_ARG="$OPTARG" ;;
        A) APPLIANCE_ARG="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[[ -z "$CLIENT_IP" ]] && { echo "Error: -i <client-ip> is required" >&2; usage; }

case "$LOG_TABLE" in
    np_action|source_log) ;;
    *) echo "Error: -l must be one of: np_action, source_log" >&2; usage ;;
esac

echo "client-activity-log.sh v${VERSION}"

if ! command -v ssh >/dev/null 2>&1; then
    echo "Error: this script requires 'ssh' to be installed." >&2
    exit 1
fi

# --- convert the client IP to the big-endian uint32 the DB stores it as ---
if [[ ! "$CLIENT_IP" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    echo "Error: -i must be a dotted-quad IPv4 address, got: $CLIENT_IP" >&2
    exit 1
fi
o1="${BASH_REMATCH[1]}"; o2="${BASH_REMATCH[2]}"; o3="${BASH_REMATCH[3]}"; o4="${BASH_REMATCH[4]}"
for o in "$o1" "$o2" "$o3" "$o4"; do
    if (( o > 255 )); then
        echo "Error: -i is not a valid IPv4 address, got: $CLIENT_IP" >&2
        exit 1
    fi
done
INT_IP=$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))

# --- convert -s/-e to epoch seconds, if given ---
to_epoch_seconds() {
    local val="$1"
    if [[ "$val" =~ ^[0-9]+$ ]]; then
        echo "$val"
        return 0
    fi
    local converted
    # Force UTC interpretation of the input string -- the DB's raw time
    # columns are plain Unix epoch (inherently UTC) and every displayed
    # timestamp is explicitly "AT TIME ZONE 'UTC'", so a -s/-e value
    # parsed in the local host's zone instead would silently shift the
    # filter window. Caught live: the EM runs in IST (UTC+1), and an
    # unqualified `date -d` parse missed a known event by exactly an hour.
    if ! converted="$(TZ=UTC date -d "$val" +%s 2>/dev/null)"; then
        echo "Error: could not parse time value: $val" >&2
        return 1
    fi
    echo "$converted"
}

START_EPOCH=""
END_EPOCH=""
if [[ -n "$START_ARG" ]]; then
    START_EPOCH="$(to_epoch_seconds "$START_ARG")" || exit 1
fi
if [[ -n "$END_ARG" ]]; then
    END_EPOCH="$(to_epoch_seconds "$END_ARG")" || exit 1
fi

# source_log.time is epoch MILLISECONDS; np_action.time is epoch seconds.
# Scale the filter to whichever unit the selected table's raw column uses.
TIME_SCALE=1
[[ "$LOG_TABLE" == "source_log" ]] && TIME_SCALE=1000

# Defense in depth: every value about to be embedded in the SQL string is
# validated as purely numeric first (INT_IP above, these two here), even
# though they're already derived from validated/converted input -- a
# malformed conversion should fail loudly, not end up interpolated as-is.
for v in "$START_EPOCH" "$END_EPOCH"; do
    if [[ -n "$v" && ! "$v" =~ ^[0-9]+$ ]]; then
        echo "Error: internal time conversion produced a non-numeric value: $v" >&2
        exit 1
    fi
done

# --- find the managing appliance, unless one was given directly ---
APPLIANCE="$APPLIANCE_ARG"
if [[ -z "$APPLIANCE" ]]; then
    if ! command -v fstool >/dev/null 2>&1; then
        echo "Error: 'fstool' not found -- run this on the EM, or pass -A <appliance-ip> directly." >&2
        exit 1
    fi
    HOSTINFO="$(fstool hostinfo "$CLIENT_IP" 2>&1)"
    if [[ ! "$HOSTINFO" =~ assigned-to,\ ([0-9]{1,3}(\.[0-9]{1,3}){3})\ \(IP: ]]; then
        echo "Error: could not determine the managing appliance from 'fstool hostinfo $CLIENT_IP':" >&2
        echo "$HOSTINFO" >&2
        exit 1
    fi
    APPLIANCE="${BASH_REMATCH[1]}"
fi
echo "Client $CLIENT_IP is managed by appliance $APPLIANCE"

# --- build the query. Both tables get the same real_ip computed column
# (Postgres bitwise arithmetic -- no int->inet cast works on this schema)
# and a computed *_gmt column, so both log types are processed the same
# way from here on, per the design note this was built from. ---
REAL_IP_EXPR="((primary_id >> 24) & 255) || '.' || ((primary_id >> 16) & 255) || '.' || ((primary_id >> 8) & 255) || '.' || (primary_id & 255)"

if [[ "$LOG_TABLE" == "np_action" ]]; then
    SQL="SELECT ${REAL_IP_EXPR} AS real_ip, *, to_timestamp(time) AT TIME ZONE 'UTC' AS time_gmt, to_timestamp(clear_time) AT TIME ZONE 'UTC' AS clear_time_gmt FROM np_action WHERE primary_id=${INT_IP}"
else
    SQL="SELECT ${REAL_IP_EXPR} AS real_ip, *, to_timestamp(time/1000.0) AT TIME ZONE 'UTC' AS time_gmt FROM source_log WHERE primary_id=${INT_IP}"
fi

[[ -n "$START_EPOCH" ]] && SQL="${SQL} AND time>=$(( START_EPOCH * TIME_SCALE ))"
[[ -n "$END_EPOCH"   ]] && SQL="${SQL} AND time<$(( END_EPOCH * TIME_SCALE ))"
SQL="${SQL} ORDER BY time;"

echo "Querying $LOG_TABLE on $APPLIANCE ..."

# The SQL is passed through two shell parses (this shell -> the remote
# login shell ssh hands it to), so it's re-quoted with printf %q rather
# than embedded in a hand-built quoted string -- %q produces a form that
# round-trips correctly through exactly that kind of re-parse.
REMOTE_CMD=$(printf '%q ' psql -t -P pager=off -c "$SQL")

# Capture stdout (the actual query results) and stderr (SSH's own
# connection chatter, e.g. "Warning: Permanently added ... to the list of
# known hosts") separately -- merging them (2>&1) would put that banner
# into the saved results file as if it were a data row, which is exactly
# what an earlier version of this script did before this was caught by a
# live test run.
STDERR_FILE="$(mktemp)"
trap 'rm -f "$STDERR_FILE"' EXIT
RESULT="$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@${APPLIANCE}" "$REMOTE_CMD" 2>"$STDERR_FILE")"
STATUS=$?
STDERR_CONTENT="$(cat "$STDERR_FILE")"

if [[ $STATUS -ne 0 ]]; then
    echo "Error: query failed on $APPLIANCE (exit $STATUS):" >&2
    [[ -n "$STDERR_CONTENT" ]] && echo "$STDERR_CONTENT" >&2
    [[ -n "$RESULT" ]] && echo "$RESULT" >&2
    exit 1
fi

if [[ -n "$OUTPUT_ARG" ]]; then
    printf '%s\n' "$RESULT" > "$OUTPUT_ARG"
    NLINES=$(printf '%s\n' "$RESULT" | grep -c .)
    echo "Saved $NLINES row(s) to $OUTPUT_ARG"
else
    printf '%s\n' "$RESULT"
fi

echo "Done."
