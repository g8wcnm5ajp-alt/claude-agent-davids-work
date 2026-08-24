#!/usr/bin/env python3
"""
webapp-query.py -- SSH forced-command wrapper for the forescout-lookup
web app's restricted key.

Deployed on the EM (192.168.22.210) at /root/scripts/webapp-query/webapp-query.py.
The corresponding authorized_keys line pins every connection using this
key to run ONLY this script:

    command="/root/scripts/webapp-query/webapp-query.py",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-rsa AAAA...

SSH sets $SSH_ORIGINAL_COMMAND to whatever the client actually asked
for; this script ignores everything else and validates that string
against a strict allow-list before doing anything. This is a command
allow-list, not a privilege reduction -- fstool/psql both require root,
so this still runs as root on the EM. What it restricts is WHAT can be
asked for, not what privilege level does the asking.

Verbs (see the plan this was built from, forescout-lookup):
    lookup <ip>            read-only: physical location, wired/wireless
                            verdict, np_action history (rule names and
                            action params resolved), arp_list decode
    debugset <ip> <spec>    per-plugin debug control -- spec is one or more
                            "<plugin>:<level>:<minutes>" triples (comma
                            separated; plugin in sw/dot1x/wireless, level
                            0-4, minutes 1-1440). Reused for both enabling
                            (level 4, a duration) and disabling immediately
                            (level 0 -- confirmed live this actually clears
                            conf.debug.until, not just shortens the timer)
                            -- the UI's checkboxes decide which plugins are
                            included at all, so this never touches a
                            plugin the caller didn't explicitly select
    techsupport <ip>        build a tech-support bundle scoped to the
                            relevant plugin(s); report-only, does not
                            transfer the bundle anywhere
    techsupportwindow <ip> <start_epoch>:<end_epoch> <plugin,plugin,...>
                            same, but scoped to an explicit historical
                            time window (fstool's own -t utc:X -t utc:Y
                            range) instead of a rolling "last 1h" -- used
                            when a requested debug capture window is
                            entirely in the past, since debug itself can
                            never be backdated
    policytree              the NINHS policy folder/rule tree (from
                            nptree.xml + nprules.xml), cached on disk --
                            static structure, no IP needed
    lastchecked <ip>        just the most-recently-evaluated rule_id(s)
                            for this host (from eval_status, the record
                            of every rule *evaluated*, not just ones
                            that fired an action) -- cheap
    matched <ip> <N><h|d|w> distinct rule_ids matched (np_action fired,
                            or eval_status matched) within a real time
                            window -- e.g. "matched 192.168.22.135 3d" --
                            drives the "show only matched & enabled"
                            tree filter's adjustable window
    rawfields <ip>          the full raw hostinfo property dump (every
                            field, not the curated lookup subset) --
                            lazy-loaded by the UI, can run 1000+ fields
    arplist <ip>            just the ARP decode table (appliance, arp
                            source, resolved IP, MAC, OUI vendor,
                            arp/mac resolve times) -- lightweight, backs
                            the table's own auto-refresh poll rather than
                            re-fetching the full lookup payload

Every code path here re-derives which plugin(s)/appliance(s) actually
matter for the given host from live data -- it never assumes the
appliance that answers `fstool hostinfo` locally on the EM is the same
appliance that owns the record. Same three-way assigned-to branch
(this appliance / another appliance / the EM itself) used by
client-activity-log.sh and documented in Host Connection Detail
Analysis.
"""
import html
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

IP_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IP_RE = rf"{IP_OCTET}(?:\.{IP_OCTET}){{3}}"

# One "<plugin>:<level>:<minutes>" triple, comma-separated list of them.
# The plugin name here is only shape-validated (safe identifier charset,
# matching real Forescout plugin directory names like "sw", "dot1x",
# "nbtscan_plugin", "google_cloud_platform") -- level 0-12 (fstool itself
# enforces no upper bound at all, confirmed live it silently accepts 13+
# too; 12 is David's own practical ceiling, not something fstool rejects),
# minutes 1-1440 (24h). This is NOT the authorization check: do_debugset
# separately confirms the plugin is actually installed
# (get_installed_plugins) before running anything, since the real set of
# debuggable plugins is per-host/per-deployment, not a fixed list that
# belongs in a regex.
DEBUGSET_PLUGIN_RE = r"[a-z][a-z0-9_]{1,40}"
DEBUGSET_LEVEL_RE = r"(?:[0-9]|1[0-2])"
DEBUGSET_ITEM_RE = rf"{DEBUGSET_PLUGIN_RE}:{DEBUGSET_LEVEL_RE}:\d{{1,4}}"
DEBUGSET_SPEC_RE = rf"{DEBUGSET_ITEM_RE}(?:,{DEBUGSET_ITEM_RE})*"

# Generic fleet/system-health policy matches that appear on every host and
# every appliance/EM "primary_id" alike -- confirmed noise, filtered out of
# the policy-match history returned to the app. See Eyesight Tests.
FLEET_NOISE_RULE_NAMES = {
    "Appliances", "EM/RecEM", "EM Load Compliance",
    "Appliance Load Compliance", "Appliance Resource Utilization",
    "Appliance Policy Efficiency", "Plugin Health",
}

NPRULES_XML = "/usr/local/forescout/etc/nprules.xml"
NPTREE_XML = "/usr/local/forescout/etc/nptree.xml"
POLICY_TREE_CACHE = "/root/scripts/webapp-query/policy_tree_cache.json"

WLC_CONFIG_PATH = "/usr/local/forescout/plugin/wireless/dev_db.wifi"
# dev_db.wifi is a binary length-prefixed record, not plain tab-delimited
# text -- confirmed live via `cat -A`: "wifi_ip" is followed by control
# bytes (e.g. \x01\x00\x00\x00\x0e), not whitespace, before the actual IP
# value. A plain \s+ separator never matched. Bounded non-greedy gap
# instead of \s+, since the field name and its value sit close together
# but aren't whitespace-separated.
WLC_IP_RE = re.compile(rf"wifi_ip.{{1,20}}?({IP_RE})")


def fail(msg, code=1):
    print(json.dumps({"error": msg}))
    sys.exit(code)


def run(cmd, timeout=60):
    """Run a local command (list form, no shell) and return (stdout, stderr, returncode)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s", 1


def ssh_appliance(appliance_ip, remote_cmd, timeout=60):
    """
    SSH from the EM to a managed appliance and run remote_cmd.
    Uses the EM's own existing pre-shared root trust to the appliances --
    the same trust client-activity-log.sh already relies on. This is a
    *different*, already-established relationship from the new restricted
    key that gets a caller into this script in the first place.
    """
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout=10", f"root@{appliance_ip}", remote_cmd,
    ]
    return run(cmd, timeout=timeout)


def ip_to_int(ip):
    o1, o2, o3, o4 = (int(x) for x in ip.split("."))
    return (o1 << 24) | (o2 << 16) | (o3 << 8) | o4


REAL_IP_EXPR = (
    "((primary_id >> 24) & 255) || CHR(46) || ((primary_id >> 16) & 255) || CHR(46) "
    "|| ((primary_id >> 8) & 255) || CHR(46) || (primary_id & 255)"
)


def get_assigned_to(ip):
    """
    Run `fstool hostinfo <ip>` locally on the EM and parse the assigned-to
    line. Returns one of:
        ("em", None)              -- assigned-to Enterprise Manager
        ("appliance", "<ip>")     -- assigned-to a specific appliance
        (None, None)              -- couldn't determine (host unknown)
    """
    out, err, rc = run(["fstool", "hostinfo", ip], timeout=30)
    text = out + err
    m = re.search(r"assigned-to,\s*Enterprise Manager", text)
    if m:
        return "em", None
    m = re.search(r"assigned-to,\s*(?:this\s*)?\(?IP:\s*([0-9.]+)", text)
    if not m:
        m = re.search(r"assigned-to,\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", text)
    if m:
        return "appliance", m.group(1)
    return None, None


def parse_hostinfo_lines(raw):
    """
    Parse `fstool hostinfo` output into a list of dicts. Each real line is:
        <ip>, <epoch>, <date>, <field_name>, <value>, (<source>), <flag>, <status-or-epoch>
    -- i.e. TWO comma-separated fields after the parenthesized source, not
    one (a genuine bug fixed here after seeing polluted values in the
    first real test: everything after the source paren was landing back
    inside "value" because the old regex assumed only one trailing field).
    Value itself is taken as everything before the first "(...)" group;
    the tail after that group is split on commas, and the LAST non-empty
    token is treated as status (matching the err-code checks used by
    classify_wired_wireless -- e.g. "sw_locate_mac_failed:err" always
    shows up as that final token when value is "???").
    """
    fields = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        parts = line.split(",", 4)
        if len(parts) < 5:
            continue
        field_name = parts[3].strip()
        rest = parts[4]
        paren_match = re.search(r"\(([^()]*)\)", rest)
        if not paren_match:
            value, source, status = rest.strip(), "", ""
        else:
            value = rest[: paren_match.start()].rstrip(", ").strip()
            source = paren_match.group(1).strip()
            tail_parts = [t.strip() for t in rest[paren_match.end():].split(",") if t.strip()]
            status = tail_parts[-1] if tail_parts else ""
        epoch = int(parts[1].strip()) if parts[1].strip().isdigit() else None
        fields.append({"field": field_name, "value": value, "source": source, "status": status, "epoch": epoch})
    return fields



# Per Host Connection Detail Analysis's method: these specific fields are
# what actually indicate physical location -- not every sw_*/wifi_*-
# prefixed field. Deliberately narrow: fields like wifi_client_login
# (a plain true/false flag, not a location signal) would otherwise read
# as "real wireless data" just because they're not "???" -- caught live
# on .135's own record during this app's first real test.
SW_LOCATION_FIELDS = {
    "sw_ip", "sw_hostname", "sw_port_desc", "sw_port_alias", "sw_port_vlan",
    "sw_vendor", "sw_port_poe_desc", "sw_port_poe_power",
}
WIFI_LOCATION_FIELDS = {
    "wifi_ap_wlc", "wifi_ssid", "wifi_client_role", "wifi_client_auth",
    "wireless_netfunc_os", "wireless_netfunc_role", "wifi_ap_name",
    "wifi_bssid", "wifi_vendor",
}


def classify_wired_wireless(fields):
    """
    Wired vs wireless per Host Connection Detail Analysis's method: which
    side has *ever* carried a real (non-???) value, read via the status
    code on the ??? entries -- not just which side is populated right now.
    """
    sw_real = any(f["value"] not in ("???", "") and f["field"] in SW_LOCATION_FIELDS for f in fields)
    wifi_real = any(f["value"] not in ("???", "") and f["field"] in WIFI_LOCATION_FIELDS for f in fields)
    sw_locate_failed = any("sw_locate_mac_failed" in f["status"] for f in fields)
    wireless_locate_failed = any("wireless_locate_host_failed" in f["status"] for f in fields)

    if sw_real and not wifi_real:
        return "wired"
    if wifi_real and not sw_real:
        return "wireless"
    if sw_real and wifi_real:
        return "both"
    if wireless_locate_failed and not sw_locate_failed:
        return "wired"
    if sw_locate_failed and not wireless_locate_failed:
        return "wireless"
    return "undetermined"


def tri_state(value):
    """hostinfo booleans come through as the strings 'true'/'false'/'???'/an error status."""
    if value == "true":
        return "yes"
    if value == "false":
        return "no"
    return "unknown"


def get_field(fields, name):
    for f in fields:
        if f["field"] == name:
            return f["value"]
    return None


def get_field_source(fields, name):
    for f in fields:
        if f["field"] == name:
            return f["source"]
    return None


def get_field_epoch(fields, name):
    for f in fields:
        if f["field"] == name:
            return f["epoch"]
    return None


def format_epoch(epoch):
    if epoch is None:
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(epoch)) + " UTC"


def get_connection_since(fields, verdict):
    """
    When did the host's *current* physical connection actually start --
    not just "when was this record last touched." Real gap found live:
    a host's policy_history can span a completely different physical
    connection than its current state (e.g. wired 802.1x/MAB activity
    from days ago, but currently tracked only via SecureConnector with
    no live switch data at all) -- confirmed against a real Console
    export for .253 before building this. Returns the epoch the current
    connection-defining field was last set, or None if genuinely unknown.
    """
    if verdict in ("wired", "both"):
        if get_field(fields, "sw_port_connected") == "connected":
            e = get_field_epoch(fields, "sw_port_connected")
            if e:
                return e
    if verdict in ("wireless", "both"):
        status = get_field(fields, "wifi_client_status")
        if status and status not in ("???", "Disassociated"):
            e = get_field_epoch(fields, "wifi_client_status")
            if e:
                return e
    # No live switch/AP data -- fall back to whatever *is* live: the
    # SecureConnector agent's own management state, then general
    # online/activity signals, in descending order of specificity.
    if get_field(fields, "manage_agent") == "true":
        e = get_field_epoch(fields, "manage_agent")
        if e:
            return e
    if get_field(fields, "online") == "true":
        e = get_field_epoch(fields, "online")
        if e:
            return e
    return get_field_epoch(fields, "active")


_node_map_cache = None


def get_node_map():
    """node_id -> appliance IP, via the EM's local `reg` table."""
    global _node_map_cache
    if _node_map_cache is not None:
        return _node_map_cache
    out, err, rc = run(["psql", "-t", "-c", "SELECT node_id, address FROM reg;"], timeout=20)
    m = {}
    for line in out.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) == 2 and parts[0]:
            m[parts[0]] = parts[1]
    _node_map_cache = m
    return m


OUI_DB_PATH = "/usr/share/hwdata/oui.txt"
# Standard hwdata-package OUI file, one entry like:
#   08-B4-D2   (hex)		Intel Corporate
# Confirmed present with identical content on the EM and both appliances --
# a local read, not a network lookup or external service.
OUI_LINE_RE = re.compile(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s*(.+?)\s*$")

_oui_cache = None


def load_oui_map():
    """OUI (first 3 octets, hex, no separators) -> vendor name."""
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache
    m = {}
    try:
        with open(OUI_DB_PATH, encoding="utf-8", errors="replace") as f:
            for line in f:
                mm = OUI_LINE_RE.match(line)
                if mm:
                    m[mm.group(1).replace("-", "").upper()] = mm.group(2).strip()
    except OSError:
        pass
    _oui_cache = m
    return m


def mac_vendor(mac):
    """
    Vendor for a MAC's OUI. Returns None for a malformed MAC or an OUI not
    in the local database (e.g. a locally administered/randomized MAC)
    rather than guessing.
    """
    hexonly = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(hexonly) < 6:
        return None
    return load_oui_map().get(hexonly[:6].upper())


def decode_arp_list(value, node_map, arp_resolved=None, mac_resolved=None):
    """
    arp_list format: "<node_id>;<arp_source_l3_ip>;<resolved_ip>;<mac>"
    possibly multiple entries separated by commas.

    arp_resolved/mac_resolved are the arp_list/mac hostinfo fields' own
    last-updated times -- field-level, not per-entry (hostinfo carries no
    per-ARP-entry timestamp) -- stamped onto every row so the UI can show
    "as of" without a second round trip.
    """
    if not value:
        return []
    out = []
    for entry in value.split(","):
        entry = entry.strip().strip("[]")
        parts = entry.split(";")
        if len(parts) != 4:
            continue
        node_id, l3_ip, resolved_ip, mac = parts
        out.append({
            "appliance": node_map.get(node_id, node_id),
            "arp_source": l3_ip,
            "resolved_ip": resolved_ip,
            "mac": mac,
            "vendor": mac_vendor(mac),
            "arp_resolved": arp_resolved,
            "mac_resolved": mac_resolved,
        })
    return out


_rule_name_cache = {}


def resolve_rule_name(rule_id, on_appliance=None):
    """Rule ID -> NAME via nprules.xml. rule_id may be empty (manual action)."""
    if not rule_id:
        return None
    if rule_id in _rule_name_cache:
        return _rule_name_cache[rule_id]
    grep_cmd = f"grep -o 'ID=\"{rule_id}\"[^>]*NAME=\"[^\"]*\"' {NPRULES_XML} | head -1"
    if on_appliance:
        out, err, rc = ssh_appliance(on_appliance, grep_cmd, timeout=20)
    else:
        out, err, rc = run(["bash", "-c", grep_cmd], timeout=20)
    m = re.search(r'NAME="([^"]*)"', out)
    name = m.group(1) if m else None
    _rule_name_cache[rule_id] = name
    return name


_action_params_cache = {}


def resolve_action_params(action_id, on_appliance=None):
    """
    An action's real configured behaviour lives in its own definition
    file, /usr/local/forescout/etc/actions/<action_id> -- e.g.
    PARAM NAME="label" VALUE="FirstMatched" for goodies_label_action, or
    PARAM NAME="authorization" VALUE="reject=dummy" for dot1x_authorize.
    Whatever the action type, this surfaces its actual PARAM name/value
    pairs generically -- including group-membership actions, whose PARAM
    would show the group -- rather than hardcoding one field name.
    """
    if not action_id:
        return {}
    if action_id in _action_params_cache:
        return _action_params_cache[action_id]
    path = f"/usr/local/forescout/etc/actions/{action_id}"
    cmd = f"cat {path} 2>/dev/null"
    if on_appliance:
        out, err, rc = ssh_appliance(on_appliance, cmd, timeout=15)
    else:
        out, err, rc = run(["bash", "-c", cmd], timeout=15)
    # The action definition XML entity-escapes control characters in its
    # VALUE attributes (e.g. a literal tab as "&#9;") -- the regex extract
    # doesn't decode that automatically, so a raw param would otherwise
    # show "&#9;" as literal text instead of the actual separator the
    # Console's own GUI renders cleanly. html.unescape covers XML's
    # standard entities (&amp; &quot; &#9; etc.) the same way.
    params = {k: html.unescape(v) for k, v in re.findall(r'PARAM NAME="([^"]*)" VALUE="([^"]*)"', out)}
    _action_params_cache[action_id] = params
    return params


# Human display names for action_name, matching the level of readability
# seen in the Console's own host log export (e.g. "802.1x Update MAR"
# rather than the raw "dot1x_update_mar"). Anything not in this map just
# falls back to its raw action_name -- not an error, just less polished.
ACTION_DISPLAY_NAMES = {
    "dot1x_update_mar": "802.1x Update MAR",
    "dot1x_authorize": "802.1x RADIUS Authorize",
    "goodies_label_action": "Label Host",
    "goodies_counter_increment": "Increment Counter",
    "snow_add_new": "Add Asset to CMDB",
    "forescout_counteract": "CounterACT Discovery",
    "sw_block": "Switch Block",
    "sw_quarantine": "Switch VLAN Quarantine",
    "sw_access_port_acl_priority": "Access Port ACL",
    "sw_acl": "Endpoint ACL",
    "dot1x_radius_log": "RADIUS Server Log",
}


def summarize_action(action_name, params):
    """
    One short, human-readable line of what this action actually
    configured -- e.g. "Restrict to: vlan:22 ..." -- built from its real
    PARAM values (see resolve_action_params), mirroring the level of
    detail the Console's own host log shows for the same event, rather
    than either a bare action_name or a full param dump (David: "remove
    the Policy Match Set" -- the old UI showed every raw param, which was
    mostly noise for things like snow_add_new's 150+ field mapping).
    """
    if not params:
        return ""
    if action_name == "dot1x_update_mar":
        authz = params.get("authz", "")
        return f"Restrict to: {authz}" if authz else f"MAR comment: {params.get('comment', '')}".strip()
    if action_name == "dot1x_authorize":
        return f"Authorization: {params.get('authorization', '')}"
    if action_name == "goodies_label_action":
        return f"Label: {params.get('label', '')}"
    if action_name == "goodies_counter_increment":
        return f"{params.get('counter_name', 'counter')} += {params.get('increment', '1')}"
    if action_name in ("sw_quarantine", "sw_block", "sw_acl", "sw_access_port_acl_priority"):
        for key in ("vlan", "acl_name", "blocking_rule"):
            if key in params:
                return f"{key}: {params[key]}"
        return ""
    if action_name == "snow_add_new":
        return f"Table: {params.get('snow_add_new_table', 'CMDB')}"
    return ""


def get_policy_history(ip, mode, appliance, window_seconds=None, limit=60, connection_since=None):
    """
    window_seconds=None keeps the old "most recent N rows" behaviour
    (used for the initial page load); a real value scopes to an actual
    time-bounded query instead (used by the `history` verb's adjustable
    period) -- not a client-side filter over an already-truncated row set.

    connection_since (epoch, from get_connection_since) flags each row
    as belonging to the host's *current* physical connection or an
    earlier one -- a real gap found live: a host's history can span a
    completely different connection than its current state (wired 802.1x
    activity from days ago on a host now only tracked via SecureConnector
    with no live switch data at all), confirmed against a real Console
    export for .253 before this was added.
    """
    int_ip = ip_to_int(ip)
    node_map = get_node_map()
    where_extra = f" AND time>={int(time.time()) - window_seconds}" if window_seconds is not None else ""
    sql = (
        f"SELECT to_char(to_timestamp(time) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') AS ts, "
        f"time, action_name, rule_name, rule_id, action_id, clear, clear_reason, node_id "
        f"FROM np_action WHERE primary_id={int_ip}{where_extra} ORDER BY time DESC LIMIT {limit};"
    )
    if mode == "em":
        out, err, rc = run(["psql", "-t", "-F", "|", "-c", sql], timeout=30)
        on_appliance = None
    else:
        out, err, rc = ssh_appliance(appliance, f"psql -t -F '|' -c \"{sql}\"", timeout=30)
        on_appliance = appliance

    rows = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 9 or not parts[0]:
            continue
        ts, raw_time, action_name, rule_name, rule_id, action_id, clear, clear_reason, node_id = parts
        if rule_name in FLEET_NOISE_RULE_NAMES:
            continue
        if not rule_name and rule_id:
            rule_name = resolve_rule_name(rule_id, on_appliance) or ""
        rows.append({
            "time": ts,
            "action": ACTION_DISPLAY_NAMES.get(action_name, action_name),
            "rule": rule_name or ("(manual action)" if not rule_id else rule_id),
            "rule_id": rule_id or None,
            # Raw node_id kept alongside its decoded appliance IP -- David's
            # ask: never leave a raw node ID unresolved, per the convention
            # already established in Host Connection Detail Analysis.
            "node_id": node_id or None,
            "appliance": node_map.get(node_id, node_id) if node_id else None,
            "cleared": clear == "t",
            "clear_reason": clear_reason or None,
            "change": summarize_action(action_name, resolve_action_params(action_id, on_appliance)),
            "current_connection": (
                None if connection_since is None else int(raw_time) >= connection_since
            ),
        })
    return rows


def get_wlc_ips(mode, appliance):
    """
    Per-host hostinfo's wifi_ap_wlc field isn't always populated -- confirmed
    live: shows "???" even on a host currently connected wirelessly. The
    Wireless plugin's own device config (dev_db.wifi) already knows which
    WLC(s) it's paired with -- confirmed live on both .212 and .213: each
    has exactly one entry, wifi_ip=192.168.22.254 (the one physical Cisco
    WLC in this environment). Read directly from whichever box manages this
    host's wireless rather than relying on the per-host field alone.
    Returns a sorted list of distinct controller IPs found (normally one;
    only used as a fallback when there's exactly one, so this never guesses
    if a future environment adds a second WLC).
    """
    cmd = f"cat {WLC_CONFIG_PATH} 2>/dev/null"
    if mode == "em":
        out, err, rc = run(["bash", "-c", cmd], timeout=15)
    else:
        out, err, rc = ssh_appliance(appliance, cmd, timeout=15)
    return sorted(set(WLC_IP_RE.findall(out)))


def do_lookup(ip):
    mode, appliance = get_assigned_to(ip)
    if mode is None:
        fail(f"could not determine managing appliance for {ip}")

    if mode == "em":
        raw, err, rc = run(["fstool", "hostinfo", ip], timeout=30)
        source_box = "Enterprise Manager (192.168.22.210)"
    else:
        raw, err, rc = ssh_appliance(appliance, f"fstool hostinfo {ip}", timeout=30)
        source_box = appliance

    fields = parse_hostinfo_lines(raw)
    verdict = classify_wired_wireless(fields)

    location = {}
    if verdict in ("wired", "both"):
        location["wired"] = {
            "switch_ip": get_field(fields, "sw_ip"),
            "switch_hostname": get_field(fields, "sw_hostname"),
            "port": get_field(fields, "sw_port_desc"),
            "vlan": get_field(fields, "sw_port_vlan"),
            "port_status": get_field(fields, "sw_port_status"),
            "port_connected": get_field(fields, "sw_port_connected"),
        }
    if verdict in ("wireless", "both"):
        wlc_field = get_field(fields, "wifi_ap_wlc")
        has_hostinfo_wlc = wlc_field not in (None, "", "???")
        wlc_ips = [] if has_hostinfo_wlc else get_wlc_ips(mode, appliance)
        location["wireless"] = {
            "ssid": get_field(fields, "wifi_ssid") or get_field(fields, "dot1x_ssid"),
            "ap": get_field(fields, "wifi_ap_name"),
            "wlc": wlc_field if has_hostinfo_wlc else (wlc_ips[0] if len(wlc_ips) == 1 else None),
            "wlc_source": "hostinfo" if has_hostinfo_wlc else ("wireless_plugin_config" if len(wlc_ips) == 1 else None),
            "client_status": get_field(fields, "wifi_client_status"),
        }

    node_map = get_node_map()
    arp_resolved = format_epoch(get_field_epoch(fields, "arp_list"))
    mac_resolved = format_epoch(get_field_epoch(fields, "mac"))
    arp_list = decode_arp_list(get_field(fields, "arp_list") or "", node_map, arp_resolved, mac_resolved)
    connection_since = get_connection_since(fields, verdict)

    mac_source = get_field_source(fields, "mac")
    result = {
        "ip": ip,
        "mac": get_field(fields, "mac"),
        # Raw source (e.g. "snow@8565155208648015208 []") kept alongside its
        # decoded appliance, same convention as arp_list/policy_history/
        # rawfields -- David's ask: show the MAC's source the same way the
        # ARP decode table already shows its appliance/arp_source.
        "mac_source": mac_source,
        "mac_source_appliance": resolve_source_appliance(mac_source, node_map),
        "managing_appliance": source_box,
        "wired_or_wireless": verdict,
        "location": location,
        "online": get_field(fields, "online"),
        "onsite": get_field(fields, "onsite"),
        "active": get_field(fields, "active"),
        # manage_agent/part_of_domain are the real fields behind what the
        # Console's own host log shows as e.g. "{Fully Trusted} Secure
        # Connector Managed NOT Domain Managed" (policy NINHS 1.2.2.02
        # Windows Enterprise Manageability) -- confirmed against a real
        # Console export for this exact host before wiring this up,
        # rather than guessed from field names alone.
        "secureconnector_managed": tri_state(get_field(fields, "manage_agent")),
        "domain_managed": tri_state(get_field(fields, "part_of_domain")),
        "arp_list": arp_list,
        "connection_since": format_epoch(connection_since),
        "policy_history": get_policy_history(ip, mode, appliance, connection_since=connection_since),
        "raw_field_count": len(fields),
        "last_checked": get_last_checked_rules(ip, mode, appliance),
        # Preview of exactly what debug/tech-support could target --
        # computed here (not just after the user clicks) so the UI can
        # show it up front. Every plugin that actually has real recovered
        # data for this host, not just sw/dot1x/wireless.
        "debug_targets": [
            {"plugin": p, "target": "192.168.22.210" if mode == "em" else appliance}
            for p in detect_plugins(fields, get_installed_plugins(mode, appliance))
        ],
    }
    print(json.dumps(result))


PLUGIN_DIR = "/usr/local/forescout/plugin"
_installed_plugins_cache = {}


def get_installed_plugins(mode, appliance):
    """
    Real installed plugin directories under /usr/local/forescout/plugin --
    the authoritative check for "is this actually a plugin fstool can
    debug/tech-support", not a guess. Cached per box (EM vs a specific
    appliance) since installed plugins don't change within one process's
    lifetime.
    """
    key = "em" if mode == "em" else appliance
    if key in _installed_plugins_cache:
        return _installed_plugins_cache[key]
    cmd = f"find {PLUGIN_DIR} -maxdepth 1 -mindepth 1 -type d -printf '%f\\n'"
    if mode == "em":
        out, err, rc = run(["bash", "-c", cmd], timeout=15)
    else:
        out, err, rc = ssh_appliance(appliance, cmd, timeout=15)
    plugins = set(out.split())
    _installed_plugins_cache[key] = plugins
    return plugins


SOURCE_PLUGIN_RE = re.compile(r"^([A-Za-z0-9_]+)@")


def detect_plugins(fields, installed):
    """
    Which plugin(s) actually contributed real (non-???, non-empty) data to
    this host's own hostinfo record -- replaces the old wired/wireless-
    verdict guess (which only ever offered sw/dot1x/wireless and missed
    e.g. crowdstrike entirely, matched purely by MAC, unrelated to
    connection medium). Confirmed live: for a real host this correctly
    surfaces crowdstrike, snow, va, ad, classification, goodies, etc.
    alongside sw/dot1x whenever those plugins genuinely have data for it --
    and by the same mechanism will surface dns_client/dhclass whenever a
    host has real DNS/DHCP-sourced fields. Cross-checked against the box's
    real installed plugin directories so a non-plugin source tag (e.g.
    "gen", the core engine's own generic field source) is never offered as
    a debuggable plugin.
    """
    found = set()
    for f in fields:
        if f["value"] in ("???", "", None):
            continue
        m = SOURCE_PLUGIN_RE.match(f["source"] or "")
        if m and m.group(1) in installed:
            found.add(m.group(1))
    return sorted(found)


def run_debug_cmd(plugin, level, minutes, mode, appliance):
    """
    fstool exposes two different debug mechanisms depending on plugin --
    `fstool sw debug` for the Switch plugin, `fstool tech-support debug`
    for everything else (dot1x, wireless). Same call shape covers both
    enable (level 4) and immediate disable (level 0, confirmed live to
    actually disable rather than just shorten the timer).
    """
    cmd = f"fstool {plugin} debug {level} {minutes}m" if plugin == "sw" else \
          f"fstool tech-support debug -t {minutes}m --level {level} {plugin}"
    if mode == "em":
        return run(["bash", "-c", cmd], timeout=30)
    return ssh_appliance(appliance, cmd, timeout=30)


def do_debugset(ip, spec):
    """
    Per-plugin debug control -- replaces the old uniform do_debug/do_undebug
    (same level across every relevant plugin, auto-detected from verdict).
    This applies an independently chosen level per plugin (duration is
    shared across whichever plugins are checked -- David's ask, one
    dial rather than N) to exactly the plugins the UI's checkboxes
    selected, nothing auto-derived -- lets David debug just one plugin,
    or different plugins at different levels, rather than always
    all-relevant-plugins-at-once. Reused for both
    directions: "Start debug" sends each checked plugin's configured
    level+minutes; "Stop debug now" sends the same checked plugins at
    level=0/minutes=1 (confirmed live under the old do_undebug that level 0
    disables immediately, not just shortens the timer -- same mechanism,
    still true here).

    spec is shape-validated by the caller's regex before this is ever
    reached (safe plugin-name charset, level 0-4, minutes 1-1440), but
    that alone doesn't know which plugin names are real. This checks
    every plugin in spec against the box's actual installed plugin
    directories (get_installed_plugins -- the same authoritative source
    detect_plugins uses to build the UI's checkbox list in the first
    place) UPFRONT, before running anything -- one bad plugin name fails
    the whole request rather than partially executing.
    """
    mode, appliance = get_assigned_to(ip)
    if mode is None:
        fail(f"could not determine managing appliance for {ip}")
    installed = get_installed_plugins(mode, appliance)
    target = "192.168.22.210" if mode == "em" else appliance
    items = [item.split(":") for item in spec.split(",")]
    for plugin, level_s, minutes_s in items:
        if plugin not in installed:
            fail(f"'{plugin}' is not an installed plugin on {target}")

    results = []
    for plugin, level_s, minutes_s in items:
        level, minutes = int(level_s), int(minutes_s)
        out, err, rc = run_debug_cmd(plugin, level, minutes, mode, appliance)
        results.append({
            "plugin": plugin, "target": target, "level": level, "minutes": minutes,
            "ok": rc == 0, "output": (out + err).strip(),
        })
    print(json.dumps({"ip": ip, "debug_set": results}))


def get_debug_until(plugin, mode, appliance):
    """
    Read conf.debug.until (epoch seconds) from a plugin's local.properties
    on whichever box actually runs it. Returns 0 if unset/unreadable --
    treated as "no active debug window" by the caller.
    """
    # Anchored to line-start: local.properties' own header comment also
    # embeds "conf.debug.until=<epoch>" inline (e.g. "# sw configuration
    # properties (last update: conf.debug.until=... )"), so an unanchored
    # grep matches twice -- the comment AND the real property line -- and
    # multi-line output silently broke isdigit() below, a false-negative
    # that let a real tech-support build proceed while debug was still
    # active. Caught live testing this exact wrapper.
    path = f"/usr/local/forescout/plugin/{plugin}/local.properties"
    cmd = f"grep -o '^conf.debug.until=[0-9]*' {path} 2>/dev/null | tail -1 | cut -d= -f2"
    if mode == "em":
        out, err, rc = run(["bash", "-c", cmd], timeout=15)
    else:
        out, err, rc = ssh_appliance(appliance, cmd, timeout=15)
    out = out.strip()
    return int(out) if out.isdigit() else 0


def do_techsupport(ip):
    mode, appliance = get_assigned_to(ip)
    if mode is None:
        fail(f"could not determine managing appliance for {ip}")

    raw, err, rc = (run(["fstool", "hostinfo", ip], timeout=30) if mode == "em"
                     else ssh_appliance(appliance, f"fstool hostinfo {ip}", timeout=30))
    fields = parse_hostinfo_lines(raw)
    verdict = classify_wired_wireless(fields)
    # Any plugin with real recovered data for this host is in scope for
    # collection, not just sw/dot1x/wireless -- David's explicit ask:
    # "any hostinfo log that shows recovered attributes should be
    # considered for tech-support data collection."
    plugins = detect_plugins(fields, get_installed_plugins(mode, appliance))

    # Enforced here, not just in the app's UI: if enhanced debug is still
    # active on any relevant plugin, refuse -- building the bundle now
    # would ship almost none of the debug-level data it was meant to
    # capture. David's explicit requirement: wait for the debug window to
    # actually close first.
    now = int(time.time())
    still_active = []
    for plugin in plugins:
        until = get_debug_until(plugin, mode, appliance)
        if until > now:
            still_active.append({"plugin": plugin, "debug_until_epoch": until, "seconds_remaining": until - now})
    if still_active:
        print(json.dumps({
            "error": "debug window still active on one or more relevant plugins -- wait before building the bundle",
            "still_active": still_active,
        }))
        sys.exit(3)

    target = "192.168.22.210" if mode == "em" else appliance
    bundles = []
    for plugin in plugins:
        ts_cmd = (
            f"fstool tech-support -p {plugin} -comment webapp-{ip.replace('.', '-')} "
            f"--pack -company Yubique -t 1h"
        )
        if mode == "em":
            out, err, rc = run(["bash", "-c", ts_cmd], timeout=480)
        else:
            out, err, rc = ssh_appliance(appliance, ts_cmd, timeout=480)
        text = out + err
        m = re.search(r"File:\s*(\S+)", text)
        m_size = re.search(r"Size:\s*([0-9.]+\s*\w+)", text)
        bundles.append({
            "plugin": plugin,
            "target": target,
            "ok": rc == 0 and bool(m),
            "path": m.group(1) if m else None,
            "size": m_size.group(1) if m_size else None,
            "output_tail": text[-500:],
        })

    print(json.dumps({"ip": ip, "wired_or_wireless": verdict, "bundles": bundles}))


def do_techsupport_window(ip, start_epoch, end_epoch, plugins_csv):
    """
    Tech-support bundle scoped to an explicit historical time window
    (both start and end already in the past by the time the caller
    reaches here -- the app decides that upstream, in /debugset's
    mode=window handling). Uses fstool's own "-t utc:<start> -t utc:<end>"
    range syntax against already-rotated logs, rather than live debug --
    confirmed live (Aug 24 2026) that a 10-minute window produces exactly
    "Since: <start> Until: <end>" in the tool's own output, older epoch
    first. Debug itself can never be backdated -- enabling it is a real
    configuration change to the plugin that only ever takes effect from
    the moment it's actually applied, which is exactly why a fully-past
    window falls back to this rather than trying to start debug at all.

    Same debug-still-active refusal as do_techsupport, scoped to
    plugins_csv instead of an auto-detected set.
    """
    mode, appliance = get_assigned_to(ip)
    if mode is None:
        fail(f"could not determine managing appliance for {ip}")
    installed = get_installed_plugins(mode, appliance)
    plugins = plugins_csv.split(",")
    for plugin in plugins:
        if plugin not in installed:
            fail(f"'{plugin}' is not an installed plugin")

    now = int(time.time())
    still_active = []
    for plugin in plugins:
        until = get_debug_until(plugin, mode, appliance)
        if until > now:
            still_active.append({"plugin": plugin, "debug_until_epoch": until, "seconds_remaining": until - now})
    if still_active:
        print(json.dumps({
            "error": "debug window still active on one or more relevant plugins -- wait before building the bundle",
            "still_active": still_active,
        }))
        sys.exit(3)

    target = "192.168.22.210" if mode == "em" else appliance
    bundles = []
    for plugin in plugins:
        ts_cmd = (
            f"fstool tech-support -p {plugin} -comment webapp-{ip.replace('.', '-')}-window "
            f"--pack -company Yubique -t utc:{start_epoch} -t utc:{end_epoch}"
        )
        if mode == "em":
            out, err, rc = run(["bash", "-c", ts_cmd], timeout=480)
        else:
            out, err, rc = ssh_appliance(appliance, ts_cmd, timeout=480)
        text = out + err
        m = re.search(r"File:\s*(\S+)", text)
        m_size = re.search(r"Size:\s*([0-9.]+\s*\w+)", text)
        bundles.append({
            "plugin": plugin,
            "target": target,
            "ok": rc == 0 and bool(m),
            "path": m.group(1) if m else None,
            "size": m_size.group(1) if m_size else None,
            "output_tail": text[-500:],
        })

    print(json.dumps({"ip": ip, "window": {"start": start_epoch, "end": end_epoch}, "bundles": bundles}))


def _parse_nprules():
    """
    rule_id (str) -> {name, enabled, inner_rules: [{id, name, action_enabled}]}
    Only top-level <RULE> elements are relevant here -- nptree.xml's
    <POLICY ID=.../> entries always reference a top-level RULE, never an
    INNER_RULE directly (confirmed by cross-checking real IDs before
    writing this). Each INNER_RULE's own action-enabled state is carried
    too, since "which sub-rule currently has a live action" is exactly
    the kind of thing today's investigation (the reject=dummy action)
    depended on.
    """
    root = ET.parse(NPRULES_XML).getroot()
    rules = {}
    for rule_el in root.iter("RULE"):
        rid = rule_el.get("ID")
        if rid is None:
            continue
        inner = []
        for inner_el in rule_el.iter("INNER_RULE"):
            action_el = inner_el.find("ACTION")
            inner.append({
                "id": inner_el.get("ID"),
                "name": inner_el.get("NAME"),
                "action_enabled": bool(action_el is not None and action_el.get("DISABLED") == "false"),
            })
        rules[rid] = {
            "name": rule_el.get("NAME"),
            "enabled": rule_el.get("ENABLED") == "true",
            "inner_rules": inner,
        }
    return rules


def _parse_policy_folder(folder_el, rule_map):
    node = {"id": folder_el.get("ID"), "name": folder_el.get("NAME"), "type": "folder", "children": []}
    policies_el = folder_el.find("POLICIES")
    if policies_el is not None:
        for policy_el in policies_el.findall("POLICY"):
            pid = policy_el.get("ID")
            rule = rule_map.get(pid)
            if rule is None:
                continue
            node["children"].append({
                "id": pid,
                "name": rule["name"],
                "type": "rule",
                "enabled": rule["enabled"],
                "children": [
                    {"id": ir["id"], "name": ir["name"], "type": "inner_rule",
                     "action_enabled": ir["action_enabled"], "children": []}
                    for ir in rule["inner_rules"]
                ],
            })
    for child_folder in folder_el.findall("POLICY_FOLDER"):
        node["children"].append(_parse_policy_folder(child_folder, rule_map))
    return node


def build_policy_tree():
    """
    The NINHS folder/rule tree only (this deployment's real active
    policy set, per Host Connection Detail Analysis -- the other ~651
    rules are a dormant template pack under different top-level folders,
    not worth shipping to every page load). Cached to disk, rebuilt only
    if nptree.xml/nprules.xml changed since -- both are multi-MB and
    parsing them fresh on every request isn't necessary for a structure
    that changes rarely.
    """
    if os.path.isfile(POLICY_TREE_CACHE):
        try:
            cache_mtime = os.path.getmtime(POLICY_TREE_CACHE)
            src_mtime = max(os.path.getmtime(NPTREE_XML), os.path.getmtime(NPRULES_XML))
            if cache_mtime >= src_mtime:
                with open(POLICY_TREE_CACHE) as f:
                    return json.load(f)
        except (OSError, json.JSONDecodeError):
            pass

    rule_map = _parse_nprules()
    root = ET.parse(NPTREE_XML).getroot()
    ninhs_el = next((el for el in root.iter("POLICY_FOLDER") if el.get("NAME") == "NINHS"), None)
    result = (_parse_policy_folder(ninhs_el, rule_map) if ninhs_el is not None
              else {"id": None, "name": "NINHS", "type": "folder", "children": []})
    try:
        with open(POLICY_TREE_CACHE, "w") as f:
            json.dump(result, f)
    except OSError:
        pass
    return result


def get_last_checked_rules(ip, mode, appliance):
    """
    The most recently *evaluated* rule_id(s) for this host, from
    eval_status -- the record of every rule checked, not just ones that
    fired an action (that's np_action). Several rules typically tie at
    the same timestamp in one evaluation pass (confirmed on a real host
    before building this: 4 rule_ids sharing one second) -- all of them
    are returned, not just one, since they together represent that
    pass's full result.
    """
    int_ip = ip_to_int(ip)
    sql = f"SELECT rule_id, time FROM eval_status WHERE primary_id={int_ip} ORDER BY time DESC LIMIT 20;"
    if mode == "em":
        out, err, rc = run(["psql", "-t", "-F", "|", "-c", sql], timeout=20)
    else:
        out, err, rc = ssh_appliance(appliance, f"psql -t -F '|' -c \"{sql}\"", timeout=20)

    rows = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 2 or not parts[0] or not parts[1].isdigit():
            continue
        rows.append((parts[0], int(parts[1])))
    if not rows:
        return {"last_checked_time": None, "rule_ids": []}
    max_time = max(t for _, t in rows)
    ids = sorted({rid for rid, t in rows if t == max_time})
    return {"last_checked_time": max_time, "rule_ids": ids}


def parse_window(window_str):
    """'<N>h' | '<N>d' | '<N>w' -> seconds. Returns None if malformed."""
    m = re.fullmatch(r"(\d{1,4})([hdw])", window_str)
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    return n * {"h": 3600, "d": 86400, "w": 604800}[unit]


def get_matched_rule_ids(ip, mode, appliance, window_seconds):
    """
    Distinct rule_ids "matched" (fired an action, per np_action, OR simply
    evaluated as a match, per eval_status) within the given window -- a
    real time-bounded query, not a client-side filter over whatever a
    handful of most-recent rows happen to cover. That distinction matters
    for a "last 2 weeks" style window: the UI's policy_history table only
    ever shows the 40 most-recent np_action rows, which on an active host
    might span a few hours, not two weeks -- filtering client-side over
    just those 40 would silently under-report matches for a wide window.
    """
    int_ip = ip_to_int(ip)
    cutoff = int(time.time()) - window_seconds
    queries = (
        f"SELECT DISTINCT rule_id FROM np_action WHERE primary_id={int_ip} AND time>={cutoff} AND rule_id IS NOT NULL;",
        f"SELECT DISTINCT rule_id FROM eval_status WHERE primary_id={int_ip} AND time>={cutoff};",
    )
    ids = set()
    for sql in queries:
        if mode == "em":
            out, err, rc = run(["psql", "-t", "-c", sql], timeout=25)
        else:
            out, err, rc = ssh_appliance(appliance, f"psql -t -c \"{sql}\"", timeout=25)
        for line in out.splitlines():
            v = line.strip()
            if v:
                ids.add(v)
    return sorted(ids)


def do_history(ip, window_str):
    window_seconds = parse_window(window_str)
    if window_seconds is None:
        fail("invalid window format -- expected <N>h, <N>d, or <N>w")
    mode, appliance = get_assigned_to(ip)
    if mode is None:
        fail(f"could not determine managing appliance for {ip}")

    raw, err, rc = (run(["fstool", "hostinfo", ip], timeout=30) if mode == "em"
                     else ssh_appliance(appliance, f"fstool hostinfo {ip}", timeout=30))
    fields = parse_hostinfo_lines(raw)
    connection_since = get_connection_since(fields, classify_wired_wireless(fields))

    rows = get_policy_history(ip, mode, appliance, window_seconds=window_seconds, limit=500,
                               connection_since=connection_since)
    print(json.dumps({
        "ip": ip, "window": window_str,
        "connection_since": format_epoch(connection_since),
        "policy_history": rows,
    }))


def do_matched(ip, window_str):
    window_seconds = parse_window(window_str)
    if window_seconds is None:
        fail("invalid window format -- expected <N>h, <N>d, or <N>w")
    mode, appliance = get_assigned_to(ip)
    if mode is None:
        fail(f"could not determine managing appliance for {ip}")
    ids = get_matched_rule_ids(ip, mode, appliance, window_seconds)
    print(json.dumps({"ip": ip, "window": window_str, "rule_ids": ids}))


def resolve_source_appliance(source, node_map):
    """
    source looks like "dhclass@8565155208648015208 [dhclass]" or "sw@... [sw]"
    -- the plugin short-name, an "@" node ID, and the plugin name again in
    brackets. Extracts the node ID and resolves it to the appliance IP via
    the same reg-table node_map used for arp_list -- David's ask: never
    leave a raw node ID unresolved, show both the raw source and the
    decoded appliance for every field, not just arp_list entries.
    """
    m = re.search(r"@(-?\d+)", source or "")
    if not m:
        return None
    return node_map.get(m.group(1))


def do_rawfields(ip):
    """
    The FULL raw `fstool hostinfo` property dump -- every field, not just
    the curated location/policy_history subset `lookup` returns. David's
    explicit ask: the level of detail in the raw file goes well beyond
    what the curated view shows (e.g. dhcp_req_fingerprint's actual
    fingerprint string, its source appliance, and its own timestamp).
    A separate verb rather than folding into `lookup` -- this can run to
    1000+ fields, too much to bundle into every normal lookup.
    """
    mode, appliance = get_assigned_to(ip)
    if mode is None:
        fail(f"could not determine managing appliance for {ip}")

    raw, err, rc = (run(["fstool", "hostinfo", ip], timeout=30) if mode == "em"
                     else ssh_appliance(appliance, f"fstool hostinfo {ip}", timeout=30))
    fields = parse_hostinfo_lines(raw)
    node_map = get_node_map()
    print(json.dumps({
        "ip": ip,
        "field_count": len(fields),
        "fields": [
            {"field": f["field"], "value": f["value"], "source": f["source"],
             "source_appliance": resolve_source_appliance(f["source"], node_map),
             "status": f["status"], "time": format_epoch(f["epoch"])}
            for f in fields
        ],
    }))


def do_policytree():
    print(json.dumps(build_policy_tree()))


def do_lastchecked(ip):
    mode, appliance = get_assigned_to(ip)
    if mode is None:
        fail(f"could not determine managing appliance for {ip}")
    print(json.dumps({"ip": ip, **get_last_checked_rules(ip, mode, appliance)}))


def do_arplist(ip):
    """
    Just the ARP decode table -- backs the UI's own auto-refresh poll on
    that table, so a periodic check doesn't re-fetch the full lookup
    payload (policy history, raw field count, debug targets, etc).
    Re-pulls hostinfo independently rather than sharing state with
    do_lookup, matching the same per-verb pattern already used by
    do_debugset/do_history.
    """
    mode, appliance = get_assigned_to(ip)
    if mode is None:
        fail(f"could not determine managing appliance for {ip}")
    raw, err, rc = (run(["fstool", "hostinfo", ip], timeout=30) if mode == "em"
                     else ssh_appliance(appliance, f"fstool hostinfo {ip}", timeout=30))
    fields = parse_hostinfo_lines(raw)
    node_map = get_node_map()
    arp_resolved = format_epoch(get_field_epoch(fields, "arp_list"))
    mac_resolved = format_epoch(get_field_epoch(fields, "mac"))
    arp_list = decode_arp_list(get_field(fields, "arp_list") or "", node_map, arp_resolved, mac_resolved)
    print(json.dumps({"ip": ip, "arp_list": arp_list}))


def main():
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "")

    m = re.fullmatch(rf"lookup ({IP_RE})", original.strip())
    if m:
        return do_lookup(m.group(1))

    m = re.fullmatch(rf"debugset ({IP_RE}) ({DEBUGSET_SPEC_RE})", original.strip())
    if m:
        return do_debugset(m.group(1), m.group(2))

    m = re.fullmatch(rf"techsupport ({IP_RE})", original.strip())
    if m:
        return do_techsupport(m.group(1))

    m = re.fullmatch(rf"techsupportwindow ({IP_RE}) (\d{{1,10}}):(\d{{1,10}}) ({DEBUGSET_PLUGIN_RE}(?:,{DEBUGSET_PLUGIN_RE})*)", original.strip())
    if m:
        return do_techsupport_window(m.group(1), int(m.group(2)), int(m.group(3)), m.group(4))

    if original.strip() == "policytree":
        return do_policytree()

    m = re.fullmatch(rf"lastchecked ({IP_RE})", original.strip())
    if m:
        return do_lastchecked(m.group(1))

    m = re.fullmatch(rf"matched ({IP_RE}) (\d{{1,4}}[hdw])", original.strip())
    if m:
        return do_matched(m.group(1), m.group(2))

    m = re.fullmatch(rf"history ({IP_RE}) (\d{{1,4}}[hdw])", original.strip())
    if m:
        return do_history(m.group(1), m.group(2))

    m = re.fullmatch(rf"rawfields ({IP_RE})", original.strip())
    if m:
        return do_rawfields(m.group(1))

    m = re.fullmatch(rf"arplist ({IP_RE})", original.strip())
    if m:
        return do_arplist(m.group(1))

    fail(
        "rejected: command did not match an allowed pattern "
        "(lookup <ip> | debugset <ip> <plugin:level:minutes,...> | techsupport <ip> | "
        "techsupportwindow <ip> <start>:<end> <plugin,...> | policytree | "
        "lastchecked <ip> | matched <ip> <N>h|d|w | history <ip> <N>h|d|w | rawfields <ip> | "
        "arplist <ip>)",
        code=2,
    )


if __name__ == "__main__":
    main()
