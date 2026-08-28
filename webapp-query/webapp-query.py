#!/usr/bin/env python3
"""
webapp-query.py -- SSH forced-command wrapper for the forescout-lookup
web app's restricted key.

Deployed on the EM (currently 192.168.22.215 -- see EM_IP below, detected live via
`hostname -I` rather than hardcoded, since this environment's EM has changed IP before)
at /root/scripts/webapp-query/webapp-query.py.
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
    debugsetappliance <target> <spec> <case_ref>
                            per-plugin debug control, addressed by target
                            box (the EM or a specific appliance IP, never
                            resolved from a host's own IP -- the UI
                            dedupes plugin/appliance pairs across however
                            many looked-up hosts share a box, e.g. two
                            hosts on the same switch appliance need only
                            one "sw" row). spec is one or more
                            "<plugin>:<level>:<minutes>" triples (comma
                            separated; plugin shape-checked, level 0-12,
                            minutes 1-1440) -- target and every plugin
                            name are both checked against live ground
                            truth (resolve_target/get_installed_plugins)
                            before anything runs. Reused for both
                            enabling (a duration) and disabling
                            immediately (level 0 -- confirmed live this
                            actually clears conf.debug.until, not just
                            shortens the timer). case_ref is "-" for none
                            -- only ever real when this is the tech-
                            support proceed flow's own debug-enable step;
                            when given, the command actually run is
                            appended to TS_LOG_PATH (see
                            techsupportlogtail). The standalone Debug
                            panel and scheduled-debug jobs always send "-"
    tracelist <target>     read-only -- every FSTrace.category.<name> line
                            in /usr/local/forescout/etc/fstrace.properties
                            on target (EM or a specific appliance), each
                            with its live enabled/level state plus that
                            box's captured-once default alongside (the
                            first-ever call for a target snapshots the
                            file's then-current state as "default" and
                            persists it permanently -- David's ask,
                            2026-08-26, "Advanced Trace"). '#' prefix =
                            disabled (falls back to FSTrace.defaultLevel)
    tracedefaults <target>  read-only -- just the captured-once default
                            snapshot for target (capturing it now if this
                            is genuinely the first call), no live state.
                            Used by the auto-revert timer to know exactly
                            what to set things back to
    traceset <target> <category:on|off:level,...>
                            edits fstrace.properties on target -- every
                            category name is validated against that box's
                            OWN live file before any write happens (one
                            bad name fails the whole request). The file is
                            0444; chmod'd writable just long enough to
                            write the new content, then chmod'd back
    techsupportpreview <ip,ip,...> <level> <minutes> <selected_plugins> <selected_dbtables> <company> <send> <case_ref>
                            read-only -- returns the exact command
                            sequence techsupportcollect (plus the
                            debug-enable the caller fires just before
                            it) would run for these hosts/level/minutes/
                            case_ref, without executing anything. Every
                            relevant plugin, across every given host,
                            that resolves to the same target box appears
                            as ONE combined bundle for that box, not one
                            per plugin or per host
    techsupportcollect <ip,ip,...> <minutes> <selected_plugins> <selected_dbtables> <company> <send> <case_ref>
                            build tech-support bundle(s) scoped to the
                            relevant plugin(s) of one or more hosts --
                            assumes the caller already enabled debug on
                            each one and waited; does not itself enable
                            debug or wait. Every relevant plugin, across
                            every given host, that resolves to the same
                            target box collects in ONE combined bundle
                            for that box (fstool's own repeated -p, one
                            invocation); each contributing host's own
                            `fstool hostinfo` dump is attached via
                            fstool's own --attach-file, and any selected
                            significant table(s) (from `fstool db
                            diskspace`, e.g. source_log, hostinfo) via
                            fstool's own --dbtable, inline in the same
                            invocation -- re-validated per target against
                            that box's own live `db diskspace` list, since
                            a table valid on one box can be invalid on
                            another. selected_plugins is "-" for the
                            full auto-detected set, else
                            "<target>:<plugin>,..." to restrict to only
                            those explicitly checked (still only ever
                            narrows the real detected set, never injects
                            an arbitrary plugin). selected_dbtables is
                            "-" for none, else "<target>:<table>,..." --
                            same per-target re-validation as above.
                            company is "-" for DEFAULT_COMPANY, else
                            [A-Za-z0-9._-]{1,60} -- fstool's own
                            -company value (David's ask, an editable
                            override for what used to be hardcoded).
                            case_ref is "-" for
                            none, else [A-Za-z0-9_-]{1,40} -- threaded
                            into each bundle's -comment, and every
                            finished bundle (plus its commands-log
                            companion) is moved onto the EM's own
                            /shared/shared/case/<case_ref>/<target>/ --
                            pulled via scp from an appliance (then
                            deleted at the source), or just moved
                            locally if it was already built on the EM.
                            send is "1" to add fstool's own --send flag
                            alongside --pack ("Send support bundle
                            directly to Forescout", David's ask,
                            2026-08-26), "0" to omit it -- confirmed live
                            via `fstool help tech-support` that --send
                            and --pack are listed together, not
                            documented as mutually exclusive
    techsupportempreview <duration> <company> <send> <case_ref>
                            read-only -- the exact command sequence
                            techsupportem would run for this duration/
                            company/send/case_ref (David's ask: no EM
                            preview should ever be hand-approximated
                            text in a different file again -- caught
                            live 2026-08-25 that app.py's old hand-
                            written EM preview had drifted, wrong
                            -comment value, missing mkdir -p, one
                            combined mv shown instead of the real two
                            separate ones)
    techsupportem <duration> <company> <send> <case_ref>
                            a general EM-wide tech-support bundle (no
                            host to derive a relevant-plugin list from,
                            so fstool's own default category set, no -p)
                            -- same case-reference/centralize-onto-
                            /shared/shared treatment as techsupportcollect.
                            send: see techsupportpreview above
    techsupportwindowappliance <target> <start_epoch>:<end_epoch> <plugin,plugin,...> <case_ref>
                            same idea as techsupportcollect, but appliance-
                            addressed like debugsetappliance and scoped
                            to an explicit historical time window
                            (fstool's own -t utc:X -t utc:Y range)
                            instead of a rolling "last 1h" -- used when a
                            requested debug capture window is entirely in
                            the past, since debug itself can never be
                            backdated
    techsupportlogtail      no args -- returns the tail (capped,
                            TS_LOG_TAIL_BYTES) of TS_LOG_PATH
                            (/tmp/ForeScoutTech-Support.log on the EM),
                            the running log of every real command the
                            tech-support proceed flow actually executes
                            (debug-enable, fstool hostinfo/tech-support/
                            --dbtable, centralize mkdir/scp/rm/split),
                            each line tagged "[case_ref]". David's ask,
                            2026-08-26: a popup window polls this so the
                            commands are visible live, not just after the
                            whole build finishes
    techsupportlogclear     no args -- truncates TS_LOG_PATH to empty.
                            David's ask, 2026-08-26: a Clear button (with
                            a y/n confirm client-side) for each log-
                            history section; this is the one that lives
                            on the EM rather than in the app's own /data
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
    appliances               every appliance the EM knows about (reg
                            table) with live online/offline status
                            (fstool oneach) -- no args needed
    runshowerrors <target> <duration>
                            runs `fstool tech-support -t <duration>
                            --review --show-errors` on target (EM or a
                            managed appliance) and returns the parsed
                            errors/<category>/summary.txt tree -- a real,
                            unscoped snapshot that runs several minutes,
                            not a quick check; duration is <N>m or <N>h

Every code path here re-derives which plugin(s)/appliance(s) actually
matter for the given host from live data -- it never assumes the
appliance that answers `fstool hostinfo` locally on the EM is the same
appliance that owns the record. Same three-way assigned-to branch
(this appliance / another appliance / the EM itself) used by
client-activity-log.sh and documented in Host Connection Detail
Analysis.
"""
import concurrent.futures
import html
import json
import os
import re
import shutil
import socket
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


def run(cmd, timeout=60, input=None):
    """
    Run a local command (list form, no shell) and return (stdout, stderr,
    returncode). input, if given, is piped to the subprocess's stdin --
    for content too large to safely embed as a command-line argument
    (confirmed live: a real host's full `fstool hostinfo` dump, base64-
    encoded into an `echo ... | base64 -d` argument, blew the OS's
    argument-list-length limit -- "OSError: [Errno 7] Argument list too
    long"). Piping via stdin has no such limit and needs no encoding at
    all, since the content never touches shell argument parsing.
    """
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s", 1


_APPLIANCE_HOST_RE = re.compile(rf"^{IP_RE}$")
_dns_server_cache = None


def _get_fstool_dns_servers():
    """
    The DNS server(s) Forescout itself is configured to use for resolving appliance/EM
    hostnames (`fstool dns -l`) -- David's ask, 2026-08-28: a customer whose appliances/EM
    are addressed by DNS name (not IP, unlike every environment this app has been tested
    against so far) reported the app failing to reach appliances entirely. Confirmed live on
    this lab EM that the box's own OS-level resolver (/etc/resolv.conf, a local 127.0.0.1
    stub here) is a *different* thing from what `fstool dns -l` reports -- Forescout's own
    engine resolving appliance names correctly is no guarantee a plain `ssh`/`scp` subprocess
    (which uses the OS resolver) will too. Cached for this process's lifetime -- fstool's own
    DNS config doesn't change mid-request. Never raises: any failure here just means no
    fstool-sourced servers were found, and _resolve_target_host falls back further.
    """
    global _dns_server_cache
    if _dns_server_cache is not None:
        return _dns_server_cache
    try:
        out, err, rc = run(["fstool", "dns", "-l"], timeout=10)
        _dns_server_cache = re.findall(rf"^({IP_RE})$", out, re.M)
    except Exception:
        _dns_server_cache = []
    return _dns_server_cache


def _resolve_target_host(host):
    """
    Returns host unchanged if it's already a literal IPv4 address -- the case in every
    environment this app has run in so far, zero behavior change. Otherwise resolves it as a
    hostname: first against the DNS server(s) fstool itself is configured to use (see
    _get_fstool_dns_servers -- the authoritative source for how Forescout resolves its own
    managed appliances/EM), falling back to this box's plain OS-level resolver only if that
    doesn't produce an answer. Returns the original host unchanged (letting the actual
    ssh/scp call attempt its own resolution and fail with a clear error) if nothing here can
    resolve it either -- never silently substitutes something wrong. `dig` may not exist on
    every box this ever runs on, so that path is skipped (not fatal) if it's missing.
    """
    if _APPLIANCE_HOST_RE.match(host):
        return host
    if shutil.which("dig"):
        for server in _get_fstool_dns_servers():
            try:
                out, err, rc = run(["dig", f"@{server}", "+short", "+time=3", "+tries=1", host], timeout=5)
            except Exception:
                continue
            m = re.search(rf"^({IP_RE})$", out.strip(), re.M)
            if m:
                return m.group(1)
    try:
        return socket.gethostbyname(host)
    except OSError:
        return host


def ssh_appliance(appliance_ip, remote_cmd, timeout=60, input=None):
    """
    SSH from the EM to a managed appliance and run remote_cmd.
    Uses the EM's own existing pre-shared root trust to the appliances --
    the same trust client-activity-log.sh already relies on. This is a
    *different*, already-established relationship from the new restricted
    key that gets a caller into this script in the first place. input,
    if given, is piped through this SSH process's own stdin, which SSH
    transparently forwards to the remote command's stdin -- see run().

    appliance_ip may be a DNS name, not just a literal IP, in a customer
    environment -- resolved via _resolve_target_host (fstool's own DNS
    server first) before ssh ever sees it, rather than trusting ssh's own
    OS-level resolution to agree with however Forescout itself resolves
    the same name.
    """
    resolved = _resolve_target_host(appliance_ip)
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout=10", f"root@{resolved}", remote_cmd,
    ]
    return run(cmd, timeout=timeout, input=input)


TS_LOG_PATH = "/tmp/ForeScoutTech-Support.log"
TS_LOG_TAIL_BYTES = 200_000  # cap what techsupportlogtail returns -- a live-poll popup, not a full download


def _log_ts(case_ref, line):
    """
    Best-effort append to TS_LOG_PATH -- David's ask, 2026-08-26: "once I
    hit the proceed button I need to see what commands are actually
    being run," logged on the EM (this script always runs there,
    whether the command itself targets the EM or hops to an appliance
    via ssh_appliance, so a plain local append covers both) and tailed
    by the app's popup window via techsupportlogtail. Deliberately only
    called from the tech-support flow's own code paths (debug-enable,
    bundle build, centralize, split) -- NOT hooked into run()/
    ssh_appliance() globally, which would also capture every plain
    lookup/policy-tree/etc call this same script serves and bury the
    tech-support commands David actually asked to see. Never raises --
    a logging hiccup must never break the real collection it's
    describing.
    """
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        tag = f"[{case_ref}] " if case_ref else ""
        with open(TS_LOG_PATH, "a") as f:
            f.write(f"{ts} {tag}{line}\n")
    except OSError:
        pass


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
    # Was IP-only (r"...IP:\s*([0-9.]+)" / r"...,\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})") --
    # same bug class as APPLIANCE_ONLINE_RE and ssh_appliance's own DNS-resolution fix
    # (2026-08-28), but more fundamental: this is the very first step of nearly every
    # lookup/history/matched/rawfields call, so on a DNS-named-appliance environment
    # (confirmed live, HSC Belfast) this alone would return (None, None) -- "couldn't
    # determine" -- for every single host, before ssh_appliance ever gets a chance to
    # resolve anything. Now matches a hostname or an IP either way.
    m = re.search(r"assigned-to,\s*(?:this\s*)?\(?IP:\s*([^\s),]+)", text)
    if not m:
        m = re.search(r"assigned-to,\s*([^\s,)]+)", text)
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


def _domain_managed_status(fields):
    """"Domain managed" in the Identity panel -- prefers manage_domain_strict (the same live
    "Windows Manageable Domain (Current)" check already shown separately under Host Details/General)
    over part_of_domain, which can get stuck in an unresolved error state for a long time without a
    fresh retry. Confirmed live, 2026-08-28, on 192.168.22.253: part_of_domain had been stuck on
    '???' (status gen_error_service_restart:err) since 2026-07-30, while manage_domain_strict was
    fresh (today) and agreed with a live `fstool va_test -h <ip> -c manage` check on the managing
    appliance (smb/rpc/wmi all genuinely failing right now due to a hostname-resolution problem --
    "no" was the actually-correct current answer, not merely a stale field). Falls back to
    part_of_domain only if manage_domain_strict itself has no real value either."""
    strict = get_field(fields, "manage_domain_strict")
    if strict in ("true", "false"):
        return tri_state(strict)
    return tri_state(get_field(fields, "part_of_domain"))


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
        source_box = f"Enterprise Manager ({EM_IP})"
    else:
        raw, err, rc = ssh_appliance(appliance, f"fstool hostinfo {ip}", timeout=30)
        source_box = appliance

    fields = parse_hostinfo_lines(raw)
    verdict = classify_wired_wireless(fields)

    # Moved ahead of the wired/wireless location block (was computed
    # further down) so arp_list is already available to fold its
    # per-entry appliance into location["wired"] below -- David's ask.
    node_map = get_node_map()
    arp_resolved = format_epoch(get_field_epoch(fields, "arp_list"))
    mac_resolved = format_epoch(get_field_epoch(fields, "mac"))
    arp_list = decode_arp_list(get_field(fields, "arp_list") or "", node_map, arp_resolved, mac_resolved)

    location = {}
    if verdict in ("wired", "both"):
        location["wired"] = {
            "switch_ip": get_field(fields, "sw_ip"),
            "switch_hostname": get_field(fields, "sw_hostname"),
            "port": get_field(fields, "sw_port_desc"),
            "vlan": get_field(fields, "sw_port_vlan"),
            "port_status": get_field(fields, "sw_port_status"),
            "port_connected": get_field(fields, "sw_port_connected"),
            # Layer 2 -- same node-ID source decode already used for
            # mac_source_appliance elsewhere on this page (David's ask
            # here mirrors that existing convention): which appliance's
            # own record the switch/port data is attributed to. NOT
            # independently-verified proof of which appliance genuinely
            # polls this specific switch -- investigated live (2026-08-25)
            # and found no reliable signal for that; this is the same
            # field-source attribution already trusted and shown
            # throughout this app, not a new, stronger claim.
            "switch_source_appliance": resolve_source_appliance(get_field_source(fields, "sw_ip"), node_map),
            # Layer 3 -- every appliance that reported an ARP resolution
            # for this host (arp_list's own per-entry "appliance",
            # already computed below for the ARP decode table), deduped
            # since a host can have more than one arp_list entry.
            "arp_source_appliances": sorted(set(a["appliance"] for a in arp_list if a.get("appliance"))),
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
        # Same fact as managing_appliance, but always a clean dotted-IP
        # (managing_appliance is a display string, "Enterprise Manager
        # (192.168.22.210)" for the EM case) -- added so the UI's
        # DB-table attach list (David's ask, 2026-08-26) can scope
        # itself to the same "own appliance always gets a bundle"
        # target set Round 25 guarantees server-side, without parsing
        # a display string client-side.
        "own_appliance": EM_IP if mode == "em" else appliance,
        "wired_or_wireless": verdict,
        "location": location,
        "online": get_field(fields, "online"),
        "onsite": get_field(fields, "onsite"),
        "active": get_field(fields, "active"),
        # manage_agent/domain-managed are the real fields behind what the
        # Console's own host log shows as e.g. "{Fully Trusted} Secure
        # Connector Managed NOT Domain Managed" (policy NINHS 1.2.2.02
        # Windows Enterprise Manageability) -- confirmed against a real
        # Console export for this exact host before wiring this up,
        # rather than guessed from field names alone.
        "secureconnector_managed": tri_state(get_field(fields, "manage_agent")),
        "domain_managed": _domain_managed_status(fields),
        "arp_list": arp_list,
        "connection_since": format_epoch(connection_since),
        "policy_history": get_policy_history(ip, mode, appliance, connection_since=connection_since),
        "raw_field_count": len(fields),
        "last_checked": get_last_checked_rules(ip, mode, appliance),
        # Preview of exactly what debug/tech-support could target --
        # computed here (not just after the user clicks) so the UI can
        # show it up front. Every plugin that actually has real recovered
        # data for this host, not just sw/dot1x/wireless -- checked
        # against every real box's live plugin-enabled state, not just
        # the host's own assigned box and the EM (see detect_plugins), so
        # a plugin that only runs centrally on the EM still shows up
        # rather than being silently dropped. A plugin enabled on more
        # than one box (e.g. "sw") produces one row per candidate target
        # here -- the UI's plugin table already renders each as its own
        # independently-checkable row, letting the actual source be
        # picked manually when this app can't determine it live.
        "debug_targets": [
            {"plugin": p, "target": t}
            for p, targets in detect_plugins(fields, mode, appliance)
            for t in targets
        ],
        # Every real box (EM + every online appliance) -- not host-
        # specific, same value regardless of which host was looked up,
        # but included on every lookup response so the UI's plugin table
        # can offer a manual override to ANY known box, not just whatever
        # detect_plugins happened to auto-detect for a given plugin
        # (David's ask: a real override control, not just "pick among
        # the auto-detected candidates").
        "all_targets": get_all_targets(),
        # target -> [{"name", "size"}, ...] -- the tables `fstool db
        # diskspace` reports as significant on each known box (David's
        # "Attach DB" ask -- confirmed 2026-08-26 this is fstool's own
        # curated, size-ranked table list, not a raw dump of every table
        # in the schema, and not a separate whole Postgres database
        # either). Also not host-specific; included here (rather than a
        # separate round-trip) since the panel already needs all_targets
        # from this same response. Genuinely per-box, same reasoning as
        # every other per-target list here -- confirmed live each box's
        # significant-table list differs.
        "databases": {
            t: get_databases("em" if t == EM_IP else "appliance", None if t == EM_IP else t)
            for t in get_all_targets()
        },
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

_enabled_plugins_cache = {}
# Any real, always-installed plugin name works as the anchor -- confirmed
# live 2026-08-25 `fstool plugin <name> list`'s actual listing is
# identical no matter which real plugin name is passed (diffed
# `fstool plugin sw list` against `fstool plugin va list`, byte-identical
# output), it just needs SOME real plugin name to accept the command at
# all ("Plugin <bogus> does not exist" otherwise). "support" is a core
# plugin present on the EM and every appliance in this lab.
PLUGIN_LIST_ANCHOR = "support"


def get_enabled_plugins(mode, appliance):
    """
    plugin -> True/False, live per box via `fstool plugin <anchor> list`
    -- the real "is this plugin genuinely active here" signal, distinct
    from get_installed_plugins (directory presence). Confirmed live
    2026-08-25 (David's report on host 10.1.110.149): crowdstrike's
    plugin directory + a live running process + a socket exist on the EM
    AND both appliances identically, yet `fstool plugin crowdstrike
    status` reported "Plugin is up and running" only on the EM and
    "Error: CrowdStrike: not running." on both appliances -- and this
    list command's enabled=true/false state agreed, crowdstrike=true on
    the EM only. Cached per box for the process lifetime, same pattern
    as get_installed_plugins.
    """
    key = "em" if mode == "em" else appliance
    if key in _enabled_plugins_cache:
        return _enabled_plugins_cache[key]
    cmd = f"fstool plugin {PLUGIN_LIST_ANCHOR} list"
    if mode == "em":
        out, err, rc = run(["bash", "-c", cmd], timeout=15)
    else:
        out, err, rc = ssh_appliance(appliance, cmd, timeout=15)
    enabled = {}
    for line in out.splitlines():
        name, sep, val = line.strip().partition("=")
        if sep:
            enabled[name] = val.strip().lower() == "true"
    _enabled_plugins_cache[key] = enabled
    return enabled


_databases_cache = {}

DATABASE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


def get_databases(mode, appliance):
    """
    The tables `fstool db diskspace` reports for this box, WITH their
    reported size -- David's final word, 2026-08-26: "Not sure where you
    got all those databases from, but the only ones I need are listed by
    running the fstool db diskspace," then "can you also show the output
    of fstool db diskspace in the selected appliance section." Reconciles
    the confusing back-and-forth this feature went through the same day:
    this command's own output (`public.<table> |<size>`, confirmed live
    one real row per table, ~20 rows, sorted by size) IS a list of TABLE
    names within the default database, same granularity fstool's
    --dbtable always addressed -- not a separate Postgres database as a
    prior attempt assumed (that attempt, built around pg_dump +
    --attach-file, is fully reverted here). The real distinction David
    wanted was never "table vs whole database" -- it was "fstool's own
    curated, size-ranked significant tables (this command) vs every
    single table in the schema regardless of relevance" (the very first
    attempt, ~130 tables via a raw pg_tables query). Genuinely per-box,
    same reasoning as every other per-target list in this app --
    confirmed live each box reports its OWN top tables (e.g. `.212`
    includes band_width/of_device/users, `.213` includes portstable/
    detected_macs/policy instead). Returns a list of {"name", "size"}
    dicts in fstool's own reported order (largest first) -- that order
    is itself meaningful for the UI (which table is worth attaching),
    so kept as-is rather than re-sorted alphabetically. Cached per box
    for the process lifetime.
    """
    key = "em" if mode == "em" else appliance
    if key in _databases_cache:
        return _databases_cache[key]
    cmd = "fstool db diskspace"
    if mode == "em":
        out, err, rc = run(["bash", "-c", cmd], timeout=20)
    else:
        out, err, rc = ssh_appliance(appliance, cmd, timeout=20)
    seen = set()
    tables = []
    for line in out.splitlines():
        name, sep, size = line.partition("|")
        name = name.strip()
        size = size.strip()
        if not sep or not name.startswith("public."):
            continue
        name = name[len("public."):]
        if name in seen:
            continue
        seen.add(name)
        tables.append({"name": name, "size": size or None})
    _databases_cache[key] = tables
    return tables


_all_targets_cache = None


def get_all_targets():
    """
    Every real box this app can check plugin state on: the EM plus every
    appliance the EM's own reg table knows about (same source
    do_appliances uses), restricted to ones that actually answer `fstool
    oneach` so a dead appliance (confirmed two exist in this lab,
    172.16.1.129/.130) never stalls a lookup on a timeout. Cached for the
    process lifetime -- the appliance roster doesn't change within a
    single run of this script, same assumption already made throughout
    (get_node_map, get_installed_plugins).
    """
    global _all_targets_cache
    if _all_targets_cache is not None:
        return _all_targets_cache
    addresses = sorted(set(get_node_map().values()))
    out, err, rc = run(["fstool", "oneach", "-c", "-t", "10", "echo", "ok"], timeout=30)
    online = set(m.group(1) for m in (APPLIANCE_ONLINE_RE.match(line.strip()) for line in out.splitlines()) if m)
    _all_targets_cache = [EM_IP] + [a for a in addresses if a in online]
    return _all_targets_cache


def detect_plugins(fields, mode, appliance):
    """
    Which plugin(s) actually contributed real (non-???, non-empty) data to
    this host's own hostinfo record, and which box(es) to target debug/
    tech-support on for each -- replaces the old wired/wireless-verdict
    guess (which only ever offered sw/dot1x/wireless and missed e.g.
    crowdstrike entirely, matched purely by MAC, unrelated to connection
    medium). Confirmed live: for a real host this correctly surfaces
    crowdstrike, snow, va, ad, classification, goodies, etc alongside
    sw/dot1x whenever those plugins genuinely have data for it -- and by
    the same mechanism will surface dns_client/dhclass whenever a host
    has real DNS/DHCP-sourced fields.

    Target resolution, in priority order:

    1. **Field-source decode** (resolve_source_appliance, same node-ID
    mechanism already used for mac_source_appliance elsewhere) -- trusted
    ONLY when it points to a box OTHER than the host's own local
    appliance. Confirmed live 2026-08-25 (host 10.1.110.149): sw_ip/
    sw_port_desc/sw_hostname/mac are all genuinely source-attributed to
    a DIFFERENT appliance (.213) than the host's own (.212) -- real,
    precise, per-host/per-device evidence a coarse "is this plugin
    enabled anywhere" check can't produce, and exactly what David
    reported was wrong before this. A SAME-box decode is deliberately
    NOT trusted the same way -- confirmed live this is exactly how
    crowdstrike goes wrong: its EM-computed data gets synced into the
    host's local record and re-stamped with the LOCAL box's own node ID,
    making a same-box decode indistinguishable from "genuinely local"
    even when it isn't.

    2. **Live enabled-state** (get_enabled_plugins across EVERY known box,
    get_all_targets) -- the fallback whenever the field-source decode
    didn't produce a trusted cross-box answer. This is what correctly
    catches crowdstrike: its directory is installed identically
    everywhere (get_installed_plugins alone can never distinguish it),
    but it's only genuinely ENABLED on the EM in this lab, so it
    resolves there regardless of which appliance the host itself is
    assigned to. A plugin can legitimately be enabled on MORE than one
    box at once (confirmed live: most plugins besides crowdstrike show
    enabled=true on the EM AND both appliances in this lab) -- rather
    than silently guessing one, every genuinely-enabled candidate is
    returned so the caller can offer all of them. do_lookup's
    debug_targets ends up with one row per (plugin, candidate target)
    pair in this case, which the existing plugin-selection table already
    renders as separate, independently checkable rows -- the fallback
    David proposed for whichever plugin/host combination genuinely can't
    be resolved by either signal above.

    3. **Installed-directory check** -- last resort, only if the
    enabled-state check comes back with no candidates at all for a
    plugin that genuinely has real hostinfo data (defensive -- keeps a
    plugin from silently vanishing if `fstool plugin ... list`'s output
    format ever changes). Known on its own to be too coarse to
    distinguish anything (confirmed live: installed directories are
    identical across the EM and every appliance in this lab) -- never
    the primary signal, only a safety net.
    """
    local_target = EM_IP if mode == "em" else appliance
    installed_local = get_installed_plugins(mode, appliance)
    installed_em = installed_local if mode == "em" else get_installed_plugins("em", None)

    all_targets = get_all_targets()
    enabled_by_target = {
        t: get_enabled_plugins("em" if t == EM_IP else "appliance", None if t == EM_IP else t)
        for t in all_targets
    }
    node_map = get_node_map()

    found = {}
    for f in fields:
        if f["value"] in ("???", "", None):
            continue
        m = SOURCE_PLUGIN_RE.match(f["source"] or "")
        if not m:
            continue
        plugin = m.group(1)
        if plugin in found:
            continue
        if plugin not in installed_local and plugin not in installed_em:
            continue

        # Primary signal: the field's OWN node-ID source (same decode
        # resolve_source_appliance already uses for mac_source_appliance
        # etc), but ONLY trusted when it points to a box OTHER than the
        # host's own local appliance. Confirmed live 2026-08-25 (host
        # 10.1.110.149): sw_ip/sw_port_desc/sw_hostname/mac are all
        # genuinely source-attributed to a different appliance (.213)
        # than the host's own (.212) -- real, precise, per-host evidence
        # a coarse "is this plugin enabled anywhere" check can't produce.
        # A same-box decode is deliberately NOT trusted the same way --
        # confirmed live this is exactly how crowdstrike goes wrong: its
        # EM-computed data gets synced into the host's local record and
        # re-stamped with the LOCAL box's own node ID, making a same-box
        # decode indistinguishable from "genuinely local" even when it
        # isn't. That's why the fallback below (live enabled-state,
        # correctly EM-only for crowdstrike) only kicks in when this
        # field-source signal isn't itself pointing elsewhere.
        field_source_appliance = resolve_source_appliance(f["source"], node_map)
        if field_source_appliance and field_source_appliance != local_target and field_source_appliance in all_targets:
            found[plugin] = [field_source_appliance]
            continue

        candidates = [t for t in all_targets if enabled_by_target.get(t, {}).get(plugin) is True]
        if not candidates:
            if plugin in installed_local:
                candidates = [local_target]
            elif plugin in installed_em:
                candidates = [EM_IP]
        if candidates:
            found[plugin] = sorted(set(candidates))
    return sorted(found.items())


def run_debug_cmd(plugin, level, minutes, mode, appliance):
    """
    `fstool <plugin> debug <level> <minutes>m` -- the short, general
    form, same shape for every plugin (not just sw). David's explicit
    preference: the longer `fstool tech-support debug -t X --level Y
    plugin` form also works, but it's meant for scoping debug to a
    single switch/device (typically used with sw specifically), not what
    this app's plugin-wide enable is doing. Same call shape covers both
    enable (level 4) and immediate disable (level 0, confirmed live to
    actually disable rather than just shorten the timer).
    """
    cmd = f"fstool {plugin} debug {level} {minutes}m"
    if mode == "em":
        return run(["bash", "-c", cmd], timeout=30)
    return ssh_appliance(appliance, cmd, timeout=30)


def _detect_own_ip():
    """This script always runs directly on the EM (see module docstring) -- asks the OS for its own
    primary IP rather than hardcoding one. David's ask, 2026-08-28: the "Tech-Support pick
    appliance/EM" list was showing 192.168.22.210 as the EM's address when the real, live EM is
    192.168.22.215 -- this environment's EM has actually changed IP at least once already this
    session (a deliberate role switch, .210 -> .215), so a hardcoded value silently goes stale the
    next time that happens too. Same `hostname -I` approach Deploy.sh already uses for the same
    purpose. Falls back to the old hardcoded value only if that command is ever unavailable, so this
    can't hard-crash the whole script over a display/targeting detail."""
    out, err, rc = run(["hostname", "-I"], timeout=5)
    ip = out.strip().split()[0] if out.strip() else None
    return ip or "192.168.22.210"


EM_IP = _detect_own_ip()


def resolve_target(target):
    """
    target (an IP) -> (mode, appliance) for run_debug_cmd/get_installed_plugins/etc, validating along the way
    that it's a real known target -- the EM itself, or an appliance the EM's own reg table actually knows
    about (get_node_map()) -- never an arbitrary IP. Debug is now addressed by which box to run it on
    (deduplicated across however many looked-up hosts share that box), not resolved from a single host's IP,
    so this is the authorization boundary that used to be get_assigned_to(ip)'s job. Returns (None, None) if
    target isn't recognized.
    """
    if target == EM_IP:
        return "em", None
    if target in get_node_map().values():
        return "appliance", target
    return None, None


FSTRACE_PATH = "/usr/local/forescout/etc/fstrace.properties"

# Matches a real "FSTrace.category.<name> = <level>" line, active (no
# leading '#') or disabled (leading '#', no space before "FSTrace" --
# the header's own literal documentation example line, "# FSTrace.
# category.CATEGORY_NAME = LEVEL_NAME", has a space after '#' and is
# deliberately NOT matched by this). A trailing ';' and/or trailing
# whitespace both appear inconsistently in the real file (confirmed
# live -- most lines have neither, a few have ';', one has trailing
# whitespace) -- tolerated here, normalized away on write.
TRACE_CATEGORY_LINE_RE = re.compile(r"^(#)?FSTrace\.category\.([A-Za-z0-9_]+)\s*=\s*(\w+)\s*;?\s*$")
TRACE_LEVELS = ("error", "warning", "normal", "detailed")
TRACE_CATEGORY_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,80}$")

# Wire shape for the dispatcher's "traceset" verb -- one or more comma-separated
# "<category>:on|off:<level>" triples, matching TRACE_CATEGORY_NAME_RE/TRACE_LEVELS above.
TRACE_ITEM_RE = r"[A-Za-z0-9_]{1,80}:(?:on|off):(?:error|warning|normal|detailed)"
TRACE_CHANGES_RE = rf"{TRACE_ITEM_RE}(?:,{TRACE_ITEM_RE})*"

# Captured-once per-target baseline, persisted on the EM (this script's
# own host) -- David's ask, 2026-08-26: "a button to revert to default
# which you can get from reading the current file and storing this for
# all time use." First real read for a given target captures whatever
# the file's active/disabled state is AT THAT MOMENT and treats it as
# that box's default forever after; every later read just returns the
# stored snapshot, never re-derives it -- so a later manual edit (by
# this app or anyone else) never silently redefines what "default"
# means.
TRACE_DEFAULTS_DIR = "/root/scripts/webapp-query/trace_defaults"


def _trace_defaults_path(target):
    return os.path.join(TRACE_DEFAULTS_DIR, target.replace(".", "-") + ".json")


def _ensure_trace_defaults_captured(target, categories):
    path = _trace_defaults_path(target)
    if os.path.isfile(path):
        return
    try:
        os.makedirs(TRACE_DEFAULTS_DIR, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({c["name"]: {"enabled": c["enabled"], "level": c["level"]} for c in categories}, f)
        os.replace(tmp, path)
    except OSError:
        pass  # best-effort -- a missing snapshot just means the next call tries again


def _get_trace_defaults(target):
    path = _trace_defaults_path(target)
    if not os.path.isfile(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _fstrace_read(mode, appliance):
    cmd = f"cat {FSTRACE_PATH}"
    out, err, rc = (run(["bash", "-c", cmd], timeout=15) if mode == "em"
                     else ssh_appliance(appliance, cmd, timeout=15))
    if rc != 0:
        fail(f"could not read {FSTRACE_PATH} on this target: {(err or out).strip()}")
    return out


def get_trace_categories(mode, appliance):
    """Every FSTrace.category.<name> line in fstrace.properties, deduped by name (last one in the file
    wins, matching how Java .properties files themselves resolve a repeated key) -- {"name", "enabled",
    "level"} dicts, sorted by name. Deliberately excludes the separate FSTrace.filfer.* sub-filter
    properties (a different namespace, not a category toggle)."""
    text = _fstrace_read(mode, appliance)
    seen = {}
    for line in text.split("\n"):
        m = TRACE_CATEGORY_LINE_RE.match(line)
        if not m:
            continue
        disabled, name, level = m.group(1), m.group(2), m.group(3).lower()
        seen[name] = {"name": name, "enabled": disabled is None, "level": level}
    return sorted(seen.values(), key=lambda c: c["name"])


def do_tracelist(target):
    """Read-only -- current state of every trace category on `target`, plus that box's captured-once
    default alongside each one (capturing it now if this is genuinely the first call for this target).
    David's ask: the popup that opens after picking a box from Enhance Trace shows both."""
    mode, appliance = resolve_target(target)
    if mode is None:
        fail(f"'{target}' is not a known EM or managed appliance")
    categories = get_trace_categories(mode, appliance)
    _ensure_trace_defaults_captured(target, categories)
    defaults = _get_trace_defaults(target)
    for c in categories:
        d = defaults.get(c["name"])
        c["default_enabled"] = d["enabled"] if d else c["enabled"]
        c["default_level"] = d["level"] if d else c["level"]
    print(json.dumps({"target": target, "categories": categories}))


def do_tracedefaults(target):
    """Read-only -- just the captured-once default snapshot (capturing it now if needed), no live state.
    Used by app.py's auto-revert timer to know exactly what to set things back to when it fires, without
    needing to also fetch (and discard) the current live state."""
    mode, appliance = resolve_target(target)
    if mode is None:
        fail(f"'{target}' is not a known EM or managed appliance")
    categories = get_trace_categories(mode, appliance)
    _ensure_trace_defaults_captured(target, categories)
    print(json.dumps({"target": target, "defaults": _get_trace_defaults(target)}))


def do_traceset(target, changes_csv):
    """
    changes_csv: comma-separated "<category>:on|off:<level>" triples.
    Every category name is validated against this target's OWN live
    fstrace.properties BEFORE any write happens -- one bad name fails
    the whole request rather than partially applying (same defense-in-
    depth pattern as do_debugsetappliance's plugin check).

    fstrace.properties is 0444 (read-only, owned _fsservice) --
    chmod'd writable just long enough to write the new content (via
    _write_remote_file, piped through stdin, not a shell-embedded
    argument -- same reasoning as hostinfo attachment: the file is
    ~330 lines and could grow), then chmod'd back to 444 immediately
    after, matching how the file was found rather than leaving it
    permanently writable.
    """
    mode, appliance = resolve_target(target)
    if mode is None:
        fail(f"'{target}' is not a known EM or managed appliance")
    items = [c.split(":") for c in changes_csv.split(",") if c]
    if not items:
        fail("no changes given")
    parsed = []
    for item in items:
        if len(item) != 3:
            fail(f"malformed change '{':'.join(item)}'")
        name, enabled_s, level = item
        if not TRACE_CATEGORY_NAME_RE.match(name):
            fail(f"'{name}' is not a valid category name")
        if enabled_s not in ("on", "off"):
            fail(f"'{enabled_s}' must be on or off")
        level = level.lower()
        if level not in TRACE_LEVELS:
            fail(f"'{level}' is not a valid level ({'/'.join(TRACE_LEVELS)})")
        parsed.append((name, enabled_s == "on", level))

    text = _fstrace_read(mode, appliance)
    lines = text.split("\n")
    line_index = {}
    for i, line in enumerate(lines):
        m = TRACE_CATEGORY_LINE_RE.match(line)
        if m:
            line_index[m.group(2)] = i

    for name, _enabled, _level in parsed:
        if name not in line_index:
            fail(f"'{name}' is not a real trace category on {target}")

    for name, enabled, level in parsed:
        prefix = "" if enabled else "#"
        lines[line_index[name]] = f"{prefix}FSTrace.category.{name} = {level}"
    new_text = "\n".join(lines)

    chmod_w_cmd = f"chmod u+w {FSTRACE_PATH}"
    chmod_restore_cmd = f"chmod 444 {FSTRACE_PATH}"
    if mode == "em":
        run(["bash", "-c", chmod_w_cmd], timeout=15)
    else:
        ssh_appliance(appliance, chmod_w_cmd, timeout=15)
    _write_remote_file(target, f"cat > {FSTRACE_PATH}", new_text, timeout=30)
    if mode == "em":
        run(["bash", "-c", chmod_restore_cmd], timeout=15)
    else:
        ssh_appliance(appliance, chmod_restore_cmd, timeout=15)

    categories = get_trace_categories(mode, appliance)
    print(json.dumps({"target": target, "categories": categories}))


def do_debugsetappliance(target, spec, case_ref=None):
    """
    Appliance-addressed debug control -- replaces the IP-addressed
    do_debugset. The UI dedupes plugin/appliance pairs across however
    many looked-up hosts are checked (e.g. two hosts on the same switch
    appliance need only one "sw" row, not two; hosts on different switch
    appliances need one row each), so debug is naturally addressed by
    which box to run it on rather than which host's IP happens to
    resolve there. Level is independently chosen per plugin; duration is
    shared across whichever plugins are checked (David's ask, one dial
    rather than N). Reused for both directions: "Start debug" sends each
    checked plugin's configured level+minutes; "Stop debug now" sends
    the same checked plugins at level=0/minutes=1 (confirmed live this
    disables immediately, not just shortens the timer).

    spec is shape-validated by the caller's regex before this is ever
    reached (safe plugin-name charset, level 0-12, minutes 1-1440), but
    that alone doesn't know which plugin names are real. This checks
    every plugin in spec against the box's actual installed plugin
    directories (get_installed_plugins) UPFRONT, before running
    anything -- one bad plugin name fails the whole request rather than
    partially executing.

    case_ref (optional, "-"/None means not given): only threaded through
    by the tech-support proceed flow (start_techsupport_run's own
    debug-enable step) -- the standalone Debug panel and scheduled-debug
    jobs call this with no case_ref, so their commands never land in
    TS_LOG_PATH. David's ask was specifically "once I hit the proceed
    button," not every debug toggle across the whole app.
    """
    mode, appliance = resolve_target(target)
    if mode is None:
        fail(f"'{target}' is not a known EM or managed appliance")
    installed = get_installed_plugins(mode, appliance)
    items = [item.split(":") for item in spec.split(",")]
    for plugin, level_s, minutes_s in items:
        if plugin not in installed:
            fail(f"'{plugin}' is not an installed plugin on {target}")

    results = []
    for plugin, level_s, minutes_s in items:
        level, minutes = int(level_s), int(minutes_s)
        out, err, rc = run_debug_cmd(plugin, level, minutes, mode, appliance)
        if case_ref:
            _log_ts(case_ref, f"[{target}] fstool {plugin} debug {level} {minutes}m -> {'ok' if rc == 0 else 'FAILED'}")
        results.append({
            "plugin": plugin, "target": target, "level": level, "minutes": minutes,
            "ok": rc == 0, "output": (out + err).strip(),
        })
    print(json.dumps({"target": target, "debug_set": results}))


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


CASE_REF_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")

# No spaces (same constraint as CASE_REF_RE) -- the dispatch commands
# this travels through are space-separated positional tokens, so a
# space inside the value would break parsing; -_. cover reasonable word
# separators (e.g. "Yubique-Ltd") without that risk. ts_cmd embeds this
# quoted ("-company \"{company}\"", not argv) as defense in depth, but
# the shape check is what actually rules out quote/backslash/shell-
# metacharacters. David's ask, 2026-08-26: an editable override for the
# previously-hardcoded "Yubique".
COMPANY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,60}$")
DEFAULT_COMPANY = "Yubique"
COMPANY_TOKEN_RE = rf"(?:{COMPANY_NAME_RE.pattern[1:-1]}|-)"


def _write_remote_file(plugin_target, remote_write_cmd, content, timeout=30):
    """
    Runs remote_write_cmd on plugin_target (EM locally via bash -c, else
    ssh_appliance) with content piped to its stdin -- never embedded in
    the command string itself. Confirmed live this matters: a real
    host's full `fstool hostinfo` dump, first tried base64-encoded into
    an `echo ... | base64 -d` command-line argument, blew the OS's
    argument-list-length limit ("OSError: [Errno 7] Argument list too
    long") on a genuinely large dump. Piping via stdin has no such
    limit and needs no encoding, since the content never touches shell
    argument parsing -- SSH transparently forwards its own stdin to the
    remote command's stdin.
    """
    if plugin_target == EM_IP:
        return run(["bash", "-c", remote_write_cmd], timeout=timeout, input=content)
    return ssh_appliance(plugin_target, remote_write_cmd, timeout=timeout, input=content)


def _write_commands_summary(plugin_target, path, summary_text):
    """
    Writes a human-readable "here's exactly what ran" companion file next
    to the bundle it describes (same directory, <bundle-basename>-
    commands.txt) -- David's ask, so the collection process itself can be
    debugged later (e.g. "why is this plugin's data missing") without
    having to remember or reconstruct which fstool invocation actually
    produced a given file. Returns the written path, or None if the
    write itself failed (never lets a summary-write failure fail the
    build).
    """
    write_cmd = (
        f'D=$(dirname "{path}"); B=$(basename "{path}" .tgz); '
        f'cat > "$D/$B-commands.txt" && echo "$D/$B-commands.txt"'
    )
    out, err, rc = _write_remote_file(plugin_target, write_cmd, summary_text)
    written = out.strip()
    return written if rc == 0 and written else None


def _attach_hostinfo_files(plugin_target, hostinfo_by_ip):
    """
    Writes each host's own `fstool hostinfo` dump to a temp file ON THE
    TARGET BOX (piped via stdin, see _write_remote_file -- a real
    hostinfo dump can run 1000+ lines, which is exactly what broke the
    original base64-as-argument approach live), returning the list of
    remote paths to pass as repeated --attach-file arguments. Confirmed
    live fstool embeds each attached file under files/<original-path>
    inside the resulting archive, and genuinely accepts more than one
    --attach-file in a single invocation. Caller is responsible for
    cleaning these up once the build finishes (see _build_combined_bundle).
    """
    paths = []
    for ip, raw in sorted(hostinfo_by_ip.items()):
        path = f"/tmp/hostinfo-{ip.replace('.', '-')}-{int(time.time() * 1000)}-{os.urandom(2).hex()}.txt"
        _write_remote_file(plugin_target, f'cat > "{path}"', raw)
        paths.append(path)
    return paths


def do_techsupport_log_tail():
    """
    Returns the tail of TS_LOG_PATH (capped at TS_LOG_TAIL_BYTES) --
    David's ask, 2026-08-26: a popup window polls this while a build is
    running so the actual commands (debug-enable, the fstool hostinfo/
    tech-support/--dbtable invocations, and the mkdir/scp/rm/split
    centralize steps) are visible as they run, not just after the whole
    proceed action finishes. No args -- the log is one shared file for
    the whole EM, tagged per-line with [case_ref] rather than split into
    per-case files, so a single popup naturally covers everything
    currently in flight.
    """
    if not os.path.isfile(TS_LOG_PATH):
        print(json.dumps({"log": ""}))
        return
    try:
        size = os.path.getsize(TS_LOG_PATH)
        with open(TS_LOG_PATH, "r", errors="replace") as f:
            if size > TS_LOG_TAIL_BYTES:
                f.seek(size - TS_LOG_TAIL_BYTES)
                chunk = f.read()
                # Drop the partial leading line so the tail reads cleanly
                # from a real line boundary -- but only when there's a
                # complete line left after it. If the seek point lands
                # inside the file's very last line (only possible when
                # TS_LOG_TAIL_BYTES is small relative to line length --
                # not a real concern at the real ~200KB cap, but confirmed
                # live in testing with a small cap), dropping it would
                # discard the entire tail and return nothing; fall back to
                # the raw, possibly-partial chunk instead.
                nl = chunk.find("\n")
                log = chunk[nl + 1:] if nl != -1 and nl + 1 < len(chunk) else chunk
            else:
                log = f.read()
    except OSError as e:
        fail(f"could not read {TS_LOG_PATH}: {e}")
        return
    print(json.dumps({"log": log}))


def do_techsupport_log_clear():
    """
    Truncates TS_LOG_PATH to empty -- David's ask, 2026-08-26: a Clear
    button (with a y/n confirm client-side) for each log-history
    section, this one being the only one that lives on the EM rather
    than in the app's own /data. Truncates rather than deletes so the
    file (and its permissions) stay in place for the next _log_ts call
    to append to -- no different from any other "clear this log"
    action elsewhere in the app.
    """
    if os.path.isfile(TS_LOG_PATH):
        open(TS_LOG_PATH, "w").close()
    print(json.dumps({"ok": True}))


# Every centralized bundle (and its -commands.txt / split .part-xx
# siblings) lives under exactly this tree -- see _centralize_bundle's own
# dest_dir and _split_if_oversized's chunk naming. Bounding the download
# verb to this exact shape (case_dir/target/filename, each segment plain
# alnum/dot/dash/underscore) is what stops it being an arbitrary-file-read
# primitive off the back of a browser-supplied path.
BUNDLE_PATH_RE = re.compile(
    r"^/shared/shared/case/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$"
)


def _is_safe_bundle_path(path):
    if not BUNDLE_PATH_RE.match(path or ""):
        return False
    return not any(seg in (".", "..") for seg in path.split("/"))


def do_techsupport_download(path):
    """
    Streams a previously-built, already-centralized bundle (or a
    -commands.txt / split .part-xx sibling) straight to stdout as raw
    bytes -- David's ask, 2026-08-27: download the built bundles via the
    web app's own HTTP session instead of an admin having to scp them off
    the EM by hand. Deliberately NOT JSON like every other verb here (a
    multi-hundred-MB bundle base64'd into a JSON string would be a
    memory/bandwidth disaster on both ends) -- app.py's own
    download_techsupport_bundle() knows to expect this verb's raw-bytes
    response instead of parsing it as JSON, gated on the "BEGIN-BINARY"
    marker line below so a rejected/missing path still reports a normal
    JSON error rather than silently returning zero bytes.
    """
    if not _is_safe_bundle_path(path) or not os.path.isfile(path):
        print(json.dumps({"error": f"'{path}' is not a known, existing tech-support bundle file."}))
        return
    sys.stdout.write("BEGIN-BINARY\n")
    sys.stdout.flush()
    with open(path, "rb") as f:
        shutil.copyfileobj(f, sys.stdout.buffer)
    sys.stdout.buffer.flush()


def do_techsupport_cleanup(path):
    """
    Deletes a single centralized bundle/chunk/-commands.txt file --
    David's ask, 2026-08-27: a Clean up button right next to each
    Download link, so a bundle already retrieved (or no longer needed)
    doesn't have to be rm'd off the EM by hand. Same path whitelist as
    do_techsupport_download -- this is a delete primitive, so it gets at
    least as much scrutiny, not less. Deleting an already-gone file is
    reported ok (matches the button's own "already cleaned up" case
    rather than surfacing a confusing error for something that's already
    achieved the user's actual intent).
    """
    if not _is_safe_bundle_path(path):
        print(json.dumps({"error": f"'{path}' is not a known tech-support bundle path."}))
        return
    if os.path.isfile(path):
        os.remove(path)
    print(json.dumps({"ok": True}))


def _case_dir_name(case_ref):
    """Timestamped fallback when no case reference was given, so ad-hoc builds still land somewhere distinct
    rather than colliding in one shared "adhoc" folder."""
    return case_ref or f"adhoc-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}"


def _centralize_command_lines(plugin_target, bundle_path, commands_log_path, case_dir):
    """
    The exact sequence of commands _centralize_bundle runs to move a
    finished bundle (+ its commands-log companion) onto the EM's shared
    case storage -- pulled out as its own pure, no-side-effects function
    so EVERY preview (do_techsupport_preview, do_techsupport_em_preview)
    shows precisely this, never a hand-approximated version that can
    drift out of sync with what actually executes. David caught exactly
    this kind of drift live (2026-08-25): the EM preview's hand-written
    text showed one combined "mv a b dest/" line and no mkdir -p, but
    the real code always runs mkdir -p first, then a SEPARATE mv (or
    scp) per file -- confirmed this same drift existed in the host-based
    preview too, not just the EM one. bundle_path/commands_log_path can
    be real paths (the actual execution) or placeholders like
    "<bundle>.tgz" (a preview, before the real filename exists).
    case_dir: already resolved via _case_dir_name by the caller ONCE --
    not recomputed here, since _case_dir_name's timestamp fallback (no
    case_ref given) would otherwise risk producing a different value on
    a second call than whatever the caller already displayed/used.
    Returns (commands, dest_dir).
    """
    dest_dir = f"/shared/shared/case/{case_dir}/{plugin_target}"
    files = [f for f in (bundle_path, commands_log_path) if f]
    # Explicitly labeled "on the EM" -- this always runs there regardless
    # of which box built the bundle (via run(), never ssh_appliance()),
    # but sitting next to scp/ssh lines that clearly show a cross-box hop
    # made it easy to misread as running wherever the bundle itself was
    # built. Nothing under /shared/shared is ever created on an
    # appliance -- confirmed directly in the code, not just by this label.
    commands = [f'mkdir -p "{dest_dir}"  # on the EM']
    if plugin_target == EM_IP:
        for f in files:
            commands.append(f'mv "{f}" "{dest_dir}/"')
    else:
        for f in files:
            commands.append(f"scp {plugin_target}:{f} em:{dest_dir}/")
        commands.append(f"ssh {plugin_target} rm " + " ".join(f'"{f}"' for f in files))
    return commands, dest_dir


def _centralize_bundle(plugin_target, path, commands_log, case_ref, case_dir=None):
    """
    Moves the finished bundle (and its commands-log companion, if any)
    off whichever box built it and onto the EM's own /shared/shared
    mount, under /shared/shared/case/<case_ref-or-adhoc-timestamp>/
    <target>/ -- David's ask, one place to retrieve every bundle for a
    case regardless of which box(es) actually built them, rather than
    SSHing into each appliance separately. Confirmed live /shared/shared
    is the genuinely read-write mount on this EM (/shared/log and
    /shared/oslog are read-only bind-mounts of the same underlying
    filesystem -- "/shared/shared" is not a typo). If the bundle already
    lives on the EM this is a plain local move; otherwise the EM pulls
    it via scp (the same pre-shared root trust ssh_appliance already
    relies on -- confirmed live scp works identically) and deletes the
    source copy off the appliance afterward. Returns (new_path, new_
    commands_log, executed_commands) -- paths fall back to the originals
    if the move itself didn't actually land, confirmed by checking the
    destination file exists rather than trusting a zero exit code alone,
    so a centralization hiccup never hides an otherwise-successful build.

    case_dir: pre-resolved case directory name, when the caller already
    computed one (do_techsupport_collect, for its multi-target
    concurrent build -- see the concurrency comment there). Without
    this, each target's own call here would independently fall back to
    _case_dir_name(case_ref)'s adhoc-<timestamp> naming when case_ref is
    empty -- fine for a single sequential bundle, but confirmed live to
    genuinely scatter concurrent targets across DIFFERENT adhoc-<HHMMSS>
    folders (each thread's own call landing a few seconds apart), when
    they're really all part of the same one Proceed action and belong
    in the same case folder.

    The actual mkdir/mv/scp/rm executed below always matches
    _centralize_command_lines' returned command list exactly (each real
    call corresponds 1:1 to one of those display strings, in the same
    order) -- kept manually in sync rather than parsed back out of the
    strings, since the real calls need proper argv lists (ssh options,
    etc) that the simplified display strings deliberately omit for
    readability, same convention already used throughout this app (e.g.
    the debug-enable preview line doesn't show the ssh wrapper either).
    """
    if not path:
        return path, commands_log, []

    commands, dest_dir = _centralize_command_lines(
        plugin_target, path, commands_log, case_dir or _case_dir_name(case_ref)
    )
    files = [f for f in (path, commands_log) if f]

    run(["bash", "-c", commands[0]], timeout=15)  # mkdir -p
    if plugin_target == EM_IP:
        for f in files:
            run(["bash", "-c", f'mv "{f}" "{dest_dir}/"'], timeout=30)
    else:
        resolved_target = _resolve_target_host(plugin_target)
        for f in files:
            run(["scp", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                 "-o", "ConnectTimeout=10", f"root@{resolved_target}:{f}", f"{dest_dir}/"], timeout=60)
        ssh_appliance(plugin_target, "rm -f " + " ".join(f'"{f}"' for f in files), timeout=15)

    new_path = f"{dest_dir}/{os.path.basename(path)}"
    new_commands_log = f"{dest_dir}/{os.path.basename(commands_log)}" if commands_log else None
    check_out, _, check_rc = run(["bash", "-c", f'test -f "{new_path}" && echo ok'], timeout=15)
    if check_rc != 0 or "ok" not in check_out:
        return path, commands_log, commands
    return new_path, new_commands_log, commands


# David's ask, 2026-08-27: was hardcoded at 480s, independent of whatever
# timeout app.py's own collect_techsupport/build_techsupport_em callers
# used -- confirmed live on a still-settling appliance (fresh off a
# disconnect/reconnect) that `fstool tech-support` can genuinely run well
# past 8 minutes and still succeed; when it did, the bundle it produced
# was orphaned in /tmp on that box forever, since this SSH call had
# already given up and moved on. app.py's own outer SSH-response timeout
# is 3600s (see collect_techsupport/build_techsupport_em call sites) --
# staying comfortably under that (rather than matching it exactly) still
# leaves headroom for centralizing + splitting afterward.
TECH_SUPPORT_BUILD_TIMEOUT = 3300  # 55 minutes

SPLIT_THRESHOLD_BYTES = int(1.5 * 1024 * 1024 * 1024)  # 1.5GB
SPLIT_CHUNK_SIZE = "500M"


def _split_if_oversized(path):
    """
    David's ask: no centralized .tgz should be left larger than 1.5GB --
    split it into 500MB chunks (GNU split, binary M suffix) if it is.
    Always runs on the EM via run() (never ssh_appliance) -- David's
    "final step on the EM," since by the time this is called the bundle
    is already centralized onto /shared/shared. Checks the REAL file
    size via `stat -c%s` rather than trusting fstool's own reported
    "Size:" string (an approximate display value like "1.2 GB", not
    exact bytes -- not reliable enough to gate a real split decision on).
    The original un-split file is only removed once the chunks are
    confirmed to actually exist -- splitting is meant to REPLACE the
    oversized file, not risk losing it if the split itself failed.

    Returns (path, chunk_paths, executed_commands): if no split was
    needed, path is unchanged and chunk_paths is empty; if a split
    happened, path is None (nothing single left to point at) and
    chunk_paths holds every part, sorted.
    """
    if not path:
        return path, [], []
    size_out, _, size_rc = run(["bash", "-c", f'stat -c%s "{path}" 2>/dev/null'], timeout=15)
    try:
        size_bytes = int(size_out.strip())
    except ValueError:
        return path, [], []
    if size_rc != 0 or size_bytes <= SPLIT_THRESHOLD_BYTES:
        return path, [], []

    prefix = f"{path}.part-"
    split_cmd = f'split -b {SPLIT_CHUNK_SIZE} "{path}" "{prefix}"'
    executed = [split_cmd]
    run(["bash", "-c", split_cmd], timeout=180)

    list_out, _, _ = run(["bash", "-c", f'ls -1 "{prefix}"* 2>/dev/null'], timeout=15)
    chunk_paths = sorted(p for p in list_out.splitlines() if p.strip())
    if not chunk_paths:
        return path, [], executed  # split produced nothing -- leave the original alone, don't risk deleting it

    rm_cmd = f'rm -f "{path}"'
    executed.append(rm_cmd)
    run(["bash", "-c", rm_cmd], timeout=15)
    return None, chunk_paths, executed


def _build_combined_bundle(
    plugins, plugin_target, comment, case_ref, time_args, hostinfo_by_ip=None, databases=None, company=None,
    case_dir=None, send=False,
):
    """
    Runs ONE `fstool tech-support [-p <plugin>]... [--attach-file <f>]...
    [--dbtable <table>]... --pack` invocation on its own target box (EM
    or a specific appliance) -- confirmed live fstool genuinely supports
    repeating -p (multiple plugins in one snapshot, e.g. "-p sw -p va"),
    --attach-file (multiple files embedded in one archive, each under
    files/<original-path>), and --dbtable (documented under `fstool help
    tech-support`'s "Miscellaneous options"), so every plugin relevant to
    this target, every involved host's own hostinfo dump, and every
    requested table all land in a single bundle rather than one bundle
    per plugin -- David's explicit ask, so only one bundle needs building
    per appliance even when several hosts, plugins, or tables are
    involved. Tables come from get_databases (fstool's own `db
    diskspace` -- David's final word, 2026-08-26, after this went
    through a table-vs-whole-database detour the same day: it's tables,
    same as --dbtable always addressed, just fstool's own curated,
    size-ranked significant ones rather than every table in the schema).

    Writes a companion *-commands.txt summary next to the bundle (see
    _write_commands_summary) recording the exact command(s) run and the
    tool's own output, for debugging the collection process itself
    later, then centralizes both files onto the EM's shared case storage
    (see _centralize_bundle) rather than leaving them on whichever box
    happened to build them.

    plugins=[] (or None) omits -p entirely (fstool's own default category
    set) -- used for a general EM-wide bundle, where there's no host to
    derive a relevant-plugin list from in the first place (see
    do_techsupport_em). hostinfo_by_ip={} (or None) omits the hostinfo
    --attach-file entirely. databases=[] (or None) omits --dbtable
    entirely -- re-validated here against this target's OWN live `db
    diskspace` list (get_databases) before use, not just trusted from
    the caller, since which tables are significant enough to appear is
    genuinely per-box and a name valid elsewhere would otherwise fail
    this specific build outright. company: fstool's own -company value,
    David's ask 2026-08-26 -- an editable override for what used to be a
    hardcoded "Yubique"; defaults to DEFAULT_COMPANY when not given.
    send: fstool's own --send flag, David's ask 2026-08-26 -- "Send
    support bundle directly to Forescout." Confirmed live via `fstool
    help tech-support`: --send and --pack are both listed together
    under "Non interactive related options", not documented as mutually
    exclusive, so this ADDS --send alongside the existing --pack rather
    than replacing it -- --pack is what makes fstool actually produce
    the local archive this app's own File:/Size: parsing, centralize,
    and split logic all depend on; if --send alone dropped that, every
    downstream step here would break. This combined-flag behavior has
    NOT been live-fired (unlike everything else in this app, this one
    real-transmits data to Forescout's own external support servers,
    so it needs David's own explicit test, not an assistant-triggered
    one) -- confirm this actually behaves as expected before relying on
    it for a real case.
    """
    plugins = plugins or []
    hostinfo_by_ip = hostinfo_by_ip or {}
    company = company or DEFAULT_COMPANY
    # This function is only ever reached from real execution (never
    # preview), so TS_LOG_PATH logging below is unconditional -- gating
    # it on `if case_ref:` (an earlier cut of this) meant a genuine
    # Proceed run with no case reference typed produced ZERO new log
    # lines, leaving the popup showing whatever was last logged by an
    # unrelated earlier run and making a live build look like it had
    # already finished. log_tag is display-only (defaults to "adhoc"
    # when no case_ref was given) -- case_ref itself is left untouched
    # for everything else this function uses it for (the case
    # directory _centralize_bundle moves the bundle into, via its own
    # separate _case_dir_name timestamp fallback, and the "Case
    # reference: ..." line in the commands_log summary).
    log_tag = case_ref or "adhoc"
    db_mode = "em" if plugin_target == EM_IP else "appliance"
    db_appliance = None if plugin_target == EM_IP else plugin_target
    valid_table_names = {t["name"] for t in get_databases(db_mode, db_appliance)}
    databases = sorted(d for d in (databases or []) if d in valid_table_names)
    started_display = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    attach_paths = _attach_hostinfo_files(plugin_target, hostinfo_by_ip)
    plugin_flags = "".join(f"-p {p} " for p in plugins)
    attach_flags = "".join(f'--attach-file "{p}" ' for p in attach_paths)
    dbtable_flags = "".join(f"--dbtable {t} " for t in databases)
    send_flag = "--send " if send else ""
    ts_cmd = (
        f'fstool tech-support {plugin_flags}{attach_flags}{dbtable_flags}'
        f'-comment {comment} --pack {send_flag}-company "{company}" {time_args}'
    )
    _log_ts(log_tag, f"[{plugin_target}] {ts_cmd}")
    if plugin_target == EM_IP:
        out, err, rc = run(["bash", "-c", ts_cmd], timeout=TECH_SUPPORT_BUILD_TIMEOUT)
    else:
        out, err, rc = ssh_appliance(plugin_target, ts_cmd, timeout=TECH_SUPPORT_BUILD_TIMEOUT)
    text = out + err
    finished_display = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    m = re.search(r"File:\s*(\S+)", text)
    m_size = re.search(r"Size:\s*([0-9.]+\s*\w+)", text)
    path = m.group(1) if m else None
    _log_ts(
        log_tag,
        f"[{plugin_target}] -> {'ok' if rc == 0 and m else 'FAILED'}"
        + (f", file={m.group(1)}, size={m_size.group(1)}" if m and m_size else ""),
    )

    # Best-effort cleanup of the temp hostinfo files regardless of the
    # build's own outcome -- they're only ever needed as --attach-file
    # source paths for the one invocation above, already embedded inside
    # the resulting archive by the time this runs. --dbtable tables need
    # no such cleanup -- fstool reads them directly out of the database
    # itself, nothing temporary is written for them.
    if attach_paths:
        cleanup_cmd = "rm -f " + " ".join(f'"{p}"' for p in attach_paths)
        if plugin_target == EM_IP:
            run(["bash", "-c", cleanup_cmd], timeout=15)
        else:
            ssh_appliance(plugin_target, cleanup_cmd, timeout=15)

    commands_log = None
    if path:
        summary_lines = [
            "Tech-support bundle build log -- generated by the forescout-lookup webapp",
            f"Plugins: {', '.join(plugins) or '(general -- fstool default category set)'}",
            f"Hosts attached: {', '.join(sorted(hostinfo_by_ip.keys())) or '(none)'}",
            f"Tables attached (--dbtable): {', '.join(databases) or '(none)'}",
            f"Target box: {plugin_target}",
            f"Case reference: {case_ref or '(none)'}",
            f"Started:  {started_display}",
            f"Finished: {finished_display}",
            "",
        ] + (
            ["Hostinfo fetched fresh on this target box (run before the command below):"]
            + [f"  fstool hostinfo {ip}" for ip in sorted(hostinfo_by_ip.keys())]
            + [""]
            if hostinfo_by_ip else []
        ) + [
            "Collection command (run on the target box above):",
            f"  {ts_cmd}",
            "",
            f"Result: {'ok' if rc == 0 and m else 'FAILED'}",
            f"File: {m.group(1) if m else '(not reported)'}",
            f"Size: {m_size.group(1) if m_size else '(not reported)'}",
            "",
            "--- Full tool output ---",
            text,
        ]
        commands_log = _write_commands_summary(plugin_target, path, "\n".join(summary_lines))

    centralize_commands = []
    if path:
        path, commands_log, centralize_commands = _centralize_bundle(
            plugin_target, path, commands_log, case_ref, case_dir=case_dir
        )
        for c in centralize_commands:
            _log_ts(log_tag, c)

    # Final step, always on the EM -- David's ask, no centralized bundle
    # should be left over 1.5GB. Only meaningful once the bundle is
    # actually centralized (splitting it on whichever box built it,
    # before the move, would just mean scp-ing N files instead of 1 for
    # no benefit -- the size limit is about what's left sitting in
    # /shared/shared, not about the transfer itself).
    chunk_paths = []
    if path:
        path, chunk_paths, split_commands = _split_if_oversized(path)
        centralize_commands.extend(split_commands)
        for c in split_commands:
            _log_ts(log_tag, c)

    return {
        "plugins": plugins or ["general"], "target": plugin_target,
        "hosts": sorted(hostinfo_by_ip.keys()), "databases": databases,
        "ok": rc == 0 and bool(m), "path": path,
        "chunks": chunk_paths,
        "size": m_size.group(1) if m_size else None,
        "commands_log": commands_log,
        "centralize_commands": centralize_commands,
        "output_tail": text[-500:],
    }


def _group_plugins_by_target(ips_csv, selected_plugins=None, case_ref=None):
    """
    Shared by do_techsupport_preview and do_techsupport_collect --
    fetches each host's own hostinfo and merges every relevant (plugin,
    target) pair (see detect_plugins) into a per-target union across all
    given hosts, so two hosts sharing an appliance (or one host needing
    several plugins on the same box) collapse into one bundle for it.
    Read-only (no side effects besides the hostinfo fetch itself), so
    it's safe to call once for the preview and again, independently,
    when the user actually proceeds -- hostinfo could in principle
    differ slightly between the two calls; accepted as a simplification
    rather than trying to pin state between them.

    selected_plugins: optional {target: set(plugin)} restricting the
    detected set to only what's explicitly checked in the UI -- David's
    ask, plugin inclusion should default to nothing auto-selected rather
    than everything a host happens to touch (same reasoning as the old
    Debug panel's default-unchecked rows: "not all cases it will be
    necessary to set debug on for all plugins... therefore their log
    data will not need to be included in the tech-support bundles").
    Only ever narrows the real, detected set via intersection -- never
    injects a plugin that wasn't genuinely found on that host, so this
    parameter can't be used to smuggle in an arbitrary plugin name. A
    target left with zero plugins after filtering is dropped entirely --
    UNLESS it's some host's own managing appliance (see below), which
    always survives regardless of plugin selection.

    Each host's own hostinfo dump is attached to the bundle on that
    host's own managing appliance (or the EM if managed centrally),
    never to a target its plugins merely fan out to (e.g. crowdstrike
    resolving to the EM, or the switch plugin resolving to whichever
    appliance manages the switch a host connects through) -- confirmed
    with David: those aren't where the host itself lives, so attaching
    its hostinfo there would misrepresent the data's source.

    A bundle on a host's own managing appliance is now ALWAYS built,
    carrying its hostinfo, regardless of whether any selected plugin
    happens to resolve there too (reversed 2026-08-26 -- David's earlier
    call was the opposite, "only if a selected plugin lands there," but
    a real case -- host 10.1.110.149, own appliance 192.168.22.212, no
    checked plugin landing there since crowdstrike/sw both resolved
    elsewhere -- showed that left the host's own hostinfo with nowhere
    to go at all. Confirmed with David this is the standing rule now: an
    otherwise-empty own-appliance bundle (no -p, fstool's own default
    category set, same shape as the EM's general bundle) is exactly
    what's wanted, not a corner case to avoid).
    """
    ips = [ip.strip() for ip in ips_csv.split(",") if ip.strip()]
    plugins_by_target = {}
    hostinfo_by_target = {}
    verdict_by_ip = {}
    unresolved = []
    own_targets = set()
    for ip in ips:
        mode, appliance = get_assigned_to(ip)
        if mode is None:
            unresolved.append(ip)
            continue
        raw, err, rc = (run(["fstool", "hostinfo", ip], timeout=30) if mode == "em"
                         else ssh_appliance(appliance, f"fstool hostinfo {ip}", timeout=30))
        if case_ref:
            _log_ts(case_ref, f"[{EM_IP if mode == 'em' else appliance}] fstool hostinfo {ip}")
        fields = parse_hostinfo_lines(raw)
        verdict_by_ip[ip] = classify_wired_wireless(fields)
        # Hostinfo belongs with the bundle on the host's OWN managing
        # appliance -- attaching it to every fanned-out plugin target
        # (e.g. a plugin that only exists on the EM, or on the appliance
        # managing the switch a host connects through, neither of which
        # is where this host itself lives) would misrepresent where the
        # data actually came from. Always guaranteed a home now: the
        # host's own appliance always gets a bundle (see own_targets
        # below), so hostinfo always has somewhere real to attach.
        own_target = EM_IP if mode == "em" else appliance
        own_targets.add(own_target)
        plugins_by_target.setdefault(own_target, set())
        hostinfo_by_target.setdefault(own_target, {})[ip] = raw
        for plugin, plugin_targets in detect_plugins(fields, mode, appliance):
            for plugin_target in plugin_targets:
                plugins_by_target.setdefault(plugin_target, set()).add(plugin)

    if selected_plugins is not None:
        kept_targets = {}
        kept_hostinfo = {}
        for target, plugins in plugins_by_target.items():
            keep = plugins & selected_plugins.get(target, set())
            if keep or target in own_targets:
                kept_targets[target] = keep
                if target in hostinfo_by_target:
                    kept_hostinfo[target] = hostinfo_by_target[target]
        plugins_by_target, hostinfo_by_target = kept_targets, kept_hostinfo

    return ips, plugins_by_target, hostinfo_by_target, verdict_by_ip, unresolved


TARGET_PLUGIN_PAIR_RE = rf"{IP_RE}:{DEBUGSET_PLUGIN_RE}"
SELECTED_PLUGINS_RE = rf"(?:{TARGET_PLUGIN_PAIR_RE}(?:,{TARGET_PLUGIN_PAIR_RE})*|-|0)"


def _parse_selected_plugins(selected_plugins_token):
    """
    "-" -> None (no selection at all -- caller wants the full auto-
    detected set; not exercised by the real UI, which always sends an
    explicit dict, but kept for API completeness). "0" -> {} (David's
    ask, 2026-08-26: a deliberately EMPTY selection -- every plugin
    unchecked on purpose, e.g. a build that only attaches DB tables or
    collects a plain hostinfo-only bundle -- distinct from "-"/None:
    {} still runs the selected_plugins filter below, correctly zeroing
    out every target's plugin set rather than leaving it unfiltered).
    Otherwise "target:plugin,target:plugin,..." -> {target: set(plugin)}.
    Shape only, matches SELECTED_PLUGINS_RE already checked at the
    dispatch boundary.
    """
    if selected_plugins_token == "-":
        return None
    if selected_plugins_token == "0":
        return {}
    selected = {}
    for pair in selected_plugins_token.split(","):
        target, plugin = pair.split(":", 1)
        selected.setdefault(target, set()).add(plugin)
    return selected


TARGET_DBTABLE_PAIR_RE = rf"{IP_RE}:{DATABASE_NAME_RE.pattern[1:-1]}"
SELECTED_DBTABLES_RE = rf"(?:{TARGET_DBTABLE_PAIR_RE}(?:,{TARGET_DBTABLE_PAIR_RE})*|-)"


def _parse_selected_dbtables(selected_dbtables_token):
    """
    Same wire shape as _parse_selected_plugins -- "-" (none selected) or
    "target:database,target:database,..." -> {target: set(database)}.
    David's ask (2026-08-26, corrected from an earlier table-level
    design): attach whole databases (e.g. crowdstrike, tanium) to a
    build's bundle(s), per target since which databases exist genuinely
    differs per box. Internal names here still say "dbtable"/"database"
    interchangeably in a few spots (wire verb/parameter position kept
    stable rather than renaming every reference for a same-day
    correction) -- the VALUE flowing through is always a whole database
    name now, never a table name.
    """
    if selected_dbtables_token == "-":
        return {}
    selected = {}
    for pair in selected_dbtables_token.split(","):
        target, database = pair.split(":", 1)
        selected.setdefault(target, set()).add(database)
    return selected


def _debug_enable_cmd(plugin, level, minutes):
    """Same command shape run_debug_cmd actually executes -- kept as a separate, pure string-builder so the
    preview can show the exact command without running anything, and so it can never drift out of sync with
    what a real debug-enable call does."""
    return f"fstool {plugin} debug {level} {minutes}m"


def do_techsupport_preview(
    ips_csv, level, minutes, selected_plugins_token, selected_dbtables_token, company=None, send=False,
    case_ref=None,
):
    """
    Read-only -- computes and returns the exact command sequence
    do_techsupport_collect (plus the debug-enable app.py fires just
    before it) would run for the given hosts/level/minutes/case_ref,
    without executing anything beyond the read-only hostinfo fetch
    needed to know which plugins/targets are actually involved. David's
    ask: "review the commands that are going to be run on the appliance
    before going ahead." The real bundle filename doesn't exist yet at
    preview time (fstool generates it only once the build actually
    runs), so the collect/scp/rm lines show a "<bundle>" placeholder
    rather than a name that hasn't been created. Flags any plugin that
    already has a debug window active as informational only --
    proceeding will still enable debug and extend it; this doesn't block
    the preview or the build. selected_plugins_token: see
    _parse_selected_plugins -- "-" for the full auto-detected set.
    selected_dbtables_token: see _parse_selected_dbtables -- "-" for
    none requested, re-validated per target against that box's own live
    database list (get_databases) so the preview can't show a database
    dump that would actually get silently dropped at build time.
    company: fstool's own -company value, David's ask 2026-08-26 -- an
    editable override for what used to be a hardcoded "Yubique";
    defaults to DEFAULT_COMPANY when not given.
    """
    company = company or DEFAULT_COMPANY
    selected_plugins = _parse_selected_plugins(selected_plugins_token)
    selected_dbtables = _parse_selected_dbtables(selected_dbtables_token)
    ips, plugins_by_target, hostinfo_by_target, verdict_by_ip, unresolved = _group_plugins_by_target(
        ips_csv, selected_plugins
    )
    if not plugins_by_target:
        fail("no relevant plugins found for any of the given host(s)" +
             (f" (unresolved: {', '.join(unresolved)})" if unresolved else ""))

    case_dir = _case_dir_name(case_ref)
    duration = f"{minutes}m"
    now = int(time.time())
    targets_out = []
    for target, plugin_set in sorted(plugins_by_target.items()):
        plugins = sorted(plugin_set)
        target_mode = "em" if target == EM_IP else "appliance"
        already_active = []
        commands = []
        for plugin in plugins:
            until = get_debug_until(plugin, target_mode, target)
            if until > now:
                already_active.append(plugin)
            commands.append(_debug_enable_cmd(plugin, level, minutes))
        commands.append(f"wait {duration}")

        hostinfo_ips = sorted(hostinfo_by_target.get(target, {}).keys())
        # Explicit -- David's ask, 2026-08-26: the actual --attach-file
        # content doesn't just appear, it's a real `fstool hostinfo <ip>`
        # run fresh on THIS target after the wait above (confirmed live:
        # webapp-query.py is a fresh process per SSH call, so this is a
        # genuine post-wait fetch, not stale data reused from an earlier
        # preview) -- showing that step explicitly here, not just
        # implying it via the --attach-file placeholder, matches the
        # same "the preview must show the exact commands, not a hand-
        # waved approximation" principle Round 24 already fixed for the
        # EM preview's mkdir/mv drift.
        for ip in hostinfo_ips:
            commands.append(f"fstool hostinfo {ip}")
        valid_table_names = {t["name"] for t in get_databases(target_mode, None if target == EM_IP else target)}
        databases = sorted(d for d in selected_dbtables.get(target, set()) if d in valid_table_names)
        flag_parts = (
            [f"-p {p}" for p in plugins]
            + [f'--attach-file "<hostinfo-{ip}>"' for ip in hostinfo_ips]
            + [f"--dbtable {t}" for t in databases]
        )
        flags_prefix = "".join(f"{f} " for f in flag_parts)  # empty plugins+no hosts+no tables -> "" (own-
                                                              # appliance general bundle, fstool's default set)
        comment = case_ref or "webapp-multihost"
        send_flag = "--send " if send else ""
        commands.append(f'fstool tech-support {flags_prefix}-comment {comment} --pack {send_flag}-company "{company}" -t {duration}')

        centralize_commands, _ = _centralize_command_lines(target, "<bundle>.tgz", "<bundle>-commands.txt", case_dir)
        commands.extend(centralize_commands)

        targets_out.append({
            "target": target, "plugins": plugins, "hosts": hostinfo_ips,
            "already_debug_active": already_active, "commands": commands,
        })

    print(json.dumps({
        "ips": ips, "unresolved": unresolved, "verdicts": verdict_by_ip,
        "case_dir": case_dir, "targets": targets_out,
    }))


def do_techsupport_collect(
    ips_csv, minutes, selected_plugins_token, selected_dbtables_token, company=None, send=False, case_ref=None,
):
    """
    The collect phase of the debug-enable -> wait -> collect ->
    centralize sequence David asked for -- called by app.py AFTER it has
    already enabled debug on every relevant plugin (debugsetappliance,
    reusing the existing verb) and waited out the given duration itself.
    That wait deliberately does NOT happen inside this one SSH-invoked
    script -- a multi-hour blocking SSH call is fragile (one network
    blip loses the whole sequence); app.py's own background thread sleeps
    locally between the two separate calls instead. No debug-still-
    active refusal here (unlike the old single-shot design): this call's
    whole purpose is to collect exactly the debug-level data the caller
    just arranged, so an active window is expected, not a problem.
    selected_plugins_token: see _parse_selected_plugins -- must match
    whatever the caller's preceding debug-enable step actually used, so
    the collected bundle covers exactly what was enabled, no more.
    selected_dbtables_token: see _parse_selected_dbtables -- whole
    database dumps have no debug-enable step of their own, so this can
    differ freely from what preview_techsupport showed without
    affecting correctness. company: fstool's own -company value,
    David's ask 2026-08-26 -- defaults to DEFAULT_COMPANY when not given.
    """
    company = company or DEFAULT_COMPANY
    # Display-only fallback so a genuine collect run with no case
    # reference typed still logs to TS_LOG_PATH (see _build_combined_
    # bundle's own log_tag comment for why -- gating this on the bare
    # `case_ref` truthiness left no-case-ref runs completely silent in
    # the popup, which David caught live: a real run was still
    # "collecting" server-side but the popup showed an unrelated
    # earlier run's stale "finished" banner because nothing new had
    # ever been appended for it).
    log_tag = case_ref or "adhoc"
    selected_plugins = _parse_selected_plugins(selected_plugins_token)
    selected_dbtables = _parse_selected_dbtables(selected_dbtables_token)
    ips, plugins_by_target, hostinfo_by_target, verdict_by_ip, unresolved = _group_plugins_by_target(
        ips_csv, selected_plugins, case_ref=log_tag
    )
    if not plugins_by_target:
        fail("no relevant plugins found for any of the given host(s)" +
             (f" (unresolved: {', '.join(unresolved)})" if unresolved else ""))

    _log_ts(log_tag, f"=== techsupportcollect: {len(plugins_by_target)} target(s), hosts {ips} ===")

    # Each target's build is an independent `fstool tech-support`
    # invocation on its OWN box (EM or a specific appliance) -- nothing
    # about one target's build depends on another's, so running them
    # sequentially just adds up their durations for no reason. David's
    # ask, 2026-08-26: "the 3 sessions should be running concurrently"
    # (flagged as a known gap back on 2026-08-25, left sequential at the
    # time as a deliberately separate, riskier change -- now built).
    # subprocess.run releases the GIL while the child process runs, so
    # a plain thread per target genuinely overlaps their wall-clock
    # time rather than just interleaving CPU work. Order of `bundles`
    # in the response is kept stable (matching plugins_by_target's own
    # insertion order), not whichever thread happens to finish first.
    targets = list(plugins_by_target.items())
    # Resolved ONCE, before the concurrent builds start -- otherwise
    # each target's own _centralize_bundle call would independently
    # fall back to _case_dir_name(case_ref)'s adhoc-<timestamp> naming
    # when no case reference was given, and confirmed live (2026-08-26)
    # to genuinely land 3 concurrent targets in 3 DIFFERENT adhoc-
    # <HHMMSS> folders a few seconds apart -- one Proceed action's
    # bundles belong in one case folder regardless of whether a real
    # case_ref was typed.
    case_dir = _case_dir_name(case_ref)

    def _build_one(target, plugin_set):
        comment = case_ref or "webapp-multihost"
        return _build_combined_bundle(
            sorted(plugin_set), target, comment, case_ref, f"-t {minutes}m", hostinfo_by_target.get(target, {}),
            sorted(selected_dbtables.get(target, set())), company, case_dir=case_dir, send=send,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as executor:
        futures = [executor.submit(_build_one, target, plugin_set) for target, plugin_set in targets]
        bundles = [f.result() for f in futures]

    _log_ts(log_tag, f"=== techsupportcollect finished: {sum(1 for b in bundles if b['ok'])}/{len(bundles)} bundle(s) ok ===")
    print(json.dumps({"ips": ips, "verdicts": verdict_by_ip, "unresolved": unresolved, "bundles": bundles}))


def do_techsupport_window_appliance(target, start_epoch, end_epoch, plugins_csv, case_ref=None):
    """
    Appliance-addressed version of the historical-window tech-support
    bundle (both start and end already in the past by the time the
    caller reaches here -- the app decides that upstream, in
    /debugset's mode=window handling). Uses fstool's own
    "-t utc:<start> -t utc:<end>" range syntax against already-rotated
    logs, rather than live debug -- confirmed live (Aug 24 2026) that a
    10-minute window produces exactly "Since: <start> Until: <end>" in
    the tool's own output, older epoch first. Debug itself can never be
    backdated -- enabling it is a real configuration change to the
    plugin that only ever takes effect from the moment it's actually
    applied, which is exactly why a fully-past window falls back to
    this rather than trying to start debug at all.

    Same debug-still-active refusal as do_techsupport_multi, scoped to
    plugins_csv on a directly-addressed target rather than an
    auto-detected set resolved from a single host's IP. All plugins
    given collect in a single combined bundle for this one target (see
    _build_combined_bundle), same as the multi-host path.
    """
    mode, appliance = resolve_target(target)
    if mode is None:
        fail(f"'{target}' is not a known EM or managed appliance")
    installed = get_installed_plugins(mode, appliance)
    plugins = plugins_csv.split(",")
    for plugin in plugins:
        if plugin not in installed:
            fail(f"'{plugin}' is not an installed plugin on {target}")

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

    plugin_target = EM_IP if mode == "em" else appliance
    comment = f"webapp-{target.replace('.', '-')}-window" + (f"-{case_ref}" if case_ref else "")
    time_args = f"-t utc:{start_epoch} -t utc:{end_epoch}"
    bundle = _build_combined_bundle(plugins, plugin_target, comment, case_ref, time_args)

    print(json.dumps({"target": target, "window": {"start": start_epoch, "end": end_epoch}, "bundles": [bundle]}))


def do_techsupport_em(duration, company=None, send=False, case_ref=None):
    """
    A general, EM-wide tech-support bundle -- unlike do_techsupport_collect,
    there's no host to derive a relevant-plugin list from, so this runs
    fstool's own default category set (no -p) rather than guessing which
    plugins matter. Exists specifically so the EM can get the same
    "build tech-support bundle" + case-reference/directory-grouping
    treatment as a looked-up host, distinct from runshowerrors (do_run_
    show_errors) which is a deliberately ephemeral review snapshot that
    deletes itself -- the case-reference ask is about bundles that are
    actually kept, so it needs its own real, persisted build. company:
    fstool's own -company value, David's ask 2026-08-26 -- defaults to
    DEFAULT_COMPANY when not given.
    """
    comment = "webapp-em" + (f"-{case_ref}" if case_ref else "")
    log_tag = case_ref or "adhoc"
    _log_ts(log_tag, "=== techsupportem: general EM bundle ===")
    bundle = _build_combined_bundle(None, EM_IP, comment, case_ref, f"-t {duration}", company=company, send=send)
    _log_ts(log_tag, f"=== techsupportem finished: {'ok' if bundle['ok'] else 'FAILED'} ===")
    print(json.dumps({"target": EM_IP, "bundles": [bundle]}))


def do_techsupport_em_preview(duration, company=None, send=False, case_ref=None):
    """
    Read-only preview of exactly what do_techsupport_em would run --
    same reasoning as do_techsupport_preview for the host path (David's
    ask: review the commands before proceeding), added specifically
    because app.py's EM preview used to be hand-written text in a
    completely different file that had drifted out of sync with what
    actually runs (caught live 2026-08-25: wrong -comment value, missing
    mkdir -p, one combined mv line shown instead of the real two separate
    ones). The comment string here is intentionally copy-pasted from
    do_techsupport_em's own -- not shared via a helper, since it's one
    expression, but kept immediately next to it so a future change to
    one is hard to miss updating the other.
    """
    company = company or DEFAULT_COMPANY
    comment = "webapp-em" + (f"-{case_ref}" if case_ref else "")
    send_flag = "--send " if send else ""
    ts_cmd = f'fstool tech-support -comment {comment} --pack {send_flag}-company "{company}" -t {duration}'
    case_dir = _case_dir_name(case_ref)
    centralize_commands, _ = _centralize_command_lines(EM_IP, "<bundle>.tgz", "<bundle>-commands.txt", case_dir)
    commands = [ts_cmd] + centralize_commands
    print(json.dumps({
        "case_dir": case_dir,
        "targets": [{"target": EM_IP, "plugins": ["general"], "hosts": [], "already_debug_active": [], "commands": commands}],
    }))


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


# Was IP-only (r"^([\d.]+): Done in") -- real bug found live, 2026-08-28, on a customer
# environment (HSC Belfast) whose appliances are registered by DNS name, not IP: `fstool
# oneach` echoes back whatever identifier it targeted (a hostname like "belfscout01" there,
# not an IP), so the old pattern silently matched none of them -- every DNS-named appliance
# showed "offline" in the Appliances tab even though `fstool oneach` reached it fine, and
# get_all_targets() (same regex, used far more broadly -- debug-target selection, plugin
# detection) silently excluded every one of them too. That's the real root cause behind
# "fails to collect host data from the appliances" for DNS-named environments -- distinct
# from (and in addition to) the ssh_appliance/_resolve_target_host fix. Now matches any
# non-whitespace token before ": Done in", IP or hostname alike.
APPLIANCE_ONLINE_RE = re.compile(r"^([^\s:]+): Done in")


def do_appliances():
    """
    The EM itself, plus every appliance its own reg table knows about
    (get_node_map), with live online/offline status for the managed
    appliances from `fstool oneach -c -t 10 echo ok` -- confirmed live:
    a reachable appliance reports "<ip>: Done in Ns", an unreachable one
    reports "<ip>: Timeout" then "<ip>: Skipped." (this environment
    genuinely has two of the latter, 172.16.1.129/.130 -- confirmed not
    a bug, they just don't respond). `oneach` only ever targets the
    managed appliances, never the EM itself, so the EM is listed
    separately and always reported online -- if this code is running,
    the EM obviously is.
    """
    addresses = sorted(set(get_node_map().values()))
    out, err, rc = run(["fstool", "oneach", "-c", "-t", "10", "echo", "ok"], timeout=30)
    online = set(m.group(1) for m in (APPLIANCE_ONLINE_RE.match(line.strip()) for line in out.splitlines()) if m)
    appliances = [{"address": EM_IP, "online": True, "is_em": True}]
    appliances += [{"address": a, "online": a in online, "is_em": False} for a in addresses]
    print(json.dumps({"appliances": appliances}))


def _latest_snapshot_dir(mode, appliance):
    cmd = "ls -dt /tmp/snapshot.*/ 2>/dev/null | head -1"
    out, err, rc = (run(["bash", "-c", cmd], timeout=15) if mode == "em"
                     else ssh_appliance(appliance, cmd, timeout=15))
    line = out.strip().splitlines()[0].rstrip("/") if out.strip() else None
    return line


def _read_remote_file(mode, appliance, path):
    cmd = f"cat {path} 2>/dev/null"
    out, err, rc = (run(["bash", "-c", cmd], timeout=15) if mode == "em"
                     else ssh_appliance(appliance, cmd, timeout=15))
    return out.strip()


DIAG_CONTAINER_RE = re.compile(r'<div class="container">(.*)</div>\s*</body>', re.S)
DIAG_H2_ID_RE = re.compile(r'<h2 id="[^"]*">')
DIAG_LINK_RE = re.compile(r"<a\b[^>]*>(.*?)</a>", re.S | re.I)
DIAG_MARKER_RE = re.compile(r"##FSTOOL-DIAG-FILE##([^#\n]+)##\n?")


def _extract_html_fragment(html_text):
    """
    fstool's own per-topic .html reports (diag/*.html, errors/<category>/
    summary.html) are already clean semantic HTML -- one <div class=
    "container"> holding h2 section headings, explanatory <p> notes, and
    real <table class="table table-bordered"> markup, no external CSS/JS
    dependencies. Pulling that div's inner content straight out and
    dropping it into the app's own page (its table/th/td CSS applies
    globally by element, not by class, so it inherits the dark theme
    automatically) beats re-parsing the boxed-ASCII .txt sibling by hand
    -- confirmed live these come in pairs for every diag/*.txt file, and
    the .html is the tool's own rendering, not a guess at one. Strips the
    per-file h2 id="..." slugs since dozens of these get embedded on one
    page and duplicate ids are otherwise unavoidable. Also strips any
    <a>...</a> hyperlinks fstool's own renderer emits (e.g. local
    filesystem paths, internal anchors) -- David's ask, they point
    nowhere useful once pulled out of the appliance's own filesystem
    context, so the wrapper is dropped but the link's own text stays.
    """
    if not html_text:
        return None
    m = DIAG_CONTAINER_RE.search(html_text)
    if not m:
        return None
    fragment = DIAG_H2_ID_RE.sub("<h2>", m.group(1))
    fragment = DIAG_LINK_RE.sub(r"\1", fragment)
    return fragment.strip() or None


SNAPSHOT_STORED_RE = re.compile(r"Snapshot stored at (\S+)")


def do_run_show_errors(target, duration):
    """
    Runs `fstool tech-support -t <duration> --review --show-errors` on
    the target -- confirmed live this is a real, unscoped (no -p) full-
    category snapshot, not a quick check: it runs for several minutes
    and, for "Collecting Java processes stack traces" specifically,
    spawns one worker per running JVM on the box. The caller (app.py)
    runs this in a background thread and polls rather than blocking a
    request on it.

    Confirmed live the tool prints "Snapshot stored at <path>" and its
    own "Errors Summary Table" at the very end -- parsed directly from
    that output rather than guessed (a "newest /tmp/snapshot.*" heuristic
    would be fragile if something else on the box happens to create one
    at the same time). Reads the top-level errors/summary.txt (the same
    overview table -- no .html sibling exists for this one, confirmed
    live) plus every errors/<category>/summary.html for detail (e.g.
    "local-patches/summary.html" behind "Detected 22 local patches"),
    plus every diag/*.txt file's .html sibling (diag/cpu.txt ->
    diag/cpu.html, etc) -- confirmed live every diag/*.txt has one.
    Diag files are read in one batched remote command (not one `cat` per
    file) since a real run has 30+ of them and each remote call is its
    own SSH round-trip when the target is an appliance, not the EM.

    Deletes the snapshot directory afterwards (confirmed live: a single
    run was 80MB) -- unlike the tech-support-bundle/historical-window
    verbs, which deliberately leave their .tgz for manual retrieval, this
    one exists purely for the live on-screen review; nothing here is
    meant to be picked up later, so nothing is worth leaving behind.
    """
    mode, appliance = resolve_target(target)
    if mode is None:
        fail(f"'{target}' is not a known EM or managed appliance")

    cmd = f"fstool tech-support -t {duration} --review --show-errors"
    out, err, rc = (run(["bash", "-c", cmd], timeout=1200) if mode == "em"
                     else ssh_appliance(appliance, cmd, timeout=1200))
    text = out + err

    m = SNAPSHOT_STORED_RE.search(text)
    snapshot_dir = m.group(1) if m else _latest_snapshot_dir(mode, appliance)

    overview = None
    categories = []
    diag_files = []
    if snapshot_dir:
        overview = _read_remote_file(mode, appliance, f"{snapshot_dir}/errors/summary.txt") or None

        list_cmd = f"find {snapshot_dir}/errors -mindepth 2 -maxdepth 2 -name summary.html 2>/dev/null"
        lout, lerr, lrc = (run(["bash", "-c", list_cmd], timeout=15) if mode == "em"
                            else ssh_appliance(appliance, list_cmd, timeout=15))
        for path in lout.splitlines():
            path = path.strip()
            if not path:
                continue
            category = path.split("/")[-2]
            categories.append({
                "category": category,
                "html": _extract_html_fragment(_read_remote_file(mode, appliance, path)),
            })

        diag_list_cmd = f"find {snapshot_dir}/diag -maxdepth 1 -name '*.txt' 2>/dev/null | sort"
        dlout, dlerr, dlrc = (run(["bash", "-c", diag_list_cmd], timeout=15) if mode == "em"
                                else ssh_appliance(appliance, diag_list_cmd, timeout=15))
        diag_names = [os.path.basename(p.strip())[:-4] for p in dlout.splitlines() if p.strip()]
        if diag_names:
            batch_cmd = "; ".join(
                f'echo "##FSTOOL-DIAG-FILE##{name}##"; cat "{snapshot_dir}/diag/{name}.html" 2>/dev/null'
                for name in diag_names
            )
            bout, berr, brc = (run(["bash", "-c", batch_cmd], timeout=30) if mode == "em"
                                else ssh_appliance(appliance, batch_cmd, timeout=30))
            chunks = DIAG_MARKER_RE.split(bout)[1:]
            for name, content in zip(chunks[0::2], chunks[1::2]):
                frag = _extract_html_fragment(content)
                if frag:
                    diag_files.append({"filename": name + ".txt", "html": frag})

        # Lock file is "<dir>/.snapshot....lock" (dot-prefixed hidden
        # file), not "<dir>.lock" -- confirmed live in the same /tmp
        # listing that showed the snapshot dir itself.
        cleanup_cmd = f'D="{snapshot_dir}"; rm -rf "$D" "$(dirname "$D")/.$(basename "$D").lock" 2>/dev/null'
        if mode == "em":
            run(["bash", "-c", cleanup_cmd], timeout=30)
        else:
            ssh_appliance(appliance, cleanup_cmd, timeout=30)

    print(json.dumps({
        "target": target, "ok": rc == 0, "snapshot_dir": snapshot_dir,
        "overview": overview, "categories": categories, "diag_files": diag_files,
        "output_tail": text[-1500:],
    }))


def main():
    original = os.environ.get("SSH_ORIGINAL_COMMAND", "")

    m = re.fullmatch(rf"lookup ({IP_RE})", original.strip())
    if m:
        return do_lookup(m.group(1))

    m = re.fullmatch(
        rf"debugsetappliance ({IP_RE}) ({DEBUGSET_SPEC_RE}) ({CASE_REF_RE.pattern[1:-1]})", original.strip(),
    )
    if m:
        return do_debugsetappliance(m.group(1), m.group(2), None if m.group(3) == "-" else m.group(3))

    m = re.fullmatch(rf"tracelist ({IP_RE})", original.strip())
    if m:
        return do_tracelist(m.group(1))

    m = re.fullmatch(rf"tracedefaults ({IP_RE})", original.strip())
    if m:
        return do_tracedefaults(m.group(1))

    m = re.fullmatch(rf"traceset ({IP_RE}) ({TRACE_CHANGES_RE})", original.strip())
    if m:
        return do_traceset(m.group(1), m.group(2))

    if original.strip() == "appliances":
        return do_appliances()

    m = re.fullmatch(rf"runshowerrors ({IP_RE}) (\d{{1,4}}[mh])", original.strip())
    if m:
        return do_run_show_errors(m.group(1), m.group(2))

    if original.strip() == "techsupportlogtail":
        return do_techsupport_log_tail()

    if original.strip() == "techsupportlogclear":
        return do_techsupport_log_clear()

    m = re.fullmatch(
        r"techsupportdownload (/shared/shared/case/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)",
        original.strip(),
    )
    if m:
        return do_techsupport_download(m.group(1))

    m = re.fullmatch(
        r"techsupportcleanup (/shared/shared/case/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)",
        original.strip(),
    )
    if m:
        return do_techsupport_cleanup(m.group(1))

    # Trailing case-reference token is always present -- "-" means none,
    # since making it a genuinely optional trailing group made the two
    # verbs' patterns ambiguous to match unambiguously against a plain
    # space-separated command string. One or more comma-separated IPs --
    # both verbs group their relevant plugins by target box themselves,
    # so a single host is just the n=1 case.
    m = re.fullmatch(
        rf"techsupportpreview ({IP_RE}(?:,{IP_RE})*) ({DEBUGSET_LEVEL_RE}) (\d{{1,4}}) "
        rf"({SELECTED_PLUGINS_RE}) ({SELECTED_DBTABLES_RE}) ({COMPANY_TOKEN_RE}) ([01]) ({CASE_REF_RE.pattern[1:-1]})",
        original.strip(),
    )
    if m:
        return do_techsupport_preview(
            m.group(1), m.group(2), int(m.group(3)), m.group(4), m.group(5),
            None if m.group(6) == "-" else m.group(6), m.group(7) == "1",
            None if m.group(8) == "-" else m.group(8),
        )

    m = re.fullmatch(
        rf"techsupportcollect ({IP_RE}(?:,{IP_RE})*) (\d{{1,4}}) ({SELECTED_PLUGINS_RE}) "
        rf"({SELECTED_DBTABLES_RE}) ({COMPANY_TOKEN_RE}) ([01]) ({CASE_REF_RE.pattern[1:-1]})",
        original.strip(),
    )
    if m:
        return do_techsupport_collect(
            m.group(1), int(m.group(2)), m.group(3), m.group(4),
            None if m.group(5) == "-" else m.group(5), m.group(6) == "1",
            None if m.group(7) == "-" else m.group(7),
        )

    m = re.fullmatch(
        rf"techsupportwindowappliance ({IP_RE}) (\d{{1,10}}):(\d{{1,10}}) "
        rf"({DEBUGSET_PLUGIN_RE}(?:,{DEBUGSET_PLUGIN_RE})*) ({CASE_REF_RE.pattern[1:-1]})",
        original.strip(),
    )
    if m:
        return do_techsupport_window_appliance(
            m.group(1), int(m.group(2)), int(m.group(3)), m.group(4),
            None if m.group(5) == "-" else m.group(5),
        )

    m = re.fullmatch(
        rf"techsupportempreview (\d{{1,4}}[mh]) ({COMPANY_TOKEN_RE}) ([01]) ({CASE_REF_RE.pattern[1:-1]})",
        original.strip(),
    )
    if m:
        return do_techsupport_em_preview(
            m.group(1), None if m.group(2) == "-" else m.group(2), m.group(3) == "1",
            None if m.group(4) == "-" else m.group(4),
        )

    m = re.fullmatch(
        rf"techsupportem (\d{{1,4}}[mh]) ({COMPANY_TOKEN_RE}) ([01]) ({CASE_REF_RE.pattern[1:-1]})", original.strip(),
    )
    if m:
        return do_techsupport_em(
            m.group(1), None if m.group(2) == "-" else m.group(2), m.group(3) == "1",
            None if m.group(4) == "-" else m.group(4),
        )

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
        "(lookup <ip> | debugsetappliance <target> <plugin:level:minutes,...> <case_ref> | "
        "tracelist <target> | tracedefaults <target> | traceset <target> <category:on|off:level,...> | "
        "techsupportpreview <ip,ip,...> <level> <minutes> <selected_plugins> <selected_dbtables> <company> "
        "<send> <case_ref> | "
        "techsupportcollect <ip,ip,...> <minutes> <selected_plugins> <selected_dbtables> <company> <send> "
        "<case_ref> | "
        "techsupportwindowappliance <target> <start>:<end> <plugin,...> <case_ref> | "
        "techsupportempreview <N>m|h <company> <send> <case_ref> | techsupportem <N>m|h <company> <send> <case_ref> | "
        "techsupportlogtail | techsupportlogclear | "
        "techsupportdownload </shared/shared/case/.../.../...> | "
        "techsupportcleanup </shared/shared/case/.../.../...> | "
        "policytree | "
        "lastchecked <ip> | matched <ip> <N>h|d|w | history <ip> <N>h|d|w | rawfields <ip> | "
        "arplist <ip> | appliances | runshowerrors <target> <N>m|h)",
        code=2,
    )


if __name__ == "__main__":
    main()
