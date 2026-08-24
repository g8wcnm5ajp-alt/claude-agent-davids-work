"""
forescout_client.py

Talks to the EM (192.168.22.210) via the restricted SSH key set up for
this app -- never touches an appliance directly. The EM-side forced-
command wrapper (webapp-query/webapp-query.py in this repo, deployed at
/root/scripts/webapp-query/webapp-query.py on the EM) is the only thing
that key is allowed to run; every call here maps to one of its verbs
(lookup, debugset, techsupport, policytree, lastchecked, matched,
history, rawfields, arplist) and gets back one line of JSON.
"""
import json
import os
import re
import subprocess

EM_HOST = os.environ.get("FORESCOUT_EM_HOST", "192.168.22.210")
SSH_KEY_PATH = os.environ.get("FORESCOUT_SSH_KEY", "/keys/webapp_query_rsa")

IP_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
IP_RE = re.compile(rf"^{IP_OCTET}(?:\.{IP_OCTET}){{3}}$")


class ForescoutClientError(Exception):
    """Raised for anything the UI should show as a clean error message."""


def valid_ip(ip):
    return bool(IP_RE.match(ip or ""))


def _run_verb(verb_command, timeout):
    if not os.path.isfile(SSH_KEY_PATH):
        raise ForescoutClientError(
            f"SSH key not found at {SSH_KEY_PATH} -- the container's key volume isn't mounted correctly."
        )
    cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10", "-i", SSH_KEY_PATH, f"root@{EM_HOST}", verb_command,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ForescoutClientError(f"Request to the EM timed out after {timeout}s.")
    except FileNotFoundError:
        raise ForescoutClientError("ssh is not available in this container.")

    if not p.stdout.strip():
        detail = p.stderr.strip() or f"exit code {p.returncode}"
        raise ForescoutClientError(f"No response from the EM ({detail}).")

    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise ForescoutClientError(f"Unexpected (non-JSON) response from the EM: {p.stdout[:300]}")

    if "error" in data:
        raise ForescoutClientError(data["error"] if not data.get("still_active") else _format_still_active(data))
    return data


def _format_still_active(data):
    parts = [f"{e['plugin']} ({e['seconds_remaining']}s remaining)" for e in data.get("still_active", [])]
    return "Debug still active on: " + ", ".join(parts) + ". Wait for it to finish before building a bundle."


def lookup(ip, timeout=45):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    return _run_verb(f"lookup {ip}", timeout=timeout)


# Shape only (safe plugin-name charset) -- which plugin names are real is
# a live, per-deployment fact only the EM's own wrapper can check (see
# get_installed_plugins there); this layer just blocks garbage before it
# ever reaches SSH.
DEBUGSET_ITEM_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}:(?:[0-9]|1[0-2]):\d{1,4}$")


def debug_set(ip, spec, timeout=45):
    """
    spec: comma-separated "<plugin>:<level>:<minutes>" triples, already
    built by the caller from the UI's per-plugin checkbox/level/duration
    controls. Shape-validated here (defense in depth -- the EM's own
    wrapper re-validates independently, including whether each plugin is
    actually installed) before ever reaching SSH.
    """
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    items = [i for i in (spec or "").split(",") if i]
    if not items or not all(DEBUGSET_ITEM_RE.match(i) for i in items):
        raise ForescoutClientError("Invalid debug configuration.")
    for i in items:
        minutes = int(i.split(":")[2])
        if not (1 <= minutes <= 1440):
            raise ForescoutClientError("Duration must be between 1 and 1440 minutes (24h).")
    return _run_verb(f"debugset {ip} {spec}", timeout=timeout)


def build_techsupport(ip, timeout=480):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    return _run_verb(f"techsupport {ip}", timeout=timeout)


PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")


def build_techsupport_window(ip, start_epoch, end_epoch, plugins, timeout=480):
    """
    Used when a requested debug-capture window is entirely in the past --
    debug can't be backdated, so this pulls from already-rotated logs
    instead via fstool's own -t utc:X -t utc:Y range (confirmed live).
    """
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    if not (isinstance(start_epoch, int) and isinstance(end_epoch, int) and 0 < start_epoch < end_epoch):
        raise ForescoutClientError("Invalid time window.")
    if not plugins or not all(PLUGIN_NAME_RE.match(p) for p in plugins):
        raise ForescoutClientError("Invalid plugin selection.")
    return _run_verb(f"techsupportwindow {ip} {start_epoch}:{end_epoch} {','.join(plugins)}", timeout=timeout)


def raw_fields(ip, timeout=45):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    return _run_verb(f"rawfields {ip}", timeout=timeout)


def arp_list(ip, timeout=20):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    return _run_verb(f"arplist {ip}", timeout=timeout)


def policy_tree(timeout=30):
    return _run_verb("policytree", timeout=timeout)


def last_checked(ip, timeout=20):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    return _run_verb(f"lastchecked {ip}", timeout=timeout)


WINDOW_RE = re.compile(r"^\d{1,4}[hdw]$")


def matched_rules(ip, window, timeout=30):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    if not WINDOW_RE.match(window or ""):
        raise ForescoutClientError(f"'{window}' is not a valid window (expected e.g. 24h, 3d, 2w).")
    return _run_verb(f"matched {ip} {window}", timeout=timeout)


def policy_history(ip, window, timeout=30):
    if not valid_ip(ip):
        raise ForescoutClientError(f"'{ip}' is not a valid IPv4 address.")
    if not WINDOW_RE.match(window or ""):
        raise ForescoutClientError(f"'{window}' is not a valid window (expected e.g. 24h, 3d, 2w).")
    return _run_verb(f"history {ip} {window}", timeout=timeout)
