"""
forescout-lookup -- single/multi-IP Forescout host lookup web app.

No database, no session state -- every request is a live query through
the restricted EM key (see forescout_client.py). Renders whatever the
EM's wrapper returns; never assumes success.
"""
import json
import os
import re
import threading
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, redirect, render_template, request, url_for

from forescout_client import (
    ForescoutClientError, arp_list, build_techsupport, build_techsupport_window, debug_set,
    last_checked, lookup, matched_rules, policy_history, policy_tree, raw_fields,
)

app = Flask(__name__)

_tree_cache = {"tree": None}

# Same shape check as the EM wrapper's own plugin-name validation -- the
# plugin set is dynamic per host (detected server-side from real hostinfo
# data), not a fixed list, so this route reads whichever include_<plugin>
# fields the form actually submitted rather than a hardcoded tuple.
PLUGIN_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")

# A pasted "IP,IP,IP..." could in principle fan out into an unbounded
# number of SSH round trips through the EM -- capped as a sanity limit,
# not confirmed with David as the right number.
MAX_LOOKUP_IPS = 10


# ---------------------------------------------------------------------
# Scheduled (future-start) debug -- fstool itself has no native delayed
# start (confirmed live: "fstool tech-support debug" only accepts a
# duration counted from now), so a genuinely future-dated start has to be
# implemented here. A self-rolled JSON-file job queue + a background
# polling thread, rather than pulling in a scheduler library (APScheduler
# + SQLAlchemy) -- fewer moving parts to trust for something that fires
# real config changes against a live NAC system, and no dependency on a
# library's own persistence/pickling behaviour surviving this container
# being redeployed (which happens often in a single work session).
# Persisted under /data (bind-mounted by start.sh) specifically so a
# pending job survives exactly that kind of redeploy.
# ---------------------------------------------------------------------
DATA_DIR = os.environ.get("FORESCOUT_DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)
JOBS_PATH = os.path.join(DATA_DIR, "scheduled_debug_jobs.json")
LOG_PATH = os.path.join(DATA_DIR, "scheduled_debug_log.jsonl")

_jobs_lock = threading.Lock()


def _load_jobs():
    if not os.path.isfile(JOBS_PATH):
        return []
    try:
        with open(JOBS_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def _save_jobs(jobs):
    tmp = JOBS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(jobs, f)
    os.replace(tmp, JOBS_PATH)


def schedule_debug_job(ip, spec, start_epoch):
    """Persists a pending future debug start; _scheduler_loop picks it up once start_epoch arrives."""
    with _jobs_lock:
        jobs = _load_jobs()
        job_id = f"{int(time.time() * 1000)}-{os.urandom(3).hex()}"
        jobs.append({"id": job_id, "ip": ip, "spec": spec, "start_epoch": start_epoch, "created_at": int(time.time())})
        _save_jobs(jobs)
    return job_id


def cancel_debug_job(job_id):
    with _jobs_lock:
        jobs = _load_jobs()
        remaining = [j for j in jobs if j["id"] != job_id]
        removed = len(remaining) != len(jobs)
        _save_jobs(remaining)
    return removed


def _spec_display(spec):
    """"sw:4:60,dot1x:4:60" -> "sw@4 (60m), dot1x@4 (60m)" -- human display for the pending-jobs card."""
    parts = []
    for item in spec.split(","):
        plugin, level, minutes = item.split(":")
        parts.append(f"{plugin}@{level} ({minutes}m)")
    return ", ".join(parts)


def get_pending_jobs():
    with _jobs_lock:
        jobs = _load_jobs()
    jobs.sort(key=lambda j: j["start_epoch"])
    # UTC explicitly, not the container's or browser's local time -- avoids
    # a mismatch between whatever timezone this container happens to run
    # in and whatever the browser used to compute the epoch in the first
    # place. Unambiguous either way.
    for j in jobs:
        j["start_display"] = datetime.fromtimestamp(j["start_epoch"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        j["spec_display"] = _spec_display(j["spec"])
    return jobs


def _fire_job(job):
    """Runs at (or shortly after) the scheduled start time -- fires the exact same debug_set() the interactive
    "Start debug" button uses. Outcome is appended to LOG_PATH since nothing is watching a background thread's
    return value; David can check whether it actually fired correctly after the fact."""
    entry = {"fired_at": int(time.time()), "ip": job["ip"], "spec": job["spec"], "job_id": job["id"]}
    try:
        entry["result"] = debug_set(job["ip"], job["spec"])
        entry["ok"] = True
    except ForescoutClientError as e:
        entry["ok"] = False
        entry["error"] = str(e)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _scheduler_loop():
    """Background poller, checked every 15s -- not a precision scheduler (a job can fire up to ~15s late), fine
    for a debug window measured in minutes/hours."""
    while True:
        now = int(time.time())
        with _jobs_lock:
            jobs = _load_jobs()
            due = [j for j in jobs if j["start_epoch"] <= now]
            remaining = [j for j in jobs if j["start_epoch"] > now]
            if due:
                _save_jobs(remaining)
        for job in due:
            _fire_job(job)
        time.sleep(15)


threading.Thread(target=_scheduler_loop, daemon=True).start()


def render(**kwargs):
    """render_template wrapper that always carries the pending-scheduled-jobs list, regardless of which
    action's route is rendering -- it's global state, not tied to any one lookup."""
    kwargs.setdefault("ip", "")
    kwargs.setdefault("results", [])
    kwargs.setdefault("result", None)
    kwargs.setdefault("error", None)
    kwargs.setdefault("action", None)
    kwargs["scheduled_jobs"] = get_pending_jobs()
    return render_template("index.html", **kwargs)


@app.route("/", methods=["GET"])
def index():
    return render()


@app.route("/lookup", methods=["POST"])
def do_lookup():
    """
    Accepts one IP or a comma-separated list. Each is looked up
    independently -- one failing doesn't block the rest -- and the page
    renders one full result section per IP.
    """
    ip_raw = request.form.get("ip", "").strip()
    ips = [p.strip() for p in ip_raw.split(",") if p.strip()]
    error = None
    results = []
    if len(ips) > MAX_LOOKUP_IPS:
        error = f"Too many IPs ({len(ips)}) -- limit is {MAX_LOOKUP_IPS} per lookup."
    else:
        for ip in ips:
            try:
                results.append({"ip": ip, "result": lookup(ip), "error": None})
            except ForescoutClientError as e:
                results.append({"ip": ip, "result": None, "error": str(e)})
    return render(ip=ip_raw, results=results, error=error, action="lookup")


def _checked_plugins():
    """Plugins whose checkbox was ticked in the debug config table's submitted form."""
    plugins = []
    for key, value in request.form.items():
        if not key.startswith("include_") or value != "1":
            continue
        plugin = key[len("include_"):]
        if PLUGIN_NAME_RE.match(plugin):
            plugins.append(plugin)
    return plugins


@app.route("/debugset", methods=["POST"])
def do_debugset():
    """
    Builds the "<plugin>:<level>:<minutes>" spec from the per-plugin
    checkbox/level/duration controls in the Actions card -- only plugins
    with their checkbox ticked are included at all. mode=start uses each
    plugin's configured level/minutes; mode=stop ignores those and forces
    level=0/minutes=1 on the same checked plugins, immediately -- both
    always take effect right away regardless of time_mode.

    time_mode=window additionally accepts a shared start_epoch/end_epoch
    (computed client-side from the browser's local timezone) that applies
    to every checked plugin. A debug level is a real configuration change
    to the plugin -- it can never be backdated, only ever take effect from
    whenever it's actually applied -- so mode=start with time_mode=window
    splits three ways:
      - end <= now: fully in the past -- no live debug at all, builds a
        tech-support bundle scoped to that exact historical window instead
        (fstool's own -t utc:X -t utc:Y, confirmed live against
        already-rotated logs).
      - start <= now < end: starts immediately, runs until end_epoch (the
        already-elapsed start..now portion can't be recovered).
      - start > now: genuinely delayed -- persisted via schedule_debug_job
        to fire debug_set() at start_epoch, running for (end - start).
    """
    ip = request.form.get("ip", "").strip()
    mode = request.form.get("mode", "start")
    time_mode = request.form.get("time_mode", "duration")
    plugins = _checked_plugins()

    if not plugins:
        return render(ip=ip, error="No plugins selected.", action="debugset")

    if mode == "stop" or time_mode == "duration":
        duration_minutes = request.form.get("duration_minutes", "60").strip()
        items = []
        for plugin in plugins:
            if mode == "stop":
                items.append(f"{plugin}:0:1")
            else:
                level = request.form.get(f"level_{plugin}", "4").strip()
                items.append(f"{plugin}:{level}:{duration_minutes}")
        result, error = None, None
        try:
            result = debug_set(ip, ",".join(items))
        except ForescoutClientError as e:
            error = str(e)
        return render(ip=ip, result=result, error=error, action="debugset")

    # time_mode == "window", mode == "start"
    try:
        start_epoch = int(request.form.get("start_epoch", "").strip())
        end_epoch = int(request.form.get("end_epoch", "").strip())
    except ValueError:
        return render(ip=ip, error="Invalid start/end time.", action="debugset")
    if end_epoch <= start_epoch:
        return render(ip=ip, error="End time must be after start time.", action="debugset")

    now = int(time.time())
    result, error = None, None

    if end_epoch <= now:
        try:
            result = build_techsupport_window(ip, start_epoch, end_epoch, plugins)
        except ForescoutClientError as e:
            error = str(e)
        return render(ip=ip, result=result, error=error, action="techsupport")

    if start_epoch <= now:
        minutes = max(1, (end_epoch - now + 59) // 60)
        items = [f"{p}:{request.form.get(f'level_{p}', '4').strip()}:{minutes}" for p in plugins]
        try:
            result = debug_set(ip, ",".join(items))
        except ForescoutClientError as e:
            error = str(e)
        return render(ip=ip, result=result, error=error, action="debugset")

    # start_epoch > now: genuinely scheduled.
    minutes = max(1, (end_epoch - start_epoch + 59) // 60)
    items = [f"{p}:{request.form.get(f'level_{p}', '4').strip()}:{minutes}" for p in plugins]
    spec = ",".join(items)
    job_id = schedule_debug_job(ip, spec, start_epoch)
    result = {
        "ip": ip, "job_id": job_id, "start_epoch": start_epoch, "end_epoch": end_epoch, "spec": spec,
        "start_display": datetime.fromtimestamp(start_epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "end_display": datetime.fromtimestamp(end_epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    return render(ip=ip, result=result, action="debugscheduled")


@app.route("/scheduled/cancel", methods=["POST"])
def cancel_scheduled():
    job_id = request.form.get("job_id", "").strip()
    cancel_debug_job(job_id)
    return redirect(url_for("index"))


@app.route("/api/policytree", methods=["GET"])
def api_policy_tree():
    """
    Fetched once by the page's JS and cached client-side -- the tree
    structure changes rarely, unlike the per-IP highlight, which is
    polled separately and cheaply via /api/lastchecked.
    """
    if _tree_cache["tree"] is None:
        try:
            _tree_cache["tree"] = policy_tree()
        except ForescoutClientError as e:
            return jsonify({"error": str(e)}), 502
    return jsonify(_tree_cache["tree"])


@app.route("/api/lastchecked/<ip>", methods=["GET"])
def api_last_checked(ip):
    """Just the current last-checked rule_id(s) -- used for the initial tree highlight."""
    try:
        return jsonify(last_checked(ip))
    except ForescoutClientError as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/rawfields/<ip>", methods=["GET"])
def api_raw_fields(ip):
    """
    Lazy-loaded by the UI (a "Load raw fields" button, not automatic) --
    this is the full property dump, 1000+ fields on a busy host, too
    much to bundle into every normal lookup.
    """
    try:
        return jsonify(raw_fields(ip))
    except ForescoutClientError as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/history/<ip>", methods=["GET"])
def api_history(ip):
    """Drives the Policy match history table's adjustable time period (?window=24h / 3d / 2w)."""
    window = request.args.get("window", "24h")
    try:
        return jsonify(policy_history(ip, window))
    except ForescoutClientError as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/matched/<ip>", methods=["GET"])
def api_matched(ip):
    """
    Drives the tree's "show only matched & enabled" filter window
    (?window=24h / 3d / 2w). A real time-bounded EM query each time the
    window changes, not a client-side filter over already-truncated data.
    """
    window = request.args.get("window", "24h")
    try:
        return jsonify(matched_rules(ip, window))
    except ForescoutClientError as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/arplist/<ip>", methods=["GET"])
def api_arp_list(ip):
    """Lightweight ARP/MAC-vendor decode poll -- drives the ARP decode table's auto-refresh."""
    try:
        return jsonify(arp_list(ip))
    except ForescoutClientError as e:
        return jsonify({"error": str(e)}), 502


@app.route("/techsupport", methods=["POST"])
def do_techsupport():
    ip = request.form.get("ip", "").strip()
    result, error = None, None
    try:
        result = build_techsupport(ip)
    except ForescoutClientError as e:
        error = str(e)
    return render(ip=ip, result=result, error=error, action="techsupport")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
