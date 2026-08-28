"""
forescout-lookup -- single/multi-IP Forescout host lookup web app.

No database, no session state -- every request is a live query through
the restricted EM key (see forescout_client.py). Renders whatever the
EM's wrapper returns; never assumes success.
"""
import io
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import threading
import time
import zipfile
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from forescout_client import (
    CASE_REF_RE, COMPANY_NAME_RE, LEVEL_RE, ForescoutClientError, arp_list, build_techsupport_em,
    build_techsupport_window_appliance, clear_techsupport_log, collect_techsupport, debug_set_appliance,
    delete_techsupport_bundle, download_techsupport_bundle, last_checked, list_appliances, lookup,
    matched_rules, policy_history, policy_tree, preview_techsupport, preview_techsupport_em, raw_fields,
    run_show_errors, tail_techsupport_log, trace_defaults, trace_list, trace_set,
)

app = Flask(__name__)

# Bump on every build (David's standing instruction). Deployed-at is the
# process start time, not a hand-maintained date -- every deploy does a
# fresh `docker rm -f` + `docker run` (see start.sh), so this is always
# accurate without needing to remember to update it separately from the
# version string. Shown on the Help tab, not a page footer (David's call).
APP_VERSION = "1.0.0"
APP_AUTHOR = "David"
DEPLOYED_AT = datetime.now(timezone.utc)

_tree_cache = {"tree": None}

# Debug panel rows are named "include_<target>_<plugin>" / "level_<target>_<plugin>" --
# target is an appliance/EM IP (dotted quad), plugin the shape the EM wrapper also
# validates. Anchored so a target's dots can't be confused with the plugin name that
# follows the last one.
TARGET_PLUGIN_KEY_RE = re.compile(r"^((?:\d{1,3}\.){3}\d{1,3})_([a-z][a-z0-9_]{1,40})$")

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


# ---------------------------------------------------------------------
# Login -- David's ask, 2026-08-26 (Phase D of the EM-hosted package):
# one Admin account, default password "ForescoutTechSupport123",
# forced change on first login. Password hashed with werkzeug's own
# generate_password_hash/check_password_hash (already a Flask
# dependency -- no new package needed; check_password_hash does a
# timing-safe compare internally) and stored in /data/auth.json, never
# plaintext. Every route requires a session except /login itself and
# static assets -- gated via one before_request hook rather than
# decorating each view individually, so a route added later can't
# accidentally ship unauthenticated by omission.
# ---------------------------------------------------------------------
AUTH_PATH = os.path.join(DATA_DIR, "auth.json")
DEFAULT_ADMIN_PASSWORD = "ForescoutTechSupport123"

# Persisted, not regenerated each boot -- a fresh secret key on every
# container restart would silently log everyone out every redeploy,
# same class of annoyance the scheduled-jobs/data persistence above
# was already built to avoid.
_SECRET_KEY_PATH = os.path.join(DATA_DIR, "secret_key")
if os.path.isfile(_SECRET_KEY_PATH):
    with open(_SECRET_KEY_PATH) as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)
    with open(_SECRET_KEY_PATH, "w") as f:
        f.write(app.secret_key)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Only sent back over HTTPS -- this deployment always serves HTTPS once
# FORESCOUT_SSL_CERT is set (see the ssl_context wiring at the bottom
# of this file); a plain-HTTP dev run (FORESCOUT_SSL_CERT unset, e.g.
# the .230 deployment before Phase C) correctly gets a non-Secure
# cookie instead, since marking it Secure there would mean the browser
# silently never sends it back at all.
app.config["SESSION_COOKIE_SECURE"] = bool(os.environ.get("FORESCOUT_SSL_CERT"))


def _load_auth():
    if not os.path.isfile(AUTH_PATH):
        auth = {
            "username": "admin",
            "password_hash": generate_password_hash(DEFAULT_ADMIN_PASSWORD),
            "must_change_password": True,
        }
        _save_auth(auth)
        return auth
    with open(AUTH_PATH) as f:
        return json.load(f)


def _save_auth(auth):
    tmp = AUTH_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(auth, f)
    os.replace(tmp, AUTH_PATH)


def _csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def _check_csrf():
    token = request.form.get("csrf_token", "")
    return bool(token) and secrets.compare_digest(token, session.get("csrf_token", ""))


_PUBLIC_PATHS = {"/login"}


@app.before_request
def _require_login():
    if request.path.startswith("/static/"):
        return
    if request.path in _PUBLIC_PATHS:
        return
    if not session.get("logged_in"):
        return redirect(url_for("login_route"))
    if _load_auth().get("must_change_password") and request.path != "/change-password":
        return redirect(url_for("change_password_route"))


@app.route("/login", methods=["GET", "POST"])
def login_route():
    error = None
    if request.method == "POST":
        auth = _load_auth()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == auth["username"] and check_password_hash(auth["password_hash"], password):
            session.clear()
            session["logged_in"] = True
            session["username"] = username
            _log_activity("login", username=username)
            if auth.get("must_change_password"):
                return redirect(url_for("change_password_route"))
            return redirect(url_for("index"))
        error = "Invalid username or password."
        _log_activity("login_failed", username=username)
    return render_template("login.html", error=error, csrf_token=_csrf_token())


@app.route("/logout", methods=["POST"])
def logout_route():
    _log_activity("logout", username=session.get("username"))
    session.clear()
    return redirect(url_for("login_route"))


@app.route("/change-password", methods=["GET", "POST"])
def change_password_route():
    if not session.get("logged_in"):
        return redirect(url_for("login_route"))
    error = None
    if request.method == "POST":
        if not _check_csrf():
            error = "Session expired -- please try again."
        else:
            auth = _load_auth()
            old_password = request.form.get("old_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")
            if not check_password_hash(auth["password_hash"], old_password):
                error = "Current password is incorrect."
            elif len(new_password) < 8:
                error = "New password must be at least 8 characters."
            elif new_password != confirm_password:
                error = "New password and confirmation do not match."
            elif new_password == DEFAULT_ADMIN_PASSWORD:
                error = "Choose a password different from the default."
            else:
                auth["password_hash"] = generate_password_hash(new_password)
                auth["must_change_password"] = False
                _save_auth(auth)
                _log_activity("password_changed", username=session.get("username"))
                return redirect(url_for("index"))
    return render_template(
        "change_password.html", error=error, csrf_token=_csrf_token(),
        forced=_load_auth().get("must_change_password", False),
    )


# HTTPS certificate management -- only meaningful on the EM-hosted
# package (Deploy.sh), where /certs is a read-write volume and
# /host-apache-certs is a read-only mount of this EM's own Apache SSL
# dir. On the .230 deployment neither path exists, so this page just
# reports nothing to manage rather than erroring.
CERT_DIR = "/certs"
APACHE_CERT_MOUNT = "/host-apache-certs"


def _cert_info(cert_path):
    if not os.path.isfile(cert_path):
        return None
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout", "-subject", "-issuer", "-enddate", "-fingerprint", "-sha256"],
            capture_output=True, text=True, timeout=5,
        )
    except OSError as exc:
        return {"error": str(exc)}
    if proc.returncode != 0:
        return {"error": proc.stderr.strip() or "openssl could not read this file."}
    info = {}
    for line in proc.stdout.splitlines():
        if line.startswith("subject="):
            info["subject"] = line[len("subject="):].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line[len("issuer="):].strip()
        elif line.startswith("notAfter="):
            info["expires"] = line[len("notAfter="):].strip()
        elif line.startswith("sha256 Fingerprint="):
            info["fingerprint"] = line[len("sha256 Fingerprint="):].strip()
    return info


def _key_is_encrypted(key_path):
    try:
        with open(key_path) as f:
            return "ENCRYPTED" in f.read()
    except OSError:
        return False


def _verify_cert_key(cert_path, key_path, password):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path, password=password or None)
        return True, None
    except (ssl.SSLError, OSError) as exc:
        return False, str(exc)


def _render_certs_page(error=None, message=None):
    apache_cert_path = os.path.join(APACHE_CERT_MOUNT, "cert.pem")
    apache_key_path = os.path.join(APACHE_CERT_MOUNT, "private.key")
    apache = _cert_info(apache_cert_path) if os.path.isfile(apache_cert_path) else None
    return render_template(
        "certs.html",
        current=_cert_info(os.path.join(CERT_DIR, "cert.pem")),
        apache=apache,
        apache_key_encrypted=_key_is_encrypted(apache_key_path) if apache else False,
        certs_dir_available=os.path.isdir(CERT_DIR),
        csrf_token=_csrf_token(),
        error=error,
        message=message,
    )


@app.route("/admin/certs", methods=["GET"])
def certs_route():
    if not session.get("logged_in"):
        return redirect(url_for("login_route"))
    return _render_certs_page()


@app.route("/admin/certs/apply", methods=["POST"])
def certs_apply_route():
    if not session.get("logged_in"):
        return redirect(url_for("login_route"))
    if not _check_csrf():
        return _render_certs_page(error="Session expired -- please try again.")
    if not os.path.isdir(CERT_DIR):
        return _render_certs_page(error="No writable certificate directory on this deployment.")

    source = request.form.get("source")
    password = request.form.get("password", "")
    tmp_cert = os.path.join(CERT_DIR, "cert.pem.new")
    tmp_key = os.path.join(CERT_DIR, "private.key.new")

    try:
        if source == "apache":
            src_cert = os.path.join(APACHE_CERT_MOUNT, "cert.pem")
            src_key = os.path.join(APACHE_CERT_MOUNT, "private.key")
            if not os.path.isfile(src_cert) or not os.path.isfile(src_key):
                raise ValueError("This EM's Apache cert/key could not be found.")
            shutil.copyfile(src_cert, tmp_cert)
            shutil.copyfile(src_key, tmp_key)
        elif source == "upload":
            cert_file = request.files.get("cert_file")
            key_file = request.files.get("key_file")
            if not cert_file or not key_file or not cert_file.filename or not key_file.filename:
                raise ValueError("Both a certificate file and a private key file are required.")
            cert_file.save(tmp_cert)
            key_file.save(tmp_key)
        else:
            raise ValueError("Unknown certificate source.")

        ok, err = _verify_cert_key(tmp_cert, tmp_key, password)
        if not ok:
            raise ValueError(f"That cert/key could not be loaded: {err}")

        os.replace(tmp_cert, os.path.join(CERT_DIR, "cert.pem"))
        os.replace(tmp_key, os.path.join(CERT_DIR, "private.key"))
        os.chmod(os.path.join(CERT_DIR, "private.key"), 0o600)
        pw_path = os.path.join(CERT_DIR, "key_password.txt")
        if password:
            with open(pw_path, "w") as f:
                f.write(password)
            os.chmod(pw_path, 0o600)
        elif os.path.isfile(pw_path):
            os.remove(pw_path)
    except ValueError as exc:
        for p in (tmp_cert, tmp_key):
            if os.path.isfile(p):
                os.remove(p)
        return _render_certs_page(error=str(exc))

    _log_activity("cert_updated", username=session.get("username"), source=source)
    # Werkzeug's dev server can't hot-swap a TLS cert mid-process -- the
    # container's --restart unless-stopped policy (Deploy.sh) is what
    # actually applies this, by bringing the process back up with the
    # new file already in place.
    threading.Timer(1.0, lambda: os._exit(0)).start()
    return _render_certs_page(
        message="New certificate saved. Restarting the service now to apply it -- this page will be unreachable for a few seconds."
    )


@app.route("/admin/certs/export-apache", methods=["GET"])
def certs_export_apache_route():
    if not session.get("logged_in"):
        return redirect(url_for("login_route"))
    src_cert = os.path.join(APACHE_CERT_MOUNT, "cert.pem")
    src_key = os.path.join(APACHE_CERT_MOUNT, "private.key")
    if not os.path.isfile(src_cert) or not os.path.isfile(src_key):
        return redirect(url_for("certs_route"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.write(src_cert, "cert.pem")
        zf.write(src_key, "private.key")
    buf.seek(0)
    _log_activity("cert_exported", username=session.get("username"))
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name="apache-cert.zip")


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


def schedule_debug_job(target, spec, start_epoch):
    """Persists a pending future debug start; _scheduler_loop picks it up once start_epoch arrives."""
    with _jobs_lock:
        jobs = _load_jobs()
        job_id = f"{int(time.time() * 1000)}-{os.urandom(3).hex()}"
        jobs.append({
            "id": job_id, "target": target, "spec": spec, "start_epoch": start_epoch, "created_at": int(time.time()),
        })
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
    """Runs at (or shortly after) the scheduled start time -- fires the exact same debug_set_appliance() the
    interactive "Start debug" button uses. Outcome is appended to LOG_PATH since nothing is watching a
    background thread's return value; David can check whether it actually fired correctly after the fact."""
    entry = {"fired_at": int(time.time()), "target": job["target"], "spec": job["spec"], "job_id": job["id"]}
    try:
        entry["result"] = debug_set_appliance(job["target"], job["spec"])
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


# ---------------------------------------------------------------------
# Advanced Trace -- David's ask, 2026-08-26: an "Enhance Trace" feature
# in the Tech Support Bundle Generator, exposing
# /usr/local/forescout/etc/fstrace.properties per box (EM or a specific
# appliance), each category tickable on/off with a level, alongside its
# captured-once default (webapp-query.py's own job -- see tracelist),
# plus a "revert to default" button and a timed auto-revert. Same
# self-rolled JSON-queue + daemon-thread pattern as the scheduled-debug-
# jobs above -- the revert itself re-fetches that target's captured
# defaults at fire time (tracedefaults) rather than carrying its own
# copy, so there is exactly one source of truth for "what counts as
# default," not two that could drift apart.
# ---------------------------------------------------------------------
TRACE_JOBS_PATH = os.path.join(DATA_DIR, "trace_jobs.json")
TRACE_LOG_PATH = os.path.join(DATA_DIR, "trace_revert_log.jsonl")

_trace_jobs_lock = threading.Lock()


def _load_trace_jobs():
    if not os.path.isfile(TRACE_JOBS_PATH):
        return []
    try:
        with open(TRACE_JOBS_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def _save_trace_jobs(jobs):
    tmp = TRACE_JOBS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(jobs, f)
    os.replace(tmp, TRACE_JOBS_PATH)


def schedule_trace_revert(target, revert_epoch):
    """Persists a pending auto-revert; _trace_scheduler_loop fires it once revert_epoch arrives. A target
    already has a pending revert -> replaced, not stacked -- only one "back to default at X" makes sense
    for a given box at a time (applying a new set of changes with its own duration should reset the
    clock, not queue a second, earlier revert behind it)."""
    with _trace_jobs_lock:
        jobs = [j for j in _load_trace_jobs() if j["target"] != target]
        job_id = f"{int(time.time() * 1000)}-{os.urandom(3).hex()}"
        jobs.append({
            "id": job_id, "target": target, "revert_epoch": revert_epoch, "created_at": int(time.time()),
        })
        _save_trace_jobs(jobs)
    return job_id


def cancel_trace_revert(job_id):
    with _trace_jobs_lock:
        jobs = _load_trace_jobs()
        remaining = [j for j in jobs if j["id"] != job_id]
        removed = len(remaining) != len(jobs)
        _save_trace_jobs(remaining)
    return removed


def get_pending_trace_reverts():
    with _trace_jobs_lock:
        jobs = _load_trace_jobs()
    jobs.sort(key=lambda j: j["revert_epoch"])
    for j in jobs:
        j["revert_display"] = datetime.fromtimestamp(j["revert_epoch"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return jobs


def _fire_trace_revert(job):
    """Runs at (or shortly after) the scheduled revert time -- re-fetches the target's captured defaults
    fresh (not a copy taken when the job was scheduled) and applies them via the same trace_set() the
    interactive Revert button uses. Outcome appended to TRACE_LOG_PATH, same reasoning as _fire_job's own
    LOG_PATH -- nothing is watching a background thread's return value directly."""
    entry = {"fired_at": int(time.time()), "target": job["target"], "job_id": job["id"]}
    try:
        defaults = trace_defaults(job["target"]).get("defaults", {})
        if defaults:
            changes = {name: (v["enabled"], v["level"]) for name, v in defaults.items()}
            entry["result"] = trace_set(job["target"], changes)
        entry["ok"] = True
    except ForescoutClientError as e:
        entry["ok"] = False
        entry["error"] = str(e)
    with open(TRACE_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _trace_scheduler_loop():
    while True:
        now = int(time.time())
        with _trace_jobs_lock:
            jobs = _load_trace_jobs()
            due = [j for j in jobs if j["revert_epoch"] <= now]
            remaining = [j for j in jobs if j["revert_epoch"] > now]
            if due:
                _save_trace_jobs(remaining)
        for job in due:
            _fire_trace_revert(job)
        time.sleep(15)


threading.Thread(target=_trace_scheduler_loop, daemon=True).start()


# ---------------------------------------------------------------------
# Appliance "Run Show Errors" -- fires `fstool tech-support --review
# --show-errors` (confirmed live: a real, several-minutes-long, unscoped
# snapshot, not a quick check) on one or more appliances at once. Each
# run is its own background thread rather than blocking the request that
# started it; the UI polls per-run status. Persisted to /data (same
# volume/pattern as the debug scheduler above) purely so a run in
# progress survives this app being redeployed mid-poll -- unlike the
# debug scheduler, nothing here needs to survive a full process restart
# functionally (a run that was mid-flight when the container restarted
# can't be resumed, its SSH command just dies with it), so this is
# read-back convenience more than correctness-critical persistence.
# ---------------------------------------------------------------------
RUNS_PATH = os.path.join(DATA_DIR, "appliance_runs.json")
_runs_lock = threading.Lock()


def _load_runs():
    if not os.path.isfile(RUNS_PATH):
        return []
    try:
        with open(RUNS_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def _save_runs(runs):
    tmp = RUNS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(runs, f)
    os.replace(tmp, RUNS_PATH)


def _update_run(run_id, **fields):
    with _runs_lock:
        runs = _load_runs()
        for r in runs:
            if r["id"] == run_id:
                r.update(fields)
                break
        _save_runs(runs)


def start_show_errors_run(target, duration):
    """
    Returns None (starts nothing) if a run is already active for this
    target -- checked and the new record inserted under the same lock,
    so two near-simultaneous requests can't both slip past the check and
    start two runs against the same appliance at once. Same reasoning as
    debug/tech-support's existing "still active" refusals, just for this
    verb instead.
    """
    run_id = f"{int(time.time() * 1000)}-{os.urandom(3).hex()}"
    with _runs_lock:
        runs = _load_runs()
        if any(r["target"] == target and r["status"] == "running" for r in runs):
            return None
        runs.append({
            "id": run_id, "target": target, "duration": duration, "status": "running",
            "started_at": int(time.time()), "finished_at": None, "result": None, "error": None,
        })
        _save_runs(runs)

    def _worker():
        try:
            result = run_show_errors(target, duration)
            _update_run(run_id, status="complete", finished_at=int(time.time()), result=result)
        except ForescoutClientError as e:
            _update_run(run_id, status="failed", finished_at=int(time.time()), error=str(e))

    threading.Thread(target=_worker, daemon=True).start()
    return run_id


def get_run(run_id):
    with _runs_lock:
        runs = _load_runs()
    for r in runs:
        if r["id"] == run_id:
            return r
    return None


def get_active_appliance_runs():
    """
    Every currently-running appliance job, straight from disk -- not
    client-side JS memory, so a page reload (or a second browser tab)
    doesn't lose track of a job someone already started, and the "Run
    Show Errors" button can refuse a duplicate start for a target that's
    already going.
    """
    with _runs_lock:
        runs = _load_runs()
    active = [r for r in runs if r["status"] == "running"]
    for r in active:
        r["started_display"] = _fmt_utc(r["started_at"])
    active.sort(key=lambda r: r["started_at"])
    return active


# ---------------------------------------------------------------------
# Tech-support bundle building -- same background-thread + JSON-file
# tracking pattern as the appliance runs above (a build is a real
# `fstool tech-support --pack`, several minutes per plugin, so this never
# blocks the request that started it). "key" is the host IP for a
# per-host build or the literal string "EM" for the EM's general bundle
# -- used both for the in-progress dedup check and for display, so the
# UI can show "already building for this host/EM" without needing a
# separate id scheme.
# ---------------------------------------------------------------------
TS_RUNS_PATH = os.path.join(DATA_DIR, "techsupport_runs.json")
_ts_runs_lock = threading.Lock()

# Case reference builds get logged here, append-only (same convention as
# LOG_PATH above) -- "keep a record of the cases generated" was David's
# explicit ask. Logged for every completed build, not just case-tagged
# ones, so nothing is silently missing from the audit trail; the UI's
# case-history view just filters to the case-tagged rows.
CASE_LOG_PATH = os.path.join(DATA_DIR, "case_log.jsonl")


def _load_ts_runs():
    if not os.path.isfile(TS_RUNS_PATH):
        return []
    try:
        with open(TS_RUNS_PATH) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def _save_ts_runs(runs):
    tmp = TS_RUNS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(runs, f)
    os.replace(tmp, TS_RUNS_PATH)


def _update_ts_run(run_id, **fields):
    with _ts_runs_lock:
        runs = _load_ts_runs()
        for r in runs:
            if r["id"] == run_id:
                r.update(fields)
                break
        _save_ts_runs(runs)


def _log_case_build(kind, key, case_ref, result, error):
    entry = {
        "logged_at": int(time.time()), "kind": kind, "key": key, "case_ref": case_ref,
        "ok": error is None, "error": error,
        "bundles": (result or {}).get("bundles", []),
    }
    with open(CASE_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def start_techsupport_run(
    kind, hosts, case_ref, level=None, minutes=None, duration=None, selected_plugins=None, selected_dbtables=None,
    company=None, send=False,
):
    """
    kind: "host" (hosts is a non-empty list of one or more IPs; level +
    minutes required -- the worker enables debug on every relevant
    plugin across all of them, waits out `minutes` itself, THEN collects
    and centralizes) or "em" (hosts ignored, duration required --
    build_techsupport_em, a general bundle; no debug-enable step, there's
    no host to scope plugins from). key is a stable, sorted join of the
    host IPs (or "EM") -- used both for display and the duplicate-run
    guard, so starting a build for the exact same set of checked hosts
    while one's already running is refused, not queued or duplicated
    (same atomic check-and-insert-under-lock pattern as the appliance
    runs). A different/overlapping subset of hosts is treated as a
    different run -- accepted as a simplification, not worth guarding
    against for normal usage.

    selected_plugins ("host" kind only): {target: [plugin, ...]} from
    the checked plugin rows in the UI, or None/empty for the full
    auto-detected set. Passed into BOTH the internal preview_techsupport
    call (so debug is only enabled on what was actually checked) and the
    final collect_techsupport call (so the bundle only covers the same
    set) -- they must agree, or the collected bundle would include
    plugins that were never debug-enabled, or omit ones that were.

    selected_dbtables ("host" kind only): {target: [table, ...]} from
    the checked "Attach DBs" rows -- David's ask, 2026-08-26: fstool's
    own significant tables (`fstool db diskspace`, e.g. source_log,
    hostinfo), attached via --dbtable. Unlike selected_plugins, this has
    no debug-enable step of its own (a table attach doesn't need debug
    turned on), so it only needs to reach the final collect_techsupport
    call, not the preview one.

    send: fstool's own --send flag ("Send support bundle directly to
    Forescout", David's ask, 2026-08-26) -- only reaches the final
    collect/build call (same reasoning as selected_dbtables above: it
    doesn't affect debug-enable, only what the actual collection command
    looks like).

    The wait deliberately happens HERE, as a plain time.sleep() in this
    background thread, rather than inside webapp-query.py's own single
    SSH-invoked script -- a multi-hour blocking SSH call is fragile (one
    network blip loses the whole sequence); a long-lived Python thread in
    this already-running process tolerates that far better. "phase" on
    the tracked run (enabling_debug / waiting / collecting) lets the UI
    show which step a long-running job is actually in, not just a bare
    spinner with no sense of how much longer it might be. Skipped
    entirely if NOTHING across the whole batch actually has a plugin to
    debug (e.g. a build that only attaches DB tables, or a host whose
    own appliance is the only target and nothing was checked for it) --
    David's ask, 2026-08-26: nothing being debugged means there's
    nothing to wait for, so collection proceeds immediately rather than
    an idle delay for no reason. When at least one target DOES have a
    plugin, every OTHER target still waits out the same duration
    regardless of whether it has anything of its own to debug (David's
    own worked example: an appliance collecting only a host's hostinfo,
    with nothing being debugged there itself, still waits for the full
    debug window elsewhere before collecting) -- this already falls out
    of the single shared time.sleep() below applying to the whole batch,
    not a per-target wait.
    """
    key = "EM" if kind == "em" else ", ".join(sorted(hosts))
    run_id = f"{int(time.time() * 1000)}-{os.urandom(3).hex()}"
    with _ts_runs_lock:
        runs = _load_ts_runs()
        if any(r["key"] == key and r["status"] == "running" for r in runs):
            return None
        runs.append({
            "id": run_id, "kind": kind, "key": key, "case_ref": case_ref, "status": "running",
            "phase": "enabling_debug" if kind == "host" else "collecting",
            "started_at": int(time.time()), "finished_at": None, "result": None, "error": None,
        })
        _save_ts_runs(runs)

    def _worker():
        result, error = None, None
        try:
            if kind == "host":
                # Re-resolves which plugin(s) matter on which target --
                # same live grouping the preview the user already saw was
                # built from (hostinfo could in principle have shifted
                # slightly since; accepted as a simplification).
                preview = preview_techsupport(
                    hosts, level, minutes, selected_plugins=selected_plugins,
                    selected_dbtables=selected_dbtables, company=company, case_ref=case_ref, timeout=45,
                )
                any_debug_enabled = False
                for t in preview.get("targets", []):
                    spec = ",".join(f"{p}:{level}:{minutes}" for p in t["plugins"])
                    if spec:
                        # "adhoc" fallback (not the bare case_ref, which can
                        # be None when nothing was typed) -- so this run's
                        # debug-enable command still logs to TS_LOG_PATH.
                        # Passing None here would silently produce zero log
                        # lines for a genuine, currently-running build,
                        # caught live 2026-08-26: the popup kept showing an
                        # unrelated earlier run's stale "finished" state.
                        debug_set_appliance(t["target"], spec, case_ref=case_ref or "adhoc")
                        any_debug_enabled = True
                if any_debug_enabled:
                    _update_ts_run(run_id, phase="waiting")
                    time.sleep(minutes * 60)
                _update_ts_run(run_id, phase="collecting")
                # A much longer timeout than collect_techsupport's own
                # 480s default -- that default exists for a caller
                # actually waiting on the HTTP response. Nothing waits
                # synchronously on this background thread, and a host (or
                # several) with many relevant plugins genuinely can take
                # well past 8 minutes total -- confirmed live this was
                # cutting a real multi-plugin build off mid-way.
                result = collect_techsupport(
                    hosts, minutes, selected_plugins=selected_plugins,
                    selected_dbtables=selected_dbtables, company=company, send=send, case_ref=case_ref,
                    timeout=3600,
                )
            else:
                result = build_techsupport_em(duration, company=company, send=send, case_ref=case_ref, timeout=3600)
            _update_ts_run(run_id, status="complete", finished_at=int(time.time()), result=result)
        except ForescoutClientError as e:
            error = str(e)
            _update_ts_run(run_id, status="failed", finished_at=int(time.time()), error=error)
        _log_case_build(kind, key, case_ref, result, error)

    threading.Thread(target=_worker, daemon=True).start()
    return run_id


def get_ts_run(run_id):
    with _ts_runs_lock:
        runs = _load_ts_runs()
    for r in runs:
        if r["id"] == run_id:
            return r
    return None


def get_active_techsupport_runs():
    with _ts_runs_lock:
        runs = _load_ts_runs()
    active = [r for r in runs if r["status"] == "running"]
    for r in active:
        r["started_display"] = _fmt_utc(r["started_at"])
    active.sort(key=lambda r: r["started_at"])
    return active


def get_case_history(limit=20):
    """Most-recent-first, capped -- a quick "what was built for which case" glance, not a full audit export."""
    if not os.path.isfile(CASE_LOG_PATH):
        return []
    try:
        with open(CASE_LOG_PATH) as f:
            lines = f.readlines()
    except OSError:
        return []
    entries = []
    for line in lines[-limit:]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    for e in entries:
        e["logged_display"] = _fmt_utc(e["logged_at"])
    entries.reverse()
    return entries


# ---------------------------------------------------------------------
# Activity log -- one line per meaningful action (lookup, debug start/
# stop, tech-support build start, appliance run start), written as soon
# as it's requested, not just once it finishes. Exists specifically to
# tell apart a real browser click from a curl/script-driven test request
# even when both come from the same LAN/IP -- confirmed this session a
# live test call against a real host looked, from inside the app,
# indistinguishable from someone actually clicking the button, which is
# exactly the ambiguity David asked this log to resolve. User-Agent is
# the one field that reliably tells them apart (a real browser's UA vs.
# curl's own).
# ---------------------------------------------------------------------
ACTIVITY_LOG_PATH = os.path.join(DATA_DIR, "activity_log.jsonl")

# Client-side JS diagnostic beacon -- David's ask, 2026-08-28: a Graphic View
# bug (only the root "NINHS" box rendering) couldn't be reproduced live, so
# the policy-tree JS beacons its own render-state/exception detail here
# instead of relying on someone manually copying browser console output.
# Never a substitute for real testing -- pulled back via SSH once David
# reproduces it, then this route (and the JS calling it) gets removed again.
CLIENT_DEBUG_LOG_PATH = os.path.join(DATA_DIR, "client_debug_log.jsonl")


@app.route("/api/client_debug_log", methods=["POST"])
def api_client_debug_log():
    try:
        payload = request.get_json(silent=True) or {}
        entry = {
            "logged_at": int(time.time()), "username": session.get("username"),
            "remote_addr": request.remote_addr,
            **payload,
        }
        with open(CLIENT_DEBUG_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    return jsonify({"ok": True})


def _log_activity(action, **details):
    """Never lets a logging failure break the action it's describing -- best-effort only."""
    try:
        entry = {
            "logged_at": int(time.time()), "action": action,
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            **details,
        }
        with open(ACTIVITY_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def get_recent_activity(limit=50):
    """Most-recent-first, capped -- a quick "what's actually been triggered, by what" glance."""
    if not os.path.isfile(ACTIVITY_LOG_PATH):
        return []
    try:
        with open(ACTIVITY_LOG_PATH) as f:
            lines = f.readlines()
    except OSError:
        return []
    entries = []
    for line in lines[-limit:]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    common = {"logged_at", "action", "remote_addr", "user_agent"}
    for e in entries:
        e["details_display"] = json.dumps({k: v for k, v in e.items() if k not in common})
        e["logged_display"] = _fmt_utc(e["logged_at"])
    entries.reverse()
    return entries


def render(**kwargs):
    """render_template wrapper that always carries the pending-scheduled-jobs list, regardless of which
    action's route is rendering -- it's global state, not tied to any one lookup."""
    kwargs.setdefault("ip", "")
    kwargs.setdefault("results", [])
    kwargs.setdefault("result", None)
    kwargs.setdefault("error", None)
    kwargs.setdefault("action", None)
    kwargs.setdefault("active_ip", None)
    kwargs["scheduled_jobs"] = get_pending_jobs()
    kwargs["pending_trace_reverts"] = get_pending_trace_reverts()
    kwargs["active_appliance_runs"] = get_active_appliance_runs()
    kwargs["active_techsupport_runs"] = get_active_techsupport_runs()
    kwargs["case_history"] = get_case_history()
    kwargs["recent_activity"] = get_recent_activity()
    kwargs["app_version"] = APP_VERSION
    kwargs["app_author"] = APP_AUTHOR
    kwargs["deployed_at_display"] = DEPLOYED_AT.strftime("%Y-%m-%d %H:%M:%S UTC")
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

    active_ip (optional): which IP's tab should be active on reload --
    set by each IP section's own "Refresh" button, which resubmits the
    *whole* current IP list (so every tab's data comes back current, not
    just one) but should still land back on the tab the player was
    actually looking at, not always the first one.
    """
    ip_raw = request.form.get("ip", "").strip()
    active_ip = request.form.get("active_ip", "").strip() or None
    ips = [p.strip() for p in ip_raw.split(",") if p.strip()]
    _log_activity("lookup", ips=ips)
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
    return render(ip=ip_raw, results=results, error=error, action="lookup", active_ip=active_ip)


def _checked_targets():
    """
    {target: [plugin, ...]} from whichever include_<target>_<plugin> rows the debug panel's JS built and the
    user left checked -- the panel already deduplicated plugin/appliance pairs across whichever hosts are
    ticked, so this just reads back what it rendered.
    """
    by_target = {}
    for key, value in request.form.items():
        if not key.startswith("include_") or value != "1":
            continue
        m = TARGET_PLUGIN_KEY_RE.match(key[len("include_"):])
        if not m:
            continue
        by_target.setdefault(m.group(1), []).append(m.group(2))
    return by_target


def _fmt_utc(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@app.route("/debugset", methods=["POST"])
def do_debugset():
    """
    Builds one "<plugin>:<level>:<minutes>" spec per target appliance
    from the debug panel's checkbox/level/duration controls -- a single
    submission can span more than one appliance (e.g. two hosts on
    different switch appliances), so this fires one backend call per
    distinct target and combines the results into one page. mode=start
    uses each plugin's configured level/minutes; mode=stop ignores those
    and forces level=0/minutes=1 on the same checked plugins,
    immediately -- both always take effect right away regardless of
    time_mode.

    time_mode=window additionally accepts a shared start_epoch/end_epoch
    (computed client-side from the browser's local timezone) that applies
    across every checked target. A debug level is a real configuration
    change to the plugin -- it can never be backdated, only ever take
    effect from whenever it's actually applied -- so mode=start with
    time_mode=window splits three ways:
      - end <= now: fully in the past -- no live debug at all, builds a
        tech-support bundle per target scoped to that exact historical
        window instead (fstool's own -t utc:X -t utc:Y, confirmed live
        against already-rotated logs).
      - start <= now < end: starts immediately on every target, runs
        until end_epoch (the already-elapsed start..now portion can't be
        recovered).
      - start > now: genuinely delayed -- one schedule_debug_job per
        target, each firing debug_set_appliance() at start_epoch,
        running for (end - start).
    """
    mode = request.form.get("mode", "start")
    time_mode = request.form.get("time_mode", "duration")
    by_target = _checked_targets()
    _log_activity("debugset", mode=mode, time_mode=time_mode, targets=list(by_target.keys()))

    if not by_target:
        return render(error="No plugins selected.", action="debugset")

    if mode == "stop" or time_mode == "duration":
        duration_minutes = request.form.get("duration_minutes", "60").strip()
        all_debug_set, errors = [], []
        for target, plugins in by_target.items():
            items = []
            for plugin in plugins:
                if mode == "stop":
                    items.append(f"{plugin}:0:1")
                else:
                    level = request.form.get(f"level_{target}_{plugin}", "4").strip()
                    items.append(f"{plugin}:{level}:{duration_minutes}")
            try:
                r = debug_set_appliance(target, ",".join(items))
                all_debug_set.extend(r.get("debug_set", []))
            except ForescoutClientError as e:
                errors.append(f"{target}: {e}")
        result = {"debug_set": all_debug_set} if all_debug_set else None
        return render(result=result, error="; ".join(errors) or None, action="debugset")

    # time_mode == "window", mode == "start"
    try:
        start_epoch = int(request.form.get("start_epoch", "").strip())
        end_epoch = int(request.form.get("end_epoch", "").strip())
    except ValueError:
        return render(error="Invalid start/end time.", action="debugset")
    if end_epoch <= start_epoch:
        return render(error="End time must be after start time.", action="debugset")

    now = int(time.time())
    case_ref, err = _validate_case_ref()
    if err:
        return render(error=err, action="debugset")

    if end_epoch <= now:
        all_bundles, errors = [], []
        for target, plugins in by_target.items():
            try:
                r = build_techsupport_window_appliance(target, start_epoch, end_epoch, plugins, case_ref=case_ref)
                all_bundles.extend(r.get("bundles", []))
                for b in r.get("bundles", []):
                    _log_case_build("window", target, case_ref, {"bundles": [b]}, None)
            except ForescoutClientError as e:
                errors.append(f"{target}: {e}")
        result = {"bundles": all_bundles} if all_bundles else None
        return render(result=result, error="; ".join(errors) or None, action="techsupport")

    if start_epoch <= now:
        minutes = max(1, (end_epoch - now + 59) // 60)
        all_debug_set, errors = [], []
        for target, plugins in by_target.items():
            items = [f"{p}:{request.form.get(f'level_{target}_{p}', '4').strip()}:{minutes}" for p in plugins]
            try:
                r = debug_set_appliance(target, ",".join(items))
                all_debug_set.extend(r.get("debug_set", []))
            except ForescoutClientError as e:
                errors.append(f"{target}: {e}")
        result = {"debug_set": all_debug_set} if all_debug_set else None
        return render(result=result, error="; ".join(errors) or None, action="debugset")

    # start_epoch > now: genuinely scheduled, one job per target.
    minutes = max(1, (end_epoch - start_epoch + 59) // 60)
    jobs = []
    for target, plugins in by_target.items():
        items = [f"{p}:{request.form.get(f'level_{target}_{p}', '4').strip()}:{minutes}" for p in plugins]
        spec = ",".join(items)
        job_id = schedule_debug_job(target, spec, start_epoch)
        jobs.append({
            "target": target, "job_id": job_id, "spec": spec,
            "spec_display": _spec_display(spec),
            "start_display": _fmt_utc(start_epoch), "end_display": _fmt_utc(end_epoch),
        })
    return render(result={"jobs": jobs}, action="debugscheduled")


@app.route("/scheduled/cancel", methods=["POST"])
def cancel_scheduled():
    job_id = request.form.get("job_id", "").strip()
    cancel_debug_job(job_id)
    return redirect(url_for("index"))


@app.route("/appliances/kill", methods=["POST"])
def do_appliances_kill():
    """Plain-form-POST + redirect version of /api/appliance_run/<id>/kill, for the static "Run Show Errors in
    progress" table's Kill button -- same reasoning, clears a stuck "running" state rather than a real process
    kill."""
    run_id = request.form.get("run_id", "").strip()
    run = get_run(run_id)
    if run is not None and run["status"] == "running":
        _update_run(run_id, status="failed", finished_at=int(time.time()), error="Manually killed (was stuck).")
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


def _parse_trace_changes_form():
    """{category: (enabled_bool, level_str), ...} from checked change_<category>=<on|off>:<level> fields --
    mirrors _checked_ts_plugins'/_checked_ts_dbtables' own key-parsing convention elsewhere in this file."""
    changes = {}
    for key, v in request.form.items():
        if not key.startswith("change_"):
            continue
        name = key[len("change_"):]
        enabled_s, _, level = v.partition(":")
        changes[name] = (enabled_s == "on", level)
    return changes


def _parse_trace_duration_form():
    """(seconds, error_or_None) from duration_value/duration_unit fields -- empty duration_value means "no
    auto-revert requested", returned as (None, None), not an error."""
    value = request.form.get("duration_value", "").strip()
    if not value:
        return None, None
    unit = request.form.get("duration_unit", "m").strip()
    if not value.isdigit() or not (1 <= int(value) <= 9999) or unit not in ("m", "h"):
        return None, "Invalid auto-revert duration."
    return int(value) * (3600 if unit == "h" else 60), None


@app.route("/api/trace/<target>", methods=["GET"])
def api_trace_list(target):
    """David's ask, 2026-08-26: the popup that opens after picking a box from "Enhance Trace" -- every
    trace category's live state plus its captured-once default, side by side."""
    try:
        data = trace_list(target)
    except ForescoutClientError as e:
        return jsonify({"error": str(e)}), 502
    return jsonify(data)


@app.route("/api/trace/<target>/set", methods=["POST"])
def api_trace_set(target):
    """Applies whichever categories were actually changed (not a full resubmit of all ~250 -- see
    _parse_trace_changes_form), then optionally schedules an auto-revert if a duration was given
    alongside. Returns the resulting live state so the popup can redraw without a second round trip."""
    changes = _parse_trace_changes_form()
    if not changes:
        return jsonify({"error": "No changes given."}), 400
    try:
        data = trace_set(target, changes)
    except ForescoutClientError as e:
        return jsonify({"error": str(e)}), 502
    _log_activity("trace_set", target=target, categories=list(changes.keys()))

    seconds, err = _parse_trace_duration_form()
    if err:
        data["revert_error"] = err
    elif seconds:
        data["revert_job_id"] = schedule_trace_revert(target, int(time.time()) + seconds)
    return jsonify(data)


@app.route("/api/trace/<target>/revert", methods=["POST"])
def api_trace_revert(target):
    """Immediate revert-to-default -- David's ask: "a button to revert to default." Reads the target's
    captured-once default snapshot fresh and applies it via the same trace_set() everything else uses."""
    try:
        defaults = trace_defaults(target).get("defaults", {})
        if not defaults:
            return jsonify({"error": "No captured defaults for this target yet -- open Enhance Trace for it first."}), 400
        data = trace_set(target, {name: (v["enabled"], v["level"]) for name, v in defaults.items()})
    except ForescoutClientError as e:
        return jsonify({"error": str(e)}), 502
    _log_activity("trace_revert", target=target)
    return jsonify(data)


@app.route("/trace/cancel_revert", methods=["POST"])
def trace_cancel_revert():
    job_id = request.form.get("job_id", "").strip()
    cancel_trace_revert(job_id)
    return redirect(url_for("index"))


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


@app.route("/api/appliances", methods=["GET"])
def api_appliances():
    """Every known appliance + live online/offline status -- fetched once by the Appliances panel's JS on load."""
    try:
        return jsonify(list_appliances())
    except ForescoutClientError as e:
        return jsonify({"error": str(e)}), 502


DURATION_UNIT_RE = re.compile(r"^[mh]$")


@app.route("/appliances/run", methods=["POST"])
def do_appliances_run():
    """
    Starts one background "Run Show Errors" job per checked appliance
    (include_appliance_<target>=1 fields) and returns their run ids
    immediately -- each job can take several minutes, so this never
    blocks waiting for one to finish; the panel's JS polls
    /api/appliance_run/<id> per job instead. Any target that already has
    a run in progress is skipped, not queued or duplicated -- reported
    back separately in "skipped" so the UI can say so.
    """
    unit = request.form.get("duration_unit", "m").strip()
    value = request.form.get("duration_value", "30").strip()
    if not DURATION_UNIT_RE.match(unit) or not value.isdigit() or not (1 <= int(value) <= 9999):
        return jsonify({"error": "Invalid duration."}), 400
    duration = f"{value}{unit}"

    targets = [
        key[len("include_appliance_"):] for key, v in request.form.items()
        if key.startswith("include_appliance_") and v == "1"
    ]
    if not targets:
        return jsonify({"error": "Select at least one appliance."}), 400
    _log_activity("appliances_run", targets=targets, duration=duration)

    started, skipped = [], []
    for t in targets:
        run_id = start_show_errors_run(t, duration)
        if run_id is None:
            skipped.append(t)
        else:
            started.append({"target": t, "run_id": run_id})
    return jsonify({"runs": started, "skipped": skipped})


@app.route("/api/appliance_run/<run_id>", methods=["GET"])
def api_appliance_run(run_id):
    run = get_run(run_id)
    if run is None:
        return jsonify({"error": "unknown run id"}), 404
    return jsonify(run)


@app.route("/api/appliance_run/<run_id>/kill", methods=["POST"])
def api_appliance_run_kill(run_id):
    """
    Doesn't reach into and actually terminate a live background thread --
    there's no way to do that safely from a fresh request in this
    architecture, and in every real case seen so far the underlying
    subprocess was already dead anyway (a container redeploy kills the
    process mid-flight, but the run's "running" record survives in the
    bind-mounted JSON since that's a separate file). This just clears
    the stuck state: marks the run failed so the badge stops showing it
    and a new run against the same target is no longer refused as a
    duplicate. David's ask, after spotting a run that had genuinely been
    "running" for hours.
    """
    run = get_run(run_id)
    if run is None:
        return jsonify({"error": "unknown run id"}), 404
    if run["status"] != "running":
        return jsonify({"error": "run is not currently running"}), 400
    _update_run(run_id, status="failed", finished_at=int(time.time()), error="Manually killed (was stuck).")
    return jsonify({"ok": True})


CASE_REF_ERROR = "Case reference may only contain letters, numbers, '-' and '_' (max 40 chars)."


def _validate_case_ref():
    """Empty -> None (no case reference). Anything else must match CASE_REF_RE -- returns
    (case_ref, error_message_or_None)."""
    case_ref = request.form.get("case_ref", "").strip() or None
    if case_ref and not CASE_REF_RE.match(case_ref):
        return None, CASE_REF_ERROR
    return case_ref, None


COMPANY_ERROR = "Company name may only contain letters, numbers, '.', '-' and '_' (max 60 chars, no spaces)."


def _validate_company():
    """
    Empty -> None (forescout_client/webapp-query.py fall back to
    DEFAULT_COMPANY, "Yubique"). Anything else must match
    COMPANY_NAME_RE -- returns (company, error_message_or_None). David's
    ask, 2026-08-26: an editable override for what used to be hardcoded,
    shown in a box at the top of the Tech Support Bundle Generator tab
    (shared by both the Host and EM panels).
    """
    company = request.form.get("ts_company", "").strip() or None
    if company and not COMPANY_NAME_RE.match(company):
        return None, COMPANY_ERROR
    return company, None


def _parse_ts_send():
    """"Send support bundle directly to Forescout" tick box -- David's ask, 2026-08-26, in both the
    Appliance Host and EM panels. Threads fstool's own --send flag (alongside the existing --pack, not
    replacing it -- see _build_combined_bundle's own docstring for why) into the real build. A plain
    checkbox, sent or not sent depending on whether it's ticked -- no separate per-panel field name needed
    since both panels' buildFormData() use the same "ts_send" key."""
    return request.form.get("ts_send") == "1"


def _parse_ts_level_minutes():
    """Shared debug level + duration for the host debug-enable step (same value applied to every checked host's
    relevant plugins, per David's design) -- returns (level, minutes, error_message_or_None)."""
    level = request.form.get("ts_level", "4").strip()
    if not LEVEL_RE.match(level):
        return None, None, "Debug level must be 0-12."
    unit = request.form.get("ts_duration_unit", "m").strip()
    value = request.form.get("ts_duration_value", "60").strip()
    if not DURATION_UNIT_RE.match(unit) or not value.isdigit():
        return None, None, "Invalid duration."
    minutes = int(value) * 60 if unit == "h" else int(value)
    if not (1 <= minutes <= 1440):
        return None, None, "Duration must be between 1 minute and 24 hours."
    return level, minutes, None


def _checked_ts_plugins():
    """{target: [plugin, ...]} from checked include_plugin_<target>:<plugin>=1 fields -- Appliance Host panel
    only, populated client-side from the checked hosts' detected plugins, defaulting unchecked (David's
    established preference -- not every case needs every plugin's debug data). An empty dict is a legitimate
    result now (David's ask, 2026-08-26: a host doesn't necessarily need any plugin debugged at all -- a
    plain hostinfo/DB-table-only collection is valid) -- never passed on to preview_techsupport/
    collect_techsupport as-is though, since their "-"/None wire value means "no restriction, use the full
    auto-detected set," the opposite of what an all-unchecked table means here; callers pass this dict
    through unchanged, its emptiness is meaningful and must reach _selected_plugins_token as-is."""
    selected = {}
    for key, v in request.form.items():
        if key.startswith("include_plugin_") and v == "1":
            target, _, plugin = key[len("include_plugin_"):].partition(":")
            if target and plugin:
                selected.setdefault(target, []).append(plugin)
    return selected


def _checked_ts_dbtables():
    """{target: [table, ...]} from checked include_dbtable_<target>:<table>=1 fields -- Appliance Host panel
    only. David's ask, 2026-08-26 ("Attach DBs", after a same-day detour building it around whole separate
    databases first): a tick box per host reveals that target's significant tables (fstool's own `db
    diskspace`, from `databases` in the lookup response -- e.g. source_log, hostinfo), each independently
    checkable, attached via fstool's --dbtable. Defaults unchecked, same convention as plugin selection."""
    selected = {}
    for key, v in request.form.items():
        if key.startswith("include_dbtable_") and v == "1":
            target, _, table = key[len("include_dbtable_"):].partition(":")
            if target and table:
                selected.setdefault(target, []).append(table)
    return selected


def _checked_ts_hosts_and_em():
    """(host_ips, include_em, error_response_or_None) shared by preview and proceed."""
    host_ips = [
        key[len("include_ts_ip_"):] for key, v in request.form.items()
        if key.startswith("include_ts_ip_") and v == "1"
    ]
    include_em = request.form.get("include_ts_em") == "1"
    if not host_ips and not include_em:
        return None, None, (jsonify({"error": "Select at least one host or the EM."}), 400)
    return host_ips, include_em, None


@app.route("/techsupport/preview", methods=["POST"])
def do_techsupport_preview_route():
    """
    Read-only -- computes and returns the exact command sequence
    /techsupport/proceed would run for the checked hosts/EM at the given
    level/duration/case_ref, without starting anything. David's ask:
    "review the commands that are going to be run on the appliance
    before going ahead," shown in a confirm dialog with a Proceed button.
    """
    case_ref, err = _validate_case_ref()
    if err:
        return jsonify({"error": err}), 400
    company, comp_err = _validate_company()
    if comp_err:
        return jsonify({"error": comp_err}), 400
    send = _parse_ts_send()
    host_ips, include_em, resp = _checked_ts_hosts_and_em()
    if resp:
        return resp

    targets = []
    if host_ips:
        level, minutes, lvl_err = _parse_ts_level_minutes()
        if lvl_err:
            return jsonify({"error": lvl_err}), 400
        selected_plugins = _checked_ts_plugins()
        selected_dbtables = _checked_ts_dbtables()
        try:
            preview = preview_techsupport(
                host_ips, level, minutes, selected_plugins=selected_plugins,
                selected_dbtables=selected_dbtables, company=company, send=send, case_ref=case_ref,
            )
        except ForescoutClientError as e:
            return jsonify({"error": str(e)}), 502
        targets = preview.get("targets", [])

    if include_em:
        unit = request.form.get("em_duration_unit", "m").strip()
        value = request.form.get("em_duration_value", "60").strip()
        if not DURATION_UNIT_RE.match(unit) or not value.isdigit() or not (1 <= int(value) <= 9999):
            return jsonify({"error": "Invalid EM duration."}), 400
        duration = f"{value}{unit}"
        try:
            em_preview = preview_techsupport_em(duration, company=company, send=send, case_ref=case_ref)
        except ForescoutClientError as e:
            return jsonify({"error": str(e)}), 502
        # Folded into the same "targets" list as host-derived entries (not a separate "em" key) so the UI's
        # preview renderer stays one simple function regardless of which panel asked for it. Routed through
        # the real EM-side techsupportempreview verb (not hand-written text) -- David caught the old
        # hand-written version had drifted from what build_techsupport_em actually runs (wrong -comment
        # value, missing mkdir -p, one combined mv line shown instead of the real two separate ones).
        targets.extend(em_preview.get("targets", []))

    return jsonify({"targets": targets})


@app.route("/techsupport/proceed", methods=["POST"])
def do_techsupport_proceed():
    """
    The confirmed execution -- same inputs as /techsupport/preview
    (David's ask requires the Proceed button to send exactly what was
    just previewed). Starts up to two background jobs: one covering
    every checked host IP together (enable debug on every relevant
    plugin -> wait -> collect -> centralize onto the EM's shared case
    storage) and, separately, one for the EM if checked (a general
    bundle, no debug-enable step since there's no host to scope plugins
    from) -- returns their run ids immediately; the whole sequence can
    take well over the requested duration, so this never blocks the
    request that started it. The panel's JS polls /api/techsupport_run/
    <id> per job. A job is skipped, not queued or duplicated, if the
    exact same set of hosts (or the EM) already has a build running --
    reported back separately in "skipped" so the UI can say so, same
    pattern as /appliances/run.
    """
    case_ref, err = _validate_case_ref()
    if err:
        return jsonify({"error": err}), 400
    company, comp_err = _validate_company()
    if comp_err:
        return jsonify({"error": comp_err}), 400
    send = _parse_ts_send()
    host_ips, include_em, resp = _checked_ts_hosts_and_em()
    if resp:
        return resp
    _log_activity("techsupport_proceed", case_ref=case_ref, hosts=host_ips, include_em=include_em, send=send)

    started, skipped = [], []
    if host_ips:
        level, minutes, lvl_err = _parse_ts_level_minutes()
        if lvl_err:
            return jsonify({"error": lvl_err}), 400
        selected_plugins = _checked_ts_plugins()
        selected_dbtables = _checked_ts_dbtables()
        run_id = start_techsupport_run(
            "host", host_ips, case_ref, level=level, minutes=minutes,
            selected_plugins=selected_plugins, selected_dbtables=selected_dbtables, company=company, send=send,
        )
        key = ", ".join(sorted(host_ips))
        (skipped if run_id is None else started).append(key if run_id is None else {"key": key, "run_id": run_id})

    if include_em:
        unit = request.form.get("em_duration_unit", "m").strip()
        value = request.form.get("em_duration_value", "60").strip()
        if not DURATION_UNIT_RE.match(unit) or not value.isdigit() or not (1 <= int(value) <= 9999):
            return jsonify({"error": "Invalid EM duration."}), 400
        duration = f"{value}{unit}"
        run_id = start_techsupport_run("em", None, case_ref, duration=duration, company=company, send=send)
        (skipped if run_id is None else started).append("EM" if run_id is None else {"key": "EM", "run_id": run_id})

    return jsonify({"runs": started, "skipped": skipped})


@app.route("/api/techsupport_run/<run_id>", methods=["GET"])
def api_techsupport_run(run_id):
    run = get_ts_run(run_id)
    if run is None:
        return jsonify({"error": "unknown run id"}), 404
    return jsonify(run)


@app.route("/api/techsupport_log", methods=["GET"])
def api_techsupport_log():
    """
    David's ask, 2026-08-26: "once I hit the proceed button I need to
    see what commands are actually being run... logged to
    /tmp/ForeScoutTech-Support.log on the EM and at the same time to a
    popup window." Polled every few seconds by the popup opened right
    when Proceed is clicked -- returns the tail of that EM-side file
    (every real command the tech-support flow's own code paths execute:
    debug-enable, hostinfo/tech-support/--dbtable, centralize
    mkdir/scp/rm/split), so the popup shows genuinely what ran, not a
    hand-approximated preview. Best-effort: a transient SSH hiccup while
    polling shouldn't blow up the popup, just show a benign message
    until the next successful poll.
    """
    try:
        data = tail_techsupport_log()
    except ForescoutClientError as e:
        return jsonify({"log": f"(log temporarily unavailable: {e})"})
    return jsonify({"log": data.get("log", "")})


@app.route("/api/techsupport_run/<run_id>/kill", methods=["POST"])
def api_techsupport_run_kill(run_id):
    """Same reasoning as /api/appliance_run/<id>/kill -- clears a stuck "running" state (e.g. orphaned by a
    container redeploy mid-job) rather than actually reaching into a live thread."""
    run = get_ts_run(run_id)
    if run is None:
        return jsonify({"error": "unknown run id"}), 404
    if run["status"] != "running":
        return jsonify({"error": "run is not currently running"}), 400
    _update_ts_run(run_id, status="failed", finished_at=int(time.time()), error="Manually killed (was stuck).")
    return jsonify({"ok": True})


@app.route("/api/techsupport_run/<run_id>/delete", methods=["POST"])
def api_techsupport_run_delete(run_id):
    """Terminates and removes a tracked Review->Proceed job outright -- David's ask, 2026-08-27: "add a
    delete job, ie. term each review proceed session as a job." Distinct from /kill just above (which
    only flips a stuck "running" row to "failed" so the UI can unstick, keeping the record for history)
    and from /admin/clear_log/techsupport_runs (which wipes every tracked run at once) -- this drops ONE
    run's row entirely, regardless of its current status. A still-"running" row is no more reachable from
    here than /kill can reach it -- deleting just discards the tracked row; whatever SSH call is still in
    flight on the EM runs to completion or failure on its own, same honest limitation as /kill."""
    run = get_ts_run(run_id)
    if run is None:
        return jsonify({"error": "unknown run id"}), 404
    with _ts_runs_lock:
        runs = _load_ts_runs()
        runs = [r for r in runs if r["id"] != run_id]
        _save_ts_runs(runs)
    _log_activity("techsupport_run_delete", username=session.get("username"), run_id=run_id)
    return jsonify({"ok": True})


@app.route("/techsupport/download", methods=["GET"])
def techsupport_download_route():
    """
    Streams a built tech-support bundle (or its -commands.txt / split
    .part-xx sibling) straight through this app's own HTTPS session --
    David's ask, 2026-08-27: no more scp-ing bundles off the EM by hand
    once a build finishes. `path` is whatever a completed run's own
    bundles[].path (or .chunks[]) already reported back to the browser --
    never accepted as free text, and re-validated against the same
    /shared/shared/case/.../.../... shape on both this side and the EM's
    own forced-command wrapper before anything is opened.
    """
    path = request.args.get("path", "")
    try:
        proc = download_techsupport_bundle(path)
    except ForescoutClientError as e:
        return str(e), 400

    def generate():
        try:
            while True:
                chunk = proc.stdout.read(262144)
                if not chunk:
                    break
                yield chunk
        finally:
            proc.stdout.close()
            proc.wait()

    filename = os.path.basename(path) or "techsupport-bundle"
    return Response(
        generate(),
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/techsupport/cleanup", methods=["POST"])
def techsupport_cleanup_route():
    """
    Deletes a single built bundle/chunk/-commands.txt file off the EM's
    shared case storage -- David's ask, 2026-08-27: a Clean up button
    right next to each Download link. Same path-whitelist reasoning as
    the download route; no CSRF here, matching /admin/clear_log/<section>
    (the app's existing precedent for a destructive-but-narrow, already
    login-gated action).
    """
    path = request.form.get("path", "")
    try:
        delete_techsupport_bundle(path)
    except ForescoutClientError as e:
        return jsonify({"error": str(e)}), 400
    _log_activity("techsupport_bundle_cleanup", username=session.get("username"), path=path)
    return jsonify({"ok": True})


# ---------------------------------------------------------------------
# Clear log history -- David's ask, 2026-08-26: a Clear button (with a
# y/n confirm client-side -- window.confirm, nothing fancier needed for
# something this reversible-in-spirit-but-not-in-fact) for each of the
# log/history sections the app tracks. Six clearable sections: five
# plain local files under DATA_DIR, plus TS_LOG_PATH which lives on the
# EM (Round 30) and needs its own verb round-trip (clear_techsupport_log)
# rather than a local truncate. "scheduled_jobs" clears BOTH the
# pending-jobs queue and its fired-outcome log together -- clearing it
# also cancels whatever hasn't fired yet, not just erasing history; the
# button's own label says so explicitly rather than leaving that as a
# surprise.
# ---------------------------------------------------------------------
LOG_SECTIONS = {
    "scheduled_jobs": {"paths": [JOBS_PATH, LOG_PATH], "lock": _jobs_lock},
    "trace_jobs": {"paths": [TRACE_JOBS_PATH, TRACE_LOG_PATH], "lock": _trace_jobs_lock},
    "appliance_runs": {"paths": [RUNS_PATH], "lock": _runs_lock},
    "techsupport_runs": {"paths": [TS_RUNS_PATH], "lock": _ts_runs_lock},
    "case_history": {"paths": [CASE_LOG_PATH], "lock": None},
    "activity_log": {"paths": [ACTIVITY_LOG_PATH], "lock": None},
}


def _reset_log_file(path):
    """.json files (a list every loader expects) reset to "[]"; .jsonl append-only logs reset to empty.
    Atomic (.tmp + os.replace) for .json files, matching every other writer of these same files -- a plain
    truncate is enough for .jsonl since nothing here ever reads a partially-written line either."""
    if not os.path.isfile(path):
        return
    if path.endswith(".jsonl"):
        open(path, "w").close()
    else:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump([], f)
        os.replace(tmp, path)


@app.route("/admin/clear_log/<section>", methods=["POST"])
def clear_log_section(section):
    if section == "ts_command_log":
        try:
            clear_techsupport_log()
        except ForescoutClientError as e:
            return jsonify({"error": str(e)}), 502
        _log_activity("clear_log", section=section)
        return jsonify({"ok": True})

    spec = LOG_SECTIONS.get(section)
    if spec is None:
        return jsonify({"error": "unknown log section"}), 404
    if spec["lock"] is not None:
        with spec["lock"]:
            for path in spec["paths"]:
                _reset_log_file(path)
    else:
        for path in spec["paths"]:
            _reset_log_file(path)
    _log_activity("clear_log", section=section)
    return jsonify({"ok": True})


if __name__ == "__main__":
    # HTTPS -- David's ask, 2026-08-26 (Phase C, the EM-hosted package):
    # only engaged when Deploy.sh mounts real certs and sets both env
    # vars (see SESSION_COOKIE_SECURE above, which keys off the same
    # FORESCOUT_SSL_CERT). Unset on the .230 deployment (start.sh never
    # sets these), so that one keeps running plain HTTP exactly as
    # before -- this is additive, not a behavior change for the
    # existing deployment.
    _ssl_cert = os.environ.get("FORESCOUT_SSL_CERT")
    _ssl_key = os.environ.get("FORESCOUT_SSL_KEY")
    if _ssl_cert and _ssl_key:
        # The EM's own Apache key is passphrase-protected, so this can't
        # use Werkzeug's plain (certfile, keyfile) shortcut -- that path
        # calls load_cert_chain with no password and always fails on an
        # encrypted key. Building the SSLContext ourselves lets us pass
        # one. The passphrase itself is never in the image or the repo --
        # Deploy.sh only mounts it if an admin has dropped it by hand
        # into certs/key_password.txt on the EM.
        _ssl_key_password = None
        _ssl_key_password_file = os.environ.get("FORESCOUT_SSL_KEY_PASSWORD_FILE")
        if _ssl_key_password_file and os.path.isfile(_ssl_key_password_file):
            with open(_ssl_key_password_file) as f:
                _ssl_key_password = f.read().strip()
        _ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        _ssl_ctx.load_cert_chain(_ssl_cert, _ssl_key, password=_ssl_key_password or None)
        app.run(host="0.0.0.0", port=5000, ssl_context=_ssl_ctx)
    else:
        app.run(host="0.0.0.0", port=5000)
