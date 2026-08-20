#!/usr/bin/env python3
"""
app.py -- Fruit Machine web app.

Built from the design note at 06 - Personal/Fruit-Machine-Fun-Project/
Build a fun simulation fruit machine..md.

Flask + sqlite3 (stdlib), no ORM. Session-based auth via Flask's signed
cookies. Wheel count and win probability are admin-adjustable at runtime
(the `settings` table / get_settings()); per-symbol rarity and payouts
(SYMBOL_WEIGHTS / PAYOUTS below) are still fixed constants.
"""

import os
import random
import sqlite3
from collections import Counter
from datetime import datetime, timezone

from flask import Flask, g, redirect, render_template, request, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.environ.get("FRUIT_MACHINE_DB", "/data/fruit_machine.db")
STARTING_TOKENS = 100
SPIN_COST = 1
DEFAULT_ADMIN_PASSWORD = os.environ.get("FRUIT_MACHINE_ADMIN_PASSWORD", "fruit-admin-2026")

# --- game design -----------------------------------------------------------
#
# A spin is decided in two steps, not by independently randomizing three
# reels and checking if they happen to match -- that makes the real win
# probability hard to reason about or tune. Instead:
#   1. Roll a weighted "does this spin win?" check (WIN_PROBABILITY).
#   2. If it wins, weighted-pick WHICH symbol makes the winning triple
#      (SYMBOL_WEIGHTS) -- so the jackpot symbol is much rarer than a
#      small win, not equally likely.
#   3. If it doesn't win, generate three reels that are deliberately NOT
#      a triple (retry until they aren't), so a "no win" spin is a real
#      near-miss, never an accidental match.
#
# Requested odds: "weighted 8:2 in favour of the fruit machine" -- read as
# an overall ~80/20 house edge: about 1 spin in 5 wins something. This is
# now the *default* -- both this and the number of wheels are admin-
# adjustable at runtime (see the `settings` table / get_settings() below),
# not fixed constants.
DEFAULT_WIN_PROBABILITY = 0.20
DEFAULT_NUM_WHEELS = 3
MIN_WHEELS, MAX_WHEELS = 3, 5
MIN_WIN_PROBABILITY, MAX_WIN_PROBABILITY = 0.01, 0.99

# Nudge feature: free (no token cost). Triggered when a losing spin is
# exactly one wheel away from a full match -- generalizes the design
# note's "two of the same" trigger (which is exactly this condition for
# the default 3-wheel machine) to any wheel count. The player gets a
# random number of nudge credits (admin-adjustable range, defaults below)
# to bump that one wheel up/down through the fixed SYMBOLS order (with
# wraparound), seeing the adjacent symbols before committing, same as a
# real fruit machine's nudge feature. No time limit -- the player nudges
# (or doesn't) at their own pace and presses START to confirm whatever
# arrangement they're left with, which is when it's actually scored.
DEFAULT_NUDGE_MIN, DEFAULT_NUDGE_MAX = 1, 6
ABSOLUTE_NUDGE_MIN, ABSOLUTE_NUDGE_MAX = 0, 10

SYMBOLS = ["\U0001F352", "\U0001F34B", "\U0001F34A", "\U0001F347", "\U0001F34E", "\U0001F514", "7️⃣"]
# cherry, lemon, orange, grapes, apple, bell, seven

# Weight of each symbol WHEN a spin has already been decided to win --
# cherries (the top prize, per the design note's "top prize" line) are the
# rarest; the seven and bell are mid-tier; the plain fruits are the most
# common small win.
SYMBOL_WEIGHTS = {
    "\U0001F352": 5,    # cherry -- jackpot, rare
    "7️⃣": 10,  # seven
    "\U0001F514": 15,   # bell
    "\U0001F34B": 17.5,  # lemon
    "\U0001F34A": 17.5,  # orange
    "\U0001F347": 17.5,  # grapes
    "\U0001F34E": 17.5,  # apple
}

PAYOUTS = {
    "\U0001F352": 50,   # cherry -- top prize
    "7️⃣": 30,  # seven
    "\U0001F514": 20,   # bell
    "\U0001F34B": 10, "\U0001F34A": 10, "\U0001F347": 10, "\U0001F34E": 10,
}

def get_or_create_secret_key():
    """A random-per-process secret key breaks sessions the moment there's
    more than one process serving requests: gunicorn runs multiple worker
    processes, each importing this module (and so re-running any
    os.urandom() at import time) independently. Confirmed live: a session
    cookie signed by one worker failed signature verification on another,
    which Flask silently treats as "no session" rather than an error --
    requests randomly looked logged-out depending on which worker picked
    them up. Persisting the key in the same volume as the DB fixes it for
    every worker, and survives container restarts too (an unpersisted key
    would just log everyone out on every restart)."""
    env_key = os.environ.get("FRUIT_MACHINE_SECRET_KEY")
    if env_key:
        return env_key.encode()

    key_path = os.path.join(os.path.dirname(DB_PATH), ".secret_key")
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    try:
        fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            key = os.urandom(32)
            os.write(fd, key)
        finally:
            os.close(fd)
        return key
    except FileExistsError:
        # Another worker/process won the race to create it -- read what
        # they wrote instead of generating a second, different key.
        with open(key_path, "rb") as f:
            return f.read()


app = Flask(__name__)
app.secret_key = get_or_create_secret_key()


def _static_version():
    """Cache-busting suffix for static assets (?v=<mtime>) -- Flask's
    default static file serving doesn't change the URL when a file's
    content changes, so a browser that already cached spin.js from a
    previous deploy can keep silently running stale JS against a fresh
    backend after a redeploy (confirmed live: a fixed backend plus a
    browser-cached old spin.js reproduced the exact bug the fix was
    supposed to remove). Computed once from the file's mtime at process
    start, not per-request."""
    try:
        return str(int(os.path.getmtime(os.path.join(app.static_folder, "spin.js"))))
    except OSError:
        return "0"


STATIC_VERSION = _static_version()


@app.context_processor
def inject_static_version():
    return {"static_version": STATIC_VERSION}


# --- db ----------------------------------------------------------------
def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        # timeout=5: wait up to 5s for a lock held by another gunicorn
        # worker's connection instead of failing immediately -- confirmed
        # via live testing that concurrent writes from multiple workers
        # are a real, expected occurrence here, not a hypothetical.
        g.db = sqlite3.connect(DB_PATH, timeout=5)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            tokens INTEGER NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            total_won INTEGER NOT NULL DEFAULT 0,
            total_spent INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    db.commit()

    # INSERT OR IGNORE rather than check-then-insert: gunicorn runs
    # multiple worker processes, each importing this module and calling
    # init_db() independently on startup. A check-then-insert has a race
    # between them (seen for real: two workers both see "no admin row
    # yet" and both try to INSERT, the second hits a UNIQUE constraint
    # violation and crashes) -- OR IGNORE makes the insert atomic and a
    # harmless no-op if another worker already won the race.
    db.execute(
        "INSERT OR IGNORE INTO users (username, password_hash, tokens, is_admin, created_at) "
        "VALUES (?, ?, ?, 1, ?)",
        ("admin", generate_password_hash(DEFAULT_ADMIN_PASSWORD), 0, now_iso()),
    )
    db.commit()

    db.execute(
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    db.commit()
    # Same INSERT OR IGNORE rationale as the admin user above -- multiple
    # gunicorn workers each call init_db() independently on startup.
    db.executemany(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
        [
            ("num_wheels", str(DEFAULT_NUM_WHEELS)),
            ("win_probability", str(DEFAULT_WIN_PROBABILITY)),
            ("nudge_min", str(DEFAULT_NUDGE_MIN)),
            ("nudge_max", str(DEFAULT_NUDGE_MAX)),
        ],
    )
    db.commit()


def get_settings():
    """Admin-adjustable game settings, read fresh from the DB on every
    call rather than cached -- request volume here is low enough (a fun
    project, not a high-traffic service) that the simplicity of "always
    current" outweighs any benefit from caching."""
    rows = get_db().execute("SELECT key, value FROM settings").fetchall()
    values = {row["key"]: row["value"] for row in rows}
    return {
        "num_wheels": int(values.get("num_wheels", DEFAULT_NUM_WHEELS)),
        "win_probability": float(values.get("win_probability", DEFAULT_WIN_PROBABILITY)),
        "nudge_min": int(values.get("nudge_min", DEFAULT_NUDGE_MIN)),
        "nudge_max": int(values.get("nudge_max", DEFAULT_NUDGE_MAX)),
    }


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# --- auth helpers --------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    if uid is None:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(view):
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


def admin_required(view):
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if not user["is_admin"]:
            flash("Admin access required.", "error")
            return redirect(url_for("game"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


# --- game logic ------------------------------------------------------------
def spin_reels(num_wheels, win_probability):
    """Returns (list of num_wheels symbols, win, payout). A win is still
    ALL wheels matching (generalized from the original fixed-3-wheel
    "row of three" rule) -- more wheels only changes the visual
    spectacle of a win, not the actual odds, since win/lose is decided by
    the win_probability gate below, not by independently-random wheels
    happening to agree."""
    if random.random() < win_probability:
        symbols = list(SYMBOL_WEIGHTS.keys())
        weights = list(SYMBOL_WEIGHTS.values())
        winning_symbol = random.choices(symbols, weights=weights, k=1)[0]
        return [winning_symbol] * num_wheels, True, PAYOUTS[winning_symbol]

    # Deliberately not an all-match -- retry until the wheels differ from
    # a real all-of-a-kind, so a losing spin is a genuine near-miss rather
    # than an accidental match slipping through.
    while True:
        reels = [random.choice(SYMBOLS) for _ in range(num_wheels)]
        if len(set(reels)) > 1:
            return reels, False, 0


def find_nudge_reels(reels):
    """Returns the list of "off" wheel indices whenever at least two
    wheels already match and it's not already a full win -- every wheel
    NOT showing the majority symbol becomes independently nudgeable. With
    exactly 3 wheels this is always a single reel (2 match -> 1 is off),
    but with 4-5 wheels, 2 matching still leaves 2-3 reels off, and each
    of those should be nudgeable, not just one. Returns [] if there's no
    match at all (every wheel different) or it's already a full win."""
    if len(reels) < 3:
        return []
    majority_symbol, majority_count = Counter(reels).most_common(1)[0]
    if majority_count < 2 or majority_count == len(reels):
        return []
    return [i for i, s in enumerate(reels) if s != majority_symbol]


# --- routes: auth --------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")
        if username.lower() == "admin":
            flash("That username is reserved.", "error")
            return render_template("register.html")

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing is not None:
            flash("That username is already taken.", "error")
            return render_template("register.html")

        db.execute(
            "INSERT INTO users (username, password_hash, tokens, created_at) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), STARTING_TOKENS, now_iso()),
        )
        db.commit()
        user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        session["user_id"] = user["id"]
        flash(f"Welcome, {username}! You start with {STARTING_TOKENS} tokens.", "success")
        return redirect(url_for("game"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        session["user_id"] = user["id"]
        if user["is_admin"]:
            return redirect(url_for("admin_panel"))
        return redirect(url_for("game"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- routes: game ----------------------------------------------------------
@app.route("/")
@login_required
def game():
    user = current_user()
    db = get_db()

    leaderboard = db.execute(
        "SELECT username, tokens FROM users WHERE is_admin = 0 ORDER BY tokens DESC LIMIT 10"
    ).fetchall()
    totals = db.execute(
        "SELECT COALESCE(SUM(total_spent), 0) AS spent, COALESCE(SUM(total_won), 0) AS won "
        "FROM users WHERE is_admin = 0"
    ).fetchone()
    house_net = totals["spent"] - totals["won"]

    last_reels = session.pop("last_reels", None)
    last_win = session.pop("last_win", None)
    last_payout = session.pop("last_payout", None)
    # "spin" -> this page load is the immediate aftermath of a fresh
    # /spin, so the reel-stop animation is about to run and the token
    # count / result / nudge availability should all stay hidden until it
    # finishes (see spin.js). "nudge" -> a nudge confirmation just
    # concluded (via /spin while a nudge was pending) -- no reel animation
    # runs for that, so nothing needs to wait; reveal immediately.
    last_source = session.pop("last_source", None)
    settings = get_settings()

    # The DB is already updated by the time this page renders (the atomic
    # UPDATE happened in /spin or /nudge), but the reel-stop animation is
    # purely client-side and takes ~1s+ to finish -- showing the *new*
    # token count and win/lose result immediately would spoil the spin
    # before it visually resolves. tokens_before_spin lets the template
    # show the pre-spin count first; JS reveals the real numbers once the
    # reels have actually stopped (see spin.js). Only computed for a
    # fresh spin -- a nudge conclusion reveals immediately, so the
    # "before" value is irrelevant there.
    tokens_before_spin = (
        (user["tokens"] - last_payout + SPIN_COST) if (last_reels and last_source == "spin") else None
    )

    # nudge_previews maps EVERY currently-nudgeable reel index to its own
    # up/down preview symbols -- with more than 3 wheels, a near-miss can
    # leave more than one reel eligible at once (e.g. 2 of 5 wheels match,
    # leaving 3 off), and each of those needs its own preview, not just a
    # single reel's. Empty once credits run out, since there's nothing
    # left to spend on a nudge -- the player's only move at that point is
    # to press START and confirm whatever they're left with.
    nudge_state = session.get("nudge_state")
    nudge_previews = {}
    nudge_credits = None
    if nudge_state:
        nudge_credits = nudge_state["credits"]
        if nudge_credits > 0:
            for idx in nudge_state["reel_indices"]:
                pos = SYMBOLS.index(nudge_state["reels"][idx])
                nudge_previews[idx] = {
                    "up": SYMBOLS[(pos + 1) % len(SYMBOLS)],
                    "down": SYMBOLS[(pos - 1) % len(SYMBOLS)],
                }

    return render_template(
        "game.html", user=user, leaderboard=leaderboard,
        house_spent=totals["spent"], house_won=totals["won"], house_net=house_net,
        last_reels=last_reels, last_win=last_win, last_payout=last_payout,
        symbols=SYMBOLS, num_wheels=settings["num_wheels"],
        tokens_before_spin=tokens_before_spin,
        should_delay_reveal=(last_source == "spin"),
        nudge_active=(nudge_state is not None),
        nudge_previews=nudge_previews,
        nudge_credits=nudge_credits,
        nudge_reels=(nudge_state["reels"] if nudge_state else None),
    )


@app.route("/spin", methods=["POST"])
@login_required
def spin():
    user = current_user()
    db = get_db()
    settings = get_settings()

    # An active nudge opportunity means START now means "confirm" rather
    # than "spin again" -- score whatever arrangement the player nudged
    # their way to (or left untouched), free, since the spin cost was
    # already charged when the original spin happened.
    nudge_state = session.get("nudge_state")
    if nudge_state:
        reels = nudge_state["reels"]
        full_win = len(set(reels)) == 1
        payout = PAYOUTS[reels[0]] if full_win else 0
        if full_win:
            db.execute(
                "UPDATE users SET tokens = tokens + ?, total_won = total_won + ? WHERE id = ?",
                (payout, payout, user["id"]),
            )
            db.commit()
        session["last_reels"] = reels
        session["last_win"] = full_win
        session["last_payout"] = payout
        session["last_source"] = "nudge"
        session.pop("nudge_state", None)
        return redirect(url_for("game"))

    reels, win, payout = spin_reels(settings["num_wheels"], settings["win_probability"])

    # Atomic, race-safe update computed entirely in SQL relative to the
    # row's CURRENT value at write time (tokens = tokens - cost + payout),
    # with a WHERE guard against going negative -- not a Python-computed
    # new_tokens written back from a separately-read row. Gunicorn runs
    # multiple worker processes, and the read-then-write version of this
    # raced for real: 3 rapid spins from one session only debited tokens
    # for 2 of them (a classic lost update between two workers).
    cur = db.execute(
        "UPDATE users SET tokens = tokens - ? + ?, total_spent = total_spent + ?, total_won = total_won + ? "
        "WHERE id = ? AND tokens >= ?",
        (SPIN_COST, payout, SPIN_COST, payout, user["id"], SPIN_COST),
    )
    db.commit()

    if cur.rowcount == 0:
        flash("Out of tokens -- ask an admin to top you up.", "error")
        return redirect(url_for("game"))

    session["last_reels"] = reels
    session["last_win"] = win
    session["last_payout"] = payout
    session["last_source"] = "spin"

    if not win and settings["nudge_max"] > 0:
        nudge_indices = find_nudge_reels(reels)
        if nudge_indices:
            session["nudge_state"] = {
                "reels": list(reels),
                "reel_indices": nudge_indices,
                "credits": random.randint(settings["nudge_min"], settings["nudge_max"]),
            }

    return redirect(url_for("game"))


@app.route("/nudge/<int:reel_index>/<direction>", methods=["POST"])
@login_required
def nudge(reel_index, direction):
    if direction not in ("up", "down"):
        flash("Invalid nudge direction.", "error")
        return redirect(url_for("game"))

    nudge_state = session.get("nudge_state")
    if not nudge_state or nudge_state["credits"] <= 0:
        flash("No nudges available.", "error")
        return redirect(url_for("game"))

    if reel_index not in nudge_state["reel_indices"]:
        flash("That wheel isn't nudgeable.", "error")
        return redirect(url_for("game"))

    reels = nudge_state["reels"]
    pos = SYMBOLS.index(reels[reel_index])
    # Free (no token cost) -- fixed reel order, wraps around at the ends.
    new_pos = (pos + 1) % len(SYMBOLS) if direction == "up" else (pos - 1) % len(SYMBOLS)
    reels[reel_index] = SYMBOLS[new_pos]
    nudge_state["credits"] -= 1

    # Recompute which wheels are still nudgeable -- the wheel just nudged
    # might now match a different, larger group than before (or, if it
    # completed a full match, none at all). Nothing is scored here: the
    # player presses START to confirm whatever arrangement they're left
    # with, whether that's now, after more nudges, or after running out
    # of credits -- see /spin's nudge_state branch.
    nudge_state["reel_indices"] = find_nudge_reels(reels)
    session["nudge_state"] = nudge_state

    return redirect(url_for("game"))


# --- routes: admin ---------------------------------------------------------
@app.route("/admin")
@admin_required
def admin_panel():
    users = get_db().execute(
        "SELECT * FROM users WHERE is_admin = 0 ORDER BY username"
    ).fetchall()
    return render_template(
        "admin.html", users=users, admin=current_user(), settings=get_settings(),
        min_wheels=MIN_WHEELS, max_wheels=MAX_WHEELS,
        absolute_nudge_min=ABSOLUTE_NUDGE_MIN, absolute_nudge_max=ABSOLUTE_NUDGE_MAX,
    )


@app.route("/admin/settings", methods=["POST"])
@admin_required
def admin_settings():
    try:
        num_wheels = int(request.form.get("num_wheels", ""))
        win_probability_pct = float(request.form.get("win_probability_pct", ""))
        nudge_min = int(request.form.get("nudge_min", ""))
        nudge_max = int(request.form.get("nudge_max", ""))
    except ValueError:
        flash("Wheels, win chance, and nudge credits must all be numbers.", "error")
        return redirect(url_for("admin_panel"))

    if not (MIN_WHEELS <= num_wheels <= MAX_WHEELS):
        flash(f"Number of wheels must be between {MIN_WHEELS} and {MAX_WHEELS}.", "error")
        return redirect(url_for("admin_panel"))

    win_probability = win_probability_pct / 100.0
    if not (MIN_WIN_PROBABILITY <= win_probability <= MAX_WIN_PROBABILITY):
        flash(f"Win chance must be between {MIN_WIN_PROBABILITY*100:.0f}% and {MAX_WIN_PROBABILITY*100:.0f}%.", "error")
        return redirect(url_for("admin_panel"))

    if not (ABSOLUTE_NUDGE_MIN <= nudge_min <= ABSOLUTE_NUDGE_MAX) or not (ABSOLUTE_NUDGE_MIN <= nudge_max <= ABSOLUTE_NUDGE_MAX):
        flash(f"Nudge credits must be between {ABSOLUTE_NUDGE_MIN} and {ABSOLUTE_NUDGE_MAX}.", "error")
        return redirect(url_for("admin_panel"))
    if nudge_min > nudge_max:
        flash("Min nudge credits can't be greater than max.", "error")
        return redirect(url_for("admin_panel"))

    db = get_db()
    db.execute("UPDATE settings SET value = ? WHERE key = 'num_wheels'", (str(num_wheels),))
    db.execute("UPDATE settings SET value = ? WHERE key = 'win_probability'", (str(win_probability),))
    db.execute("UPDATE settings SET value = ? WHERE key = 'nudge_min'", (str(nudge_min),))
    db.execute("UPDATE settings SET value = ? WHERE key = 'nudge_max'", (str(nudge_max),))
    db.commit()
    flash(
        f"Settings updated: {num_wheels} wheels, {win_probability_pct:.0f}% win chance, "
        f"{nudge_min}-{nudge_max} nudge credits.", "success",
    )
    return redirect(url_for("admin_panel"))


@app.route("/admin/reset/<int:user_id>", methods=["POST"])
@admin_required
def admin_reset(user_id):
    db = get_db()
    db.execute(
        "UPDATE users SET tokens = ?, total_won = 0, total_spent = 0 WHERE id = ? AND is_admin = 0",
        (STARTING_TOKENS, user_id),
    )
    db.commit()
    flash("Account reset.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/add-tokens/<int:user_id>", methods=["POST"])
@admin_required
def admin_add_tokens(user_id):
    try:
        amount = int(request.form.get("amount", "0"))
    except ValueError:
        amount = 0
    if amount <= 0:
        flash("Enter a positive number of tokens to add.", "error")
        return redirect(url_for("admin_panel"))

    db = get_db()
    db.execute(
        "UPDATE users SET tokens = tokens + ? WHERE id = ? AND is_admin = 0",
        (amount, user_id),
    )
    db.commit()
    flash(f"Added {amount} tokens.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/delete/<int:user_id>", methods=["POST"])
@admin_required
def admin_delete(user_id):
    db = get_db()
    cur = db.execute("DELETE FROM users WHERE id = ? AND is_admin = 0", (user_id,))
    db.commit()
    if cur.rowcount:
        flash("Account deleted.", "success")
    else:
        flash("No such account.", "error")
    return redirect(url_for("admin_panel"))


@app.route("/admin/change-password", methods=["POST"])
@admin_required
def admin_change_password():
    new_password = request.form.get("new_password", "")
    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
        return redirect(url_for("admin_panel"))

    db = get_db()
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), session["user_id"]),
    )
    db.commit()
    flash("Admin password changed.", "success")
    return redirect(url_for("admin_panel"))


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
