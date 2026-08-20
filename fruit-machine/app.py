#!/usr/bin/env python3
"""
app.py -- Fruit Machine web app.

Built from the design note at 06 - Personal/Fruit-Machine-Fun-Project/
Build a fun simulation fruit machine..md.

Flask + sqlite3 (stdlib), no ORM. Session-based auth via Flask's signed
cookies. All game odds live in one place (WIN_PROBABILITY / SYMBOL_WEIGHTS
/ PAYOUTS below) so the house edge is easy to see and tune.
"""

import os
import random
import sqlite3
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
# an overall ~80/20 house edge: about 1 spin in 5 wins something.
WIN_PROBABILITY = 0.20

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
def spin_reels():
    """Returns (list of 3 symbols, win, payout)."""
    if random.random() < WIN_PROBABILITY:
        symbols = list(SYMBOL_WEIGHTS.keys())
        weights = list(SYMBOL_WEIGHTS.values())
        winning_symbol = random.choices(symbols, weights=weights, k=1)[0]
        return [winning_symbol] * 3, True, PAYOUTS[winning_symbol]

    # Deliberately not a triple -- retry until the three reels differ from
    # a real 3-of-a-kind, so a losing spin is a genuine near-miss rather
    # than an accidental match slipping through.
    while True:
        reels = [random.choice(SYMBOLS) for _ in range(3)]
        if len(set(reels)) > 1:
            return reels, False, 0


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

    return render_template(
        "game.html", user=user, leaderboard=leaderboard,
        house_spent=totals["spent"], house_won=totals["won"], house_net=house_net,
        last_reels=last_reels, last_win=last_win, last_payout=last_payout,
        symbols=SYMBOLS,
    )


@app.route("/spin", methods=["POST"])
@login_required
def spin():
    user = current_user()
    db = get_db()

    reels, win, payout = spin_reels()

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
    return redirect(url_for("game"))


# --- routes: admin ---------------------------------------------------------
@app.route("/admin")
@admin_required
def admin_panel():
    users = get_db().execute(
        "SELECT * FROM users WHERE is_admin = 0 ORDER BY username"
    ).fetchall()
    return render_template("admin.html", users=users, admin=current_user())


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
