#!/usr/bin/env python3
"""
roulette.py -- European Roulette, sharing the Fruit Machine's users/tokens.

Built from the design note at 06 - Personal/Build a Roulette simulation.md.
Read in full before writing this file -- see the ambiguity notes below for
the two places it left a rule underspecified and the interpretation taken.

A separate Flask Blueprint (not routes bolted onto app.py's game()) so it
can be wired into a future game-select screen without entangling the two
games' logic. Registered onto the SAME Flask app / SAME sqlite DB as the
fruit machine (app.py) -- it imports get_db(), current_user(), login_required,
and now_iso() from app.py rather than duplicating them, and reuses
users.tokens directly (no separate roulette balance), per the design note's
explicit "The same tokens can be used from the fruit machine."

Design note ambiguities, resolved as follows (flagged for David to confirm
or override -- see Roulette Build Notes.md in the vault for the same list):

1. "User David will be the Banker" -- read literally as a specific username,
   not a generalized "table host" role. BANKER_USERNAME below is a single
   constant, case-insensitive match, so re-pointing it later is a one-line
   change, not a redesign.
2. "Once all bets are placed the SPIN button becomes active" -- there's no
   per-player "I'm done betting" signal described, so this is implemented
   as "the SPIN button is enabled for the Banker once at least one bet
   exists in the current round" -- the Banker's own judgement decides when
   betting is actually over, same as a real dealer calling "no more bets."
"""

import random
import sqlite3

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from app import current_user, get_db, login_required, now_iso

roulette_bp = Blueprint("roulette", __name__, url_prefix="/roulette")

# --- design constants --------------------------------------------------
BANKER_USERNAME = "david"  # case-insensitive match against users.username

# European wheel: 0-36, single zero. Standard European layout colors --
# 0 is green, everything else follows the real wheel's red/black split.
RED_NUMBERS = {
    1, 3, 5, 7, 9, 12, 14, 16, 18, 19, 21, 23, 25, 27, 30, 32, 34, 36,
}


def number_color(n):
    if n == 0:
        return "green"
    return "red" if n in RED_NUMBERS else "black"


# Bet types implemented in this initial scaffold. Deliberately NOT
# included yet: split/street/corner/six-line ("inside" bets that need a
# clickable adjacency-aware betting grid) -- flagged as a follow-up in
# Roulette Build Notes.md, not attempted tonight. All payouts below are
# standard European roulette odds (not a design-note guess -- these are
# fixed by the rules of the game itself).
STRAIGHT_PAYOUT = 35   # single number
DOZEN_PAYOUT = 2       # 1-12 / 13-24 / 25-36
COLUMN_PAYOUT = 2      # three vertical columns of 12
EVEN_MONEY_PAYOUT = 1  # red/black, odd/even, low/high


def _dozen_of(n):
    if n == 0:
        return None
    return 0 if n <= 12 else (1 if n <= 24 else 2)


def _column_of(n):
    if n == 0:
        return None
    return (n - 1) % 3


def evaluate_bet(bet_type, bet_value, winning_number):
    """Returns the payout MULTIPLE (not amount) for a single bet against
    winning_number, or None if it lost. bet_value's meaning depends on
    bet_type: an int 0-36 for 'straight', 'red'/'black' for 'color',
    'odd'/'even' for 'parity', 'low'/'high' for 'range' (1-18 / 19-36),
    0/1/2 for 'dozen' and 'column'."""
    if bet_type == "straight":
        return STRAIGHT_PAYOUT if int(bet_value) == winning_number else None

    if bet_type == "color":
        if winning_number == 0:
            return None
        return EVEN_MONEY_PAYOUT if number_color(winning_number) == bet_value else None

    if bet_type == "parity":
        if winning_number == 0:
            return None
        is_even = (winning_number % 2 == 0)
        return EVEN_MONEY_PAYOUT if (bet_value == "even") == is_even else None

    if bet_type == "range":
        if winning_number == 0:
            return None
        in_low = 1 <= winning_number <= 18
        return EVEN_MONEY_PAYOUT if (bet_value == "low") == in_low else None

    if bet_type == "dozen":
        return DOZEN_PAYOUT if _dozen_of(winning_number) == int(bet_value) else None

    if bet_type == "column":
        return COLUMN_PAYOUT if _column_of(winning_number) == int(bet_value) else None

    return None


BET_TYPES = {"straight", "color", "parity", "range", "dozen", "column"}


def init_roulette_db():
    """Called once at import time alongside app.py's init_db() -- see the
    bottom of this file. Same IF NOT EXISTS / OR IGNORE pattern as
    app.py's init_db(), for the same reason: gunicorn runs multiple
    worker processes that each import this module and could race here."""
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS roulette_rounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            status TEXT NOT NULL DEFAULT 'betting',
            winning_number INTEGER,
            opened_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            resolved_at TEXT,
            FOREIGN KEY (opened_by) REFERENCES users (id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS roulette_bets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            round_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            bet_type TEXT NOT NULL,
            bet_value TEXT NOT NULL,
            amount INTEGER NOT NULL,
            payout INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (round_id) REFERENCES roulette_rounds (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    db.commit()


def is_banker(user):
    return user is not None and user["username"].lower() == BANKER_USERNAME.lower()


def get_open_round(db):
    """The single shared table -- at most one round in 'betting' status at
    a time. None if nobody has opened one yet."""
    return db.execute(
        "SELECT * FROM roulette_rounds WHERE status = 'betting' ORDER BY id DESC LIMIT 1"
    ).fetchone()


def get_round_bets(db, round_id):
    return db.execute(
        """
        SELECT roulette_bets.*, users.username
        FROM roulette_bets JOIN users ON roulette_bets.user_id = users.id
        WHERE round_id = ? ORDER BY roulette_bets.id
        """,
        (round_id,),
    ).fetchall()


@roulette_bp.route("/")
@login_required
def table():
    user = current_user()
    db = get_db()
    open_round = get_open_round(db)
    bets = get_round_bets(db, open_round["id"]) if open_round else []

    last_round = db.execute(
        "SELECT * FROM roulette_rounds WHERE status = 'resolved' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    last_bets = get_round_bets(db, last_round["id"]) if last_round else []

    return render_template(
        "roulette.html",
        user=user,
        is_banker=is_banker(user),
        open_round=open_round,
        bets=bets,
        last_round=last_round,
        last_bets=last_bets,
        number_color=number_color,
        numbers=list(range(37)),
    )


@roulette_bp.route("/new-round", methods=["POST"])
@login_required
def new_round():
    user = current_user()
    if not is_banker(user):
        flash("Only the Banker can open a new round.", "error")
        return redirect(url_for("roulette.table"))

    db = get_db()
    if get_open_round(db) is not None:
        flash("A round is already open for betting.", "error")
        return redirect(url_for("roulette.table"))

    db.execute(
        "INSERT INTO roulette_rounds (status, opened_by, created_at) VALUES ('betting', ?, ?)",
        (user["id"], now_iso()),
    )
    db.commit()
    flash("New round open -- place your bets.", "success")
    return redirect(url_for("roulette.table"))


@roulette_bp.route("/bet", methods=["POST"])
@login_required
def place_bet():
    user = current_user()
    db = get_db()
    open_round = get_open_round(db)
    if open_round is None:
        flash("No round open for betting -- wait for the Banker to open one.", "error")
        return redirect(url_for("roulette.table"))

    bet_type = request.form.get("bet_type", "")
    bet_value = request.form.get("bet_value", "")
    if bet_type not in BET_TYPES or not bet_value:
        flash("Invalid bet.", "error")
        return redirect(url_for("roulette.table"))
    if bet_type == "straight":
        try:
            if not (0 <= int(bet_value) <= 36):
                raise ValueError
        except ValueError:
            flash("Invalid number.", "error")
            return redirect(url_for("roulette.table"))
    elif bet_type in ("dozen", "column") and bet_value not in ("0", "1", "2"):
        flash("Invalid bet.", "error")
        return redirect(url_for("roulette.table"))
    elif bet_type == "color" and bet_value not in ("red", "black"):
        flash("Invalid bet.", "error")
        return redirect(url_for("roulette.table"))
    elif bet_type == "parity" and bet_value not in ("odd", "even"):
        flash("Invalid bet.", "error")
        return redirect(url_for("roulette.table"))
    elif bet_type == "range" and bet_value not in ("low", "high"):
        flash("Invalid bet.", "error")
        return redirect(url_for("roulette.table"))

    try:
        amount = int(request.form.get("amount", ""))
    except ValueError:
        amount = 0
    if amount <= 0:
        flash("Enter a positive bet amount.", "error")
        return redirect(url_for("roulette.table"))

    # Same atomic, race-safe pattern as the fruit machine's /spin --
    # deduct against the row's live value with a WHERE guard, not a
    # Python-computed new balance written back from an earlier read.
    cur = db.execute(
        "UPDATE users SET tokens = tokens - ?, total_spent = total_spent + ? "
        "WHERE id = ? AND tokens >= ?",
        (amount, amount, user["id"], amount),
    )
    if cur.rowcount == 0:
        db.rollback()
        flash("Not enough tokens for that bet.", "error")
        return redirect(url_for("roulette.table"))

    db.execute(
        "INSERT INTO roulette_bets (round_id, user_id, bet_type, bet_value, amount, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (open_round["id"], user["id"], bet_type, bet_value, amount, now_iso()),
    )
    db.commit()
    flash(f"Bet placed: {amount} tokens.", "success")
    return redirect(url_for("roulette.table"))


@roulette_bp.route("/spin", methods=["POST"])
@login_required
def spin():
    user = current_user()
    if not is_banker(user):
        flash("Only the Banker can spin.", "error")
        return redirect(url_for("roulette.table"))

    db = get_db()
    open_round = get_open_round(db)
    if open_round is None:
        flash("No round open.", "error")
        return redirect(url_for("roulette.table"))

    bets = get_round_bets(db, open_round["id"])
    if not bets:
        flash("No bets placed yet.", "error")
        return redirect(url_for("roulette.table"))

    winning_number = random.randint(0, 36)

    for bet in bets:
        multiple = evaluate_bet(bet["bet_type"], bet["bet_value"], winning_number)
        if multiple is not None:
            payout = bet["amount"] * (multiple + 1)  # stake returned + winnings
            db.execute(
                "UPDATE users SET tokens = tokens + ?, total_won = total_won + ? WHERE id = ?",
                (payout, payout, bet["user_id"]),
            )
            db.execute("UPDATE roulette_bets SET payout = ? WHERE id = ?", (payout, bet["id"]))
        else:
            db.execute("UPDATE roulette_bets SET payout = 0 WHERE id = ?", (bet["id"],))

    db.execute(
        "UPDATE roulette_rounds SET status = 'resolved', winning_number = ?, resolved_at = ? WHERE id = ?",
        (winning_number, now_iso(), open_round["id"]),
    )
    db.commit()

    flash(f"Wheel landed on {winning_number} ({number_color(winning_number)}).", "success")
    return redirect(url_for("roulette.table"))
