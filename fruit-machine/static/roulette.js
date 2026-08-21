// Rebuilds the "Value" select's options to match whichever bet type is
// currently chosen -- a straight bet needs 0-36, but color/parity/range
// need a fixed pair of words and dozen/column need 0/1/2, not a raw
// number. Without this, selecting anything but "straight" would submit
// a number where the server expects "red"/"black"/etc. and every other
// bet type would be unusable.
(function () {
    const typeEl = document.getElementById("bet-type");
    const valueEl = document.getElementById("bet-value");
    if (!typeEl || !valueEl) return;

    const OPTIONS = {
        straight: Array.from({ length: 37 }, (_, n) => [String(n), String(n)]),
        color: [["red", "Red"], ["black", "Black"]],
        parity: [["odd", "Odd"], ["even", "Even"]],
        range: [["low", "Low (1-18)"], ["high", "High (19-36)"]],
        dozen: [["0", "1st 12 (1-12)"], ["1", "2nd 12 (13-24)"], ["2", "3rd 12 (25-36)"]],
        column: [["0", "Column 1"], ["1", "Column 2"], ["2", "Column 3"]],
    };

    function rebuild() {
        const opts = OPTIONS[typeEl.value] || OPTIONS.straight;
        valueEl.innerHTML = "";
        opts.forEach(([value, label]) => {
            const opt = document.createElement("option");
            opt.value = value;
            opt.textContent = label;
            valueEl.appendChild(opt);
        });
    }

    typeEl.addEventListener("change", rebuild);
    rebuild();
})();

// Spin animation: table rolls down and out, the wheel appears and spins,
// then zooms in on the winning number. All purely cosmetic -- the result
// was already decided server-side in roulette.py's /spin before this
// page even loaded (see data-winning-number/data-target-rotation on
// #roulette-stage); this never influences the outcome, same principle
// as the fruit machine's spin.js. Plays at most once per browser session
// per resolved round (see should_animate_spin in roulette.py) so a page
// reload doesn't replay it endlessly.
window.__rouletteAnimating = false;

(function () {
    const stage = document.getElementById("roulette-stage");
    if (!stage || stage.dataset.shouldAnimate !== "true") return;

    window.__rouletteAnimating = true;

    const bettingArea = document.getElementById("roulette-betting-area");
    const wheelScene = document.getElementById("roulette-wheel-scene");
    const wheel = document.getElementById("roulette-wheel");
    const resultEl = document.getElementById("roulette-wheel-result");
    // Both of these are rendered server-side with the real winning number
    // already in them (the "Last spin" banner in the betting area, and
    // the sidebar's "Last Round" card) -- kept visibility:hidden by the
    // template until the spin animation actually finishes, same reveal-
    // timing principle as the fruit machine, so neither spoils the wheel
    // before it stops.
    const lastSpinBanner = document.getElementById("roulette-last-spin-banner");
    const lastRoundCard = document.getElementById("roulette-last-round-card");
    if (!bettingArea || !wheelScene || !wheel || !resultEl) return;

    const targetRotation = parseFloat(stage.dataset.targetRotation || "0");
    const winningNumber = stage.dataset.winningNumber;
    const winningColor = stage.dataset.winningColor;

    const ROLL_AWAY_MS = 650;
    const SPIN_MS = 4000;
    const ZOOM_MS = 1200;
    const RESULT_HOLD_MS = 3500;

    setTimeout(() => {
        bettingArea.classList.add("rolling-away");
    }, 100);

    setTimeout(() => {
        bettingArea.style.display = "none";
        wheelScene.classList.add("showing");
        // Force a reflow so the browser registers the wheel's starting
        // (unrotated) state before the transition below kicks in --
        // otherwise the very first spin can sometimes jump straight to
        // the end angle instead of animating through it.
        void wheel.offsetWidth;
        wheel.style.transform = "rotate(" + targetRotation + "deg)";
    }, ROLL_AWAY_MS);

    setTimeout(() => {
        wheelScene.classList.add("zoomed");
        resultEl.textContent = winningNumber;
        resultEl.className = "roulette-wheel-result roulette-wheel-result-" + winningColor;
        if (lastSpinBanner) lastSpinBanner.style.visibility = "visible";
        if (lastRoundCard) lastRoundCard.style.visibility = "visible";
    }, ROLL_AWAY_MS + SPIN_MS);

    setTimeout(() => {
        wheelScene.classList.remove("zoomed", "showing");
        bettingArea.style.display = "";
        bettingArea.classList.remove("rolling-away");
        window.__rouletteAnimating = false;
    }, ROLL_AWAY_MS + SPIN_MS + ZOOM_MS + RESULT_HOLD_MS);
})();

// Auto-refresh: the table is shared across multiple players with no
// push/websocket layer, so the only way to see someone else's bet (or
// the Banker opening a new round) land without manually reloading is to
// poll. Reloads the whole page every REFRESH_MS -- skipped, not just
// delayed, on any tick where either:
//   - the spin animation is currently mid-sequence (reloading would cut
//     it off and skip straight to the static result), or
//   - focus is inside the bet form (reloading would wipe out an amount
//     or selection the player hasn't submitted yet).
// Both are re-checked on every tick, so a refresh happens as soon as
// neither is true anymore rather than being silently skipped forever.
(function () {
    const REFRESH_MS = 8000;
    const betForm = document.querySelector(".roulette-bet-form");

    function focusInBetForm() {
        return !!betForm && betForm.contains(document.activeElement);
    }

    setInterval(() => {
        if (document.hidden) return; // don't reload a backgrounded tab
        if (window.__rouletteAnimating) return;
        if (focusInBetForm()) return;
        location.reload();
    }, REFRESH_MS);
})();
