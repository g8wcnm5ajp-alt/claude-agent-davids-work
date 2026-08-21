// Purely cosmetic: briefly animates the reels through random symbols
// before landing on the real result the server already computed (passed
// in via the #reels element's data attributes). The actual win/loss
// outcome is decided server-side in app.py -- this never influences it.
(function () {
    const reelsEl = document.getElementById("reels");
    if (!reelsEl) return;

    const shouldSpin = reelsEl.dataset.spin === "true";
    const finalSymbols = reelsEl.dataset.final.split(",");
    const allSymbols = reelsEl.dataset.symbols.split(",");
    const reelEls = reelsEl.querySelectorAll(".reel");
    // Which reel indices actually animate: every reel for a fresh spin,
    // only the re-rolled one(s) for a HOLD & RE-SPIN result (the held
    // reels can't change, so they never animate -- see /hold in app.py).
    const rerollIndices = new Set(
        (reelsEl.dataset.reroll || "").split(",").filter((s) => s !== "").map(Number)
    );
    // Maps a symbol string to the username it belongs to, for the reel
    // slots that are a player's icon rather than a fixed fruit -- the
    // rest of the pool renders as plain emoji text.
    const iconMap = JSON.parse(reelsEl.dataset.iconMap || "{}");

    function escapeHtml(s) {
        return s.replace(/[&<>"']/g, (c) => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
        }[c]));
    }

    // Usernames are user-supplied at registration and end up in innerHTML
    // (the alt text below) -- escape before ever concatenating into markup.
    function iconMarkup(username, extraClass) {
        const safeUser = escapeHtml(username);
        return '<img class="reel-icon' + (extraClass ? " " + extraClass : "") +
            '" src="/icon/' + encodeURIComponent(username) + '.svg" alt="' + safeUser + '">';
    }

    function setReelSymbol(symbolEl, symbol) {
        const username = iconMap[symbol];
        if (username) {
            symbolEl.innerHTML = iconMarkup(username);
        } else {
            symbolEl.textContent = symbol;
        }
    }

    // Builds the arrow + preview markup for a nudge button -- an icon
    // preview gets a small thumbnail next to the arrow, a fruit gets the
    // emoji as before.
    function nudgeButtonMarkup(arrowEntity, symbol) {
        const username = iconMap[symbol];
        if (username) {
            return arrowEntity + " " + iconMarkup(username, "reel-icon-tiny");
        }
        return arrowEntity + " " + symbol;
    }

    // The token count, win/lose result, nudge-credits indicator, and
    // nudge buttons are all already resolved server-side by the time this
    // page loads -- but showing them immediately would spoil a fresh spin
    // before its reel animation visually finishes. Called either right
    // away (no animation running -- e.g. a nudge action, a nudge
    // confirmation, or a plain reload) or after the reel-stop delay (a
    // fresh spin just happened).
    function reveal() {
        const tokenEl = document.getElementById("token-count");
        if (tokenEl) tokenEl.textContent = tokenEl.dataset.final;

        const resultEl = document.getElementById("spin-result");
        if (resultEl) resultEl.style.visibility = "visible";

        const sideNoteEl = document.getElementById("spin-side-note");
        if (sideNoteEl) sideNoteEl.style.visibility = "visible";

        const creditsEl = document.getElementById("nudge-credits-indicator");
        if (creditsEl) creditsEl.style.visibility = "visible";

        // With more than 3 wheels, a near-miss can leave more than one
        // reel eligible at once (e.g. 2 of 5 wheels match, leaving 3
        // off) -- activate every reel index present in the preview map,
        // not just one.
        const previews = JSON.parse(reelsEl.dataset.nudgePreviews || "{}");
        Object.keys(previews).forEach((reelIndex) => {
            const upBtn = reelsEl.querySelector('.nudge-up[data-reel-index="' + reelIndex + '"]');
            const downBtn = reelsEl.querySelector('.nudge-down[data-reel-index="' + reelIndex + '"]');
            if (upBtn) {
                upBtn.disabled = false;
                upBtn.classList.add("nudge-active");
                upBtn.innerHTML = nudgeButtonMarkup("&#9650;", previews[reelIndex].up);
            }
            if (downBtn) {
                downBtn.disabled = false;
                downBtn.classList.add("nudge-active");
                downBtn.innerHTML = nudgeButtonMarkup("&#9660;", previews[reelIndex].down);
            }
        });
    }

    if (!shouldSpin) {
        // No animation runs on this load (nudge action/confirmation, or a
        // plain reload) -- the reel symbols still need to be set from the
        // server-computed result, same as the animated branch below does
        // at its last tick. Previously missing entirely, which left every
        // reel showing the template's placeholder "?" instead of the
        // actual nudged-into-place symbol.
        reelEls.forEach((reel, i) => {
            const symbolEl = reel.querySelector(".reel-symbol");
            if (symbolEl && finalSymbols[i] !== undefined) setReelSymbol(symbolEl, finalSymbols[i]);
        });
        reveal();
        return;
    }

    const spinDurationMs = 900;
    const tickMs = 80;
    const stopStaggerMs = 300;
    // Generalized for any number of wheels (3-5, admin-configurable) --
    // each wheel stops stopStaggerMs after the previous one.
    const stopDelays = Array.from(reelEls, (_, i) => spinDurationMs + i * stopStaggerMs);

    let lastRerollStop = 0;
    reelEls.forEach((reel, i) => {
        const symbolEl = reel.querySelector(".reel-symbol");

        if (!rerollIndices.has(i)) {
            // Held reel (or every reel is eligible but this one just isn't
            // in the reroll set, e.g. a non-hold load) -- it can't change,
            // so set it once and skip the animation entirely.
            setReelSymbol(symbolEl, finalSymbols[i]);
            return;
        }

        lastRerollStop = Math.max(lastRerollStop, stopDelays[i]);
        reel.classList.add("spinning");
        const interval = setInterval(() => {
            setReelSymbol(symbolEl, allSymbols[Math.floor(Math.random() * allSymbols.length)]);
        }, tickMs);

        setTimeout(() => {
            clearInterval(interval);
            reel.classList.remove("spinning");
            setReelSymbol(symbolEl, finalSymbols[i]);
        }, stopDelays[i]);
    });

    const revealDelayMs = (lastRerollStop || spinDurationMs) + 1000;
    setTimeout(reveal, revealDelayMs);
})();
