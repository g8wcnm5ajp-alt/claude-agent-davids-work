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
                upBtn.innerHTML = "&#9650; " + previews[reelIndex].up;
            }
            if (downBtn) {
                downBtn.disabled = false;
                downBtn.classList.add("nudge-active");
                downBtn.innerHTML = "&#9660; " + previews[reelIndex].down;
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
            if (symbolEl && finalSymbols[i] !== undefined) symbolEl.textContent = finalSymbols[i];
        });
        reveal();
        return;
    }

    reelEls.forEach((reel) => reel.classList.add("spinning"));

    const spinDurationMs = 900;
    const tickMs = 80;
    const stopStaggerMs = 300;
    // Generalized for any number of wheels (3-5, admin-configurable) --
    // each wheel stops stopStaggerMs after the previous one.
    const stopDelays = Array.from(reelEls, (_, i) => spinDurationMs + i * stopStaggerMs);

    reelEls.forEach((reel, i) => {
        const symbolEl = reel.querySelector(".reel-symbol");
        const interval = setInterval(() => {
            symbolEl.textContent = allSymbols[Math.floor(Math.random() * allSymbols.length)];
        }, tickMs);

        setTimeout(() => {
            clearInterval(interval);
            reel.classList.remove("spinning");
            symbolEl.textContent = finalSymbols[i];
        }, stopDelays[i]);
    });

    const revealDelayMs = stopDelays[stopDelays.length - 1] + 1000;
    setTimeout(reveal, revealDelayMs);
})();
