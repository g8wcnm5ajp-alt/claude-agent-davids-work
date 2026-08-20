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

    if (!shouldSpin) return;

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

    // The token count, win/lose result, and nudge availability are all
    // already resolved server-side by the time this page loads (the DB
    // write happens in /spin, before the redirect here) -- reveal them 1s
    // after the *last* reel actually stops, not immediately, so none of
    // it spoils the spin while it's still visually rotating.
    const revealDelayMs = stopDelays[stopDelays.length - 1] + 1000;
    setTimeout(() => {
        const tokenEl = document.getElementById("token-count");
        if (tokenEl) tokenEl.textContent = tokenEl.dataset.final;

        const resultEl = document.getElementById("spin-result");
        if (resultEl) resultEl.style.visibility = "visible";

        const nudgeEl = document.getElementById("nudge-controls");
        if (nudgeEl) nudgeEl.style.visibility = "visible";
    }, revealDelayMs);
})();
