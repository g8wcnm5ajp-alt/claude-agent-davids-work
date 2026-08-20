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
    const stopDelays = [spinDurationMs, spinDurationMs + 300, spinDurationMs + 600];

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
})();
