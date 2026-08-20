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

    // The token count, win/lose result, nudge-credits indicator, and the
    // one eligible reel's nudge buttons are all already resolved server-
    // side by the time this page loads -- but showing them immediately
    // would spoil a fresh spin before its reel animation visually
    // finishes. Called either right away (no animation running -- e.g. a
    // nudge action, or a plain reload while a nudge is still pending) or
    // after the reel-stop delay (a fresh spin just happened).
    let revealDelayMs = 0;

    function reveal() {
        const tokenEl = document.getElementById("token-count");
        if (tokenEl) tokenEl.textContent = tokenEl.dataset.final;

        const resultEl = document.getElementById("spin-result");
        if (resultEl) resultEl.style.visibility = "visible";

        const creditsEl = document.getElementById("nudge-credits-indicator");
        if (creditsEl) {
            creditsEl.style.visibility = "visible";

            // seconds_remaining was computed server-side at the moment
            // /spin ran, before the reel animation played out client-side
            // -- subtract however long that took so the visible countdown
            // reflects what's actually left of the real 10s window, not a
            // countdown that starts fresh once the animation finishes.
            const countdownEl = document.getElementById("nudge-countdown");
            let secondsLeft = Math.max(0, Math.round(parseInt(creditsEl.dataset.seconds, 10) - revealDelayMs / 1000));

            const activeButtons = () => reelsEl.querySelectorAll(".nudge-btn.nudge-active");

            function tick() {
                if (countdownEl) countdownEl.textContent = secondsLeft;
                if (secondsLeft <= 0) {
                    clearInterval(countdownTimer);
                    // Window closed client-side -- revert to the plain,
                    // disabled look. The server independently rejects any
                    // click that arrives after the real deadline anyway,
                    // this is just matching visual feedback.
                    activeButtons().forEach((btn) => {
                        btn.disabled = true;
                        btn.classList.remove("nudge-active");
                        btn.innerHTML = btn.classList.contains("nudge-up") ? "&#9650;" : "&#9660;";
                    });
                    if (creditsEl) creditsEl.style.display = "none";
                    return;
                }
                secondsLeft -= 1;
            }
            tick();
            const countdownTimer = setInterval(tick, 1000);
        }

        const nudgeReelIndex = reelsEl.dataset.nudgeReel;
        if (nudgeReelIndex !== "") {
            const upBtn = reelsEl.querySelector('.nudge-up[data-reel-index="' + nudgeReelIndex + '"]');
            const downBtn = reelsEl.querySelector('.nudge-down[data-reel-index="' + nudgeReelIndex + '"]');
            if (upBtn) {
                upBtn.disabled = false;
                upBtn.classList.add("nudge-active");
                upBtn.innerHTML = "&#9650; " + reelsEl.dataset.nudgeUp;
            }
            if (downBtn) {
                downBtn.disabled = false;
                downBtn.classList.add("nudge-active");
                downBtn.innerHTML = "&#9660; " + reelsEl.dataset.nudgeDown;
            }
        }
    }

    if (!shouldSpin) {
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

    revealDelayMs = stopDelays[stopDelays.length - 1] + 1000;
    setTimeout(reveal, revealDelayMs);
})();
