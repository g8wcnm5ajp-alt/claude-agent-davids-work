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
