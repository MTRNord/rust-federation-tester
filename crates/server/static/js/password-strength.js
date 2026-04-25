// Shared password strength indicator.
// Mirrors the server-side entropy formula: entropy = length × log2(pool_size)
// Pool: lowercase (26) + uppercase (26) + digits (10) + other ASCII (32)
// Server requirements: uppercase, lowercase, digit, special character, entropy >= 55 bits.
(function (global) {
    var LEVELS = [
        { max: 40,       label: "Very weak",   color: "#d4351c", pct: 10,  accepted: false },
        { max: 55,       label: "Weak",        color: "#f47738", pct: 30,  accepted: false },
        { max: 65,       label: "Fair",        color: "#ffdd00", pct: 55,  accepted: true  },
        { max: 80,       label: "Strong",      color: "#00703c", pct: 80,  accepted: true  },
        { max: Infinity, label: "Very strong", color: "#005a30", pct: 100, accepted: true  },
    ];

    function passwordEntropy(pw) {
        if (!pw) return 0;
        var pool = 0;
        if (/[a-z]/.test(pw)) pool += 26;
        if (/[A-Z]/.test(pw)) pool += 26;
        if (/[0-9]/.test(pw)) pool += 10;
        if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
        if (pool === 0) return 0;
        return pw.length * Math.log2(pool);
    }

    // Attach a live strength indicator to a password field.
    //
    // opts (all string element IDs):
    //   inputId     — password input (required)
    //   barId       — fill bar element, e.g. .password-strength__bar-fill (required)
    //   labelId     — text label, e.g. "Fair (62 bits)" (required)
    //   hintId      — accepted / rejected hint (optional)
    //   confirmId   — confirm-password input (optional)
    //   matchHintId — confirm match/mismatch hint (optional)
    function initPasswordStrength(opts) {
        var input     = document.getElementById(opts.inputId);
        var bar       = document.getElementById(opts.barId);
        var label     = document.getElementById(opts.labelId);
        var hint      = opts.hintId      ? document.getElementById(opts.hintId)      : null;
        var confirm   = opts.confirmId   ? document.getElementById(opts.confirmId)   : null;
        var matchHint = opts.matchHintId ? document.getElementById(opts.matchHintId) : null;

        if (!input || !bar || !label) return;

        function updateStrength() {
            var entropy = passwordEntropy(input.value);
            if (!input.value) {
                bar.style.width = "0";
                bar.style.backgroundColor = "";
                label.textContent = "";
                label.style.color = "";
                if (hint) hint.textContent = "";
                return;
            }
            var lvl = LEVELS.find(function (l) { return entropy < l.max; });
            var textColor = lvl.color === "#ffdd00" ? "#594d00" : lvl.color;
            bar.style.width = lvl.pct + "%";
            bar.style.backgroundColor = lvl.color;
            label.textContent = lvl.label + " (" + Math.round(entropy) + " bits)";
            label.style.color = textColor;
            if (hint) {
                var issues = checkRequirements(input.value);
                if (issues.length > 0) {
                    hint.textContent = "✗ Missing: " + issues.join(", ");
                    hint.style.color = "#d4351c";
                } else if (!lvl.accepted) {
                    hint.textContent = "✗ Too weak — aim for at least Fair";
                    hint.style.color = "#d4351c";
                } else {
                    hint.textContent = "✓ Meets all requirements";
                    hint.style.color = "#00703c";
                }
            }
            if (confirm && confirm.value) updateMatch();
        }

        function updateMatch() {
            if (!confirm || !matchHint) return;
            if (!confirm.value) { matchHint.textContent = ""; return; }
            if (confirm.value === input.value) {
                matchHint.textContent = "✓ Passwords match";
                matchHint.style.color = "#00703c";
            } else {
                matchHint.textContent = "✗ Passwords do not match";
                matchHint.style.color = "#d4351c";
            }
        }

        input.addEventListener("input", updateStrength);
        if (confirm) confirm.addEventListener("input", updateMatch);
    }

    function checkRequirements(pw) {
        var issues = [];
        if (pw.length < 8)              issues.push("at least 8 characters");
        if (!/[A-Z]/.test(pw))          issues.push("one uppercase letter");
        if (!/[a-z]/.test(pw))          issues.push("one lowercase letter");
        if (!/[0-9]/.test(pw))          issues.push("one number");
        if (!/[^a-zA-Z0-9]/.test(pw))   issues.push("one special character");
        return issues;
    }

    global.passwordEntropy = passwordEntropy;
    global.checkRequirements = checkRequirements;
    global.initPasswordStrength = initPasswordStrength;
})(window);
