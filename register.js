document.addEventListener('DOMContentLoaded', function () {

    /* ----------------------------------------------------------------
       Generic helper: wire up a field so its popout slides open while
       the field is focused, and closes on blur.
       ---------------------------------------------------------------- */
    function wirePopout(inputEl, popoutEl) {
        if (!inputEl || !popoutEl) return;

        inputEl.addEventListener('focus', function () {
            popoutEl.classList.add('active');
        });

        inputEl.addEventListener('blur', function () {
            popoutEl.classList.remove('active');
        });
    }

    /* ----------------------------------------------------------------
       Email requirements
       ---------------------------------------------------------------- */
    var email = document.getElementById('email');
    var emailPopout = document.getElementById('emailPopout');

    var emailChecks = {
        'email-req-at': function (v) { return /@/.test(v); },
        'email-req-domain': function (v) { return /@[^\s@]+\.[^\s@]+/.test(v); },
        'email-req-nospace': function (v) { return v.length > 0 && !/\s/.test(v); }
    };

    function updateEmailChecklist() {
        var v = email.value || '';

        Object.keys(emailChecks).forEach(function (id) {
            var el = document.getElementById(id);
            if (!el) return;
            el.classList.toggle('met', emailChecks[id](v));
        });
    }

    if (email) {
        wirePopout(email, emailPopout);
        email.addEventListener('input', updateEmailChecklist);
        email.addEventListener('focus', updateEmailChecklist);
        updateEmailChecklist();
    }

    /* ----------------------------------------------------------------
       Password requirements + strength bar
       ---------------------------------------------------------------- */
    var pw = document.getElementById('password');
    var pwPopout = document.getElementById('passwordPopout');
    var progressBar = document.getElementById('pwProgressBar');

    var pwChecks = {
        'pw-req-length': function (v) { return v.length >= 8 && v.length <= 20; },
        'pw-req-upper': function (v) { return /[A-Z]/.test(v); },
        'pw-req-lower': function (v) { return /[a-z]/.test(v); },
        'pw-req-special': function (v) { return /[^A-Za-z0-9]/.test(v); }
    };

    function updatePasswordChecklist() {
        var v = pw.value || '';
        var metCount = 0;
        var total = 0;

        Object.keys(pwChecks).forEach(function (id) {
            var el = document.getElementById(id);
            total++;
            var met = pwChecks[id](v);
            if (met) metCount++;
            if (el) el.classList.toggle('met', met);
        });

        if (progressBar) {
            progressBar.style.width = (metCount / total) * 100 + '%';
        }
    }

    if (pw) {
        wirePopout(pw, pwPopout);
        pw.addEventListener('input', updatePasswordChecklist);
        pw.addEventListener('focus', updatePasswordChecklist);
        updatePasswordChecklist();
    }
});