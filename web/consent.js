// Consent dialog for wedge:// sign requests.
//
// A continuous long-poll (App.pollPending) surfaces a parked sign
// request from the Go backend and shows this overlay. The user's click IS the
// mandatory user-presence signal that authorizes the signature — see
// docs/wedge-protocol.md §7. The decision goes back via App.respond. The loop
// runs alongside the settings/onboarding views; start it via startConsentLoop().

(function () {
  var current = null; // the request currently on screen
  var submitting = false; // double-submit guard
  var resolveDecision = null; // resolves the handle() promise once the user acts

  function el(id) { return document.getElementById(id); }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  function setDisabled(v) {
    ['consent-allow', 'consent-allow-always', 'consent-deny'].forEach(function (id) {
      var b = el(id);
      if (b) b.disabled = v;
    });
  }

  // render populates and shows the overlay for a request. Three modes:
  //  - newSite:          gated add-on-first-use — origin only (no network yet),
  //                      Add & Allow once / Add & Always allow / Deny.
  //  - alwaysAllow=true: minimal confirm line + Confirm / Deny (still a tap).
  //  - otherwise:        full detail + Allow once / Always allow / Deny.
  // All request values are attacker-influenced, so they go in via textContent.
  function render(request) {
    current = request;
    submitting = false;

    var newSite = request.newSite === true;
    var minimal = !newSite && request.alwaysAllow === true;

    el('consent-origin').textContent = request.origin || '';

    var challenge = request.challenge || '';
    if (challenge.length > 64) challenge = challenge.substring(0, 64) + '...';
    el('consent-challenge').textContent = challenge;

    var allow = el('consent-allow');
    var always = el('consent-allow-always');

    if (newSite) {
      el('consent-title').textContent = 'New site';
      el('consent-minimal-line').textContent =
        'wedge has never signed into ' + (request.origin || 'this site') + '. Add it?';
      el('consent-detail').hidden = true; // nothing fetched yet
      el('consent-minimal-line').hidden = false;
      allow.textContent = 'Add & Allow once';
      always.textContent = 'Add & Always allow';
      always.hidden = false;
    } else if (minimal) {
      el('consent-title').textContent = 'Confirm sign-in';
      el('consent-minimal-line').textContent =
        'Confirm sign-in to ' + (request.origin || 'this site');
      el('consent-detail').hidden = true;
      el('consent-minimal-line').hidden = false;
      allow.textContent = 'Confirm';
      always.hidden = true;
    } else {
      el('consent-title').textContent = 'Sign request';
      el('consent-detail').hidden = false;
      el('consent-minimal-line').hidden = true;
      allow.textContent = 'Allow once';
      always.textContent = 'Always allow';
      always.hidden = false;
    }

    setDisabled(false);
    el('consent-overlay').hidden = false;
    allow.focus();
  }

  // The three buttons map to different decision verbs for a new-site prompt vs a
  // known-site prompt.
  function decisionFor(role) {
    var newSite = current && current.newSite === true;
    if (role === 'deny') return 'deny';
    if (role === 'always') return newSite ? 'add-always' : 'allow-always';
    return newSite ? 'add-allow' : 'allow';
  }

  function hide() {
    el('consent-overlay').hidden = true;
    current = null;
  }

  function handle(request) {
    return new Promise(function (resolve) {
      resolveDecision = resolve;
      render(request);
    });
  }

  async function decide(decision) {
    if (submitting || !current) return;
    submitting = true;
    setDisabled(true);
    var id = current.id;
    try {
      await App.respond(id, decision);
    } catch (e) {
      console.error('sign respond failed:', e);
    }
    hide();
    var resolve = resolveDecision;
    resolveDecision = null;
    if (resolve) resolve();
  }

  async function loop() {
    for (;;) {
      try {
        var res = await App.pollPending();
        if (res && res.pending && res.request) {
          await handle(res.request); // blocks until the user decides
        }
      } catch (e) {
        await sleep(1000); // backend not ready / transient error — back off
      }
    }
  }

  function wire() {
    var allow = el('consent-allow');
    var always = el('consent-allow-always');
    var deny = el('consent-deny');
    if (allow) allow.addEventListener('click', function () { decide(decisionFor('primary')); });
    if (always) always.addEventListener('click', function () { decide(decisionFor('always')); });
    if (deny) deny.addEventListener('click', function () { decide(decisionFor('deny')); });

    document.addEventListener('keydown', function (e) {
      if (el('consent-overlay').hidden) return;
      if (e.key === 'Enter') {
        e.preventDefault();
        decide(decisionFor('primary'));
      } else if (e.key === 'Escape') {
        e.preventDefault();
        decide(decisionFor('deny'));
      }
    });
  }

  // Started from main.js after DOM ready so polling runs regardless of whether
  // the settings or onboarding view is active.
  window.startConsentLoop = function () {
    wire();
    loop();
  };
})();
