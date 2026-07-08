/* wedge.js — browser side of "Sign in with wedge".
 *
 * LOCKSTEP COPY: identical files at sdk/python/wedge_rp/static/wedge.js and
 * sdk/go/wedgerp/wedge.js — change all three together (the endpoint
 * contract they target is the same).
 *
 * Served by the wedge-rp adapters at /wedge/wedge.js. Talks only to the
 * matching wedge-rp endpoints on the same origin: POST /wedge/start to mint a
 * request (the response carries the wedge:// link), open the link so the OS
 * hands it to the wedge app, then poll GET /wedge/status until the sign-in
 * completes. The binding cookie set by /wedge/start rides along automatically.
 *
 * Usage:
 *   <script src="/wedge/wedge.js"></script>
 *   <button id="wedge-btn">Sign in with wedge</button>
 *   <script>Wedge.attach(document.getElementById("wedge-btn"));</script>
 *
 * Options (Wedge.attach(el, opts) / Wedge.signIn(opts)):
 *   usernameInput — CSS selector of an input whose value is sent as the
 *                   asserted username (omit for keyless sign-in)
 *   onStatus      — callback(state) for "opening" | "waiting"
 *   onError       — callback(Error); defaults to console.error
 *   pollMs, timeoutMs — polling cadence (default 1500 / 60000)
 */
(function () {
  "use strict";

  async function signIn(opts) {
    opts = opts || {};
    var startUrl = opts.startUrl || "/wedge/start";
    var statusUrl = opts.statusUrl || "/wedge/status";
    var notify = opts.onStatus || function () {};

    var username;
    if (opts.username) {
      username = opts.username;
    } else if (opts.usernameInput) {
      var input = document.querySelector(opts.usernameInput);
      if (input && input.value.trim()) username = input.value.trim();
    }

    var res = await fetch(startUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(username ? { username: username } : {}),
    });
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok || !data.ok) {
      throw new Error(data.error || "could not start sign-in");
    }

    notify("opening");
    window.location.href = data.link; // the OS routes wedge:// to the wedge app

    notify("waiting");
    var deadline = Date.now() + (opts.timeoutMs || 60000);
    while (Date.now() < deadline) {
      await new Promise(function (r) { setTimeout(r, opts.pollMs || 1500); });
      var poll = await fetch(
        statusUrl + "?request_id=" + encodeURIComponent(data.request_id),
        { credentials: "same-origin" }
      );
      var st = await poll.json().catch(function () { return {}; });
      if (st.status === "authenticated") {
        window.location.href = st.redirect || "/";
        return;
      }
      if (st.status === "denied" || st.status === "expired") {
        throw new Error("sign-in " + st.status);
      }
    }
    throw new Error("sign-in timed out");
  }

  function attach(el, opts) {
    opts = opts || {};
    el.addEventListener("click", function (ev) {
      ev.preventDefault();
      signIn(opts).catch(opts.onError || console.error);
    });
  }

  window.Wedge = { signIn: signIn, attach: attach };
})();
