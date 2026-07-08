// api.js — local HTTP API shim, replacing the old Wails bindings.
// The Go backend serves this UI and the /api/* endpoints on the same loopback
// origin, so every call here is same-origin. The server enforces a same-origin
// (Origin/Referer == Host) check, which the browser sets automatically on
// fetch — no CSRF token to manage on the client.

async function apiGet(path) {
  const res = await fetch(path, { headers: { Accept: 'application/json' } });
  const data = await res.json().catch(function () { return {}; });
  if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);
  return data;
}

async function apiPost(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {})
  });
  const data = await res.json().catch(function () { return {}; });
  if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status);
  return data;
}

// App mirrors the surface the old Wails-bound `window.go.main.App` exposed, so
// the view code changes as little as possible.
window.App = {
  getConfig: function () { return apiGet('/api/config'); },
  setConfig: function (cfg) { return apiPost('/api/config', cfg); },
  setEnabled: function (enabled) {
    return apiPost('/api/enabled', { enabled: enabled }).then(function (d) { return d.config; });
  },
  // Discovered ~/.ssh public keys, each with whether it's loaded in the agent.
  getKeys: function () { return apiGet('/api/keys'); },
  // Launch a configured site in the default browser (reuses a running instance).
  openSite: function (origin) { return apiPost('/api/open', { origin: origin }); },
  getStatus: function () { return apiGet('/api/status'); },
  getSignLog: function () { return apiGet('/api/signlog'); },

  // Long-poll for a parked wedge:// sign request. The server holds the request
  // open (~25s) and returns {pending:false} on timeout or {pending:true,
  // request:{...}}. Callers loop; on a network error, back off ~1s and retry.
  pollPending: function () { return apiGet('/api/pending'); },
  // Return the user's decision for a pending sign request. For a known site:
  // "allow" | "allow-always" | "deny". For a new-site prompt: "add-allow" |
  // "add-always" | "deny".
  respond: function (id, decision) { return apiPost('/api/respond', { id: id, decision: decision }); }
};
