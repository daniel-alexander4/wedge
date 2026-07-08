// Settings view.

var MAX_SITE_ROWS = 100;

function setStatus(text, level) {
  var el = document.getElementById('status');
  if (!el) return;
  el.textContent = text;
  el.classList.remove('status-success', 'status-error');
  if (level) el.classList.add('status-' + level);
  el.hidden = !text;
}

function renderToggle(enabled) {
  var btn = document.getElementById('toggle-enabled');
  if (!btn) return;
  btn.setAttribute('aria-pressed', enabled ? 'true' : 'false');
  btn.textContent = enabled ? 'On' : 'Off';
}

// renderKeysList populates a read-only list of the ~/.ssh keys wedge discovered,
// each flagged with whether it's loaded in the ssh-agent (only those can sign).
async function renderKeysList(containerId) {
  var container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';
  var keys = [];
  try {
    var data = await App.getKeys();
    keys = (data && data.keys) || [];
  } catch (e) {
    container.textContent = 'Could not load keys: ' + (e.message || e);
    return;
  }
  if (keys.length === 0) {
    container.textContent = 'No public keys found in ~/.ssh.';
    return;
  }
  keys.forEach(function (k) {
    var row = document.createElement('div');
    row.className = 'key-row';

    var name = document.createElement('span');
    name.className = 'key-name';
    name.textContent = (k.comment || k.fingerprint || '(key)') + (k.type ? ' · ' + k.type : '');

    var badge = document.createElement('span');
    badge.className = 'key-badge ' + (k.agentLoaded ? 'loaded' : 'not-loaded');
    badge.textContent = k.agentLoaded ? 'loaded ✓' : 'not loaded';
    if (!k.agentLoaded) badge.title = 'Run ssh-add ' + (k.path || '').replace(/\.pub$/, '') + ' to use this key';

    row.appendChild(name);
    row.appendChild(badge);
    container.appendChild(row);
  });
}

function createSiteRow(origin, alwaysAllow, silent) {
  var row = document.createElement('div');
  row.className = 'origin-row';

  var originInput = document.createElement('input');
  originInput.type = 'text';
  originInput.placeholder = 'https://example.com';
  originInput.value = origin || '';
  originInput.className = 'origin-input';
  originInput.addEventListener('input', function () { validateSiteRow(row); });

  var autoLabel = document.createElement('label');
  autoLabel.className = 'auto-allow';
  autoLabel.title = 'Always allow — skip the detail screen for this site (you still confirm each sign with a presence tap)';
  var autoInput = document.createElement('input');
  autoInput.type = 'checkbox';
  autoInput.className = 'auto-input';
  autoInput.checked = !!alwaysAllow;
  autoLabel.appendChild(autoInput);
  autoLabel.appendChild(document.createTextNode('auto'));

  var silentLabel = document.createElement('label');
  silentLabel.className = 'auto-allow';
  silentLabel.title = 'Advanced: sign for this site WITHOUT a presence tap. Reopens the phishing risk for this one site — leave off unless you understand it.';
  var silentInput = document.createElement('input');
  silentInput.type = 'checkbox';
  silentInput.className = 'silent-input';
  silentInput.checked = !!silent;
  silentLabel.appendChild(silentInput);
  silentLabel.appendChild(document.createTextNode('silent'));

  var launchBtn = document.createElement('span');
  launchBtn.className = 'launch-row-btn';
  launchBtn.textContent = '↗';
  launchBtn.setAttribute('role', 'button');
  launchBtn.setAttribute('aria-label', 'Open site in browser');
  launchBtn.title = 'Open this site in your default browser';
  launchBtn.tabIndex = 0;
  function launch() {
    var raw = originInput.value.trim();
    if (!raw) return;
    var url = '';
    try { url = new URL(raw).origin; } catch (e) { setStatus('Invalid site URL', 'error'); return; }
    App.openSite(url)
      .then(function () { setStatus('Opened ' + url, 'success'); })
      .catch(function (err) { setStatus('Could not open: ' + (err.message || err), 'error'); });
  }
  launchBtn.addEventListener('click', launch);
  launchBtn.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); launch(); }
  });

  var removeBtn = document.createElement('span');
  removeBtn.className = 'remove-row-btn';
  removeBtn.textContent = '🗑';
  removeBtn.setAttribute('role', 'button');
  removeBtn.setAttribute('aria-label', 'Remove site');
  removeBtn.tabIndex = 0;
  function removeRow() {
    row.remove();
    updateNoSitesWarning();
  }
  removeBtn.addEventListener('click', removeRow);
  removeBtn.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
      e.preventDefault();
      removeRow();
    }
  });

  row.appendChild(originInput);
  row.appendChild(autoLabel);
  row.appendChild(silentLabel);
  row.appendChild(launchBtn);
  row.appendChild(removeBtn);
  return row;
}

function validateSiteRow(row) {
  var originInput = row.querySelector('.origin-input');
  var valid = true;
  var raw = originInput.value.trim();
  if (raw) {
    try { new URL(raw); originInput.classList.remove('invalid'); }
    catch (e) { originInput.classList.add('invalid'); valid = false; }
  } else {
    originInput.classList.remove('invalid');
  }
  updateNoSitesWarning();
  return valid;
}

function collectSites(containerId) {
  containerId = containerId || 'origin-rows';
  var container = document.getElementById(containerId);
  var out = [];
  var invalidLines = [];
  if (!container) return { values: out, invalidLines: invalidLines };

  var rows = container.querySelectorAll('.origin-row');
  if (rows.length > MAX_SITE_ROWS) {
    return { values: out, invalidLines: ['Too many sites (max ' + MAX_SITE_ROWS + ')'] };
  }

  var seen = {};
  rows.forEach(function (row) {
    var originInput = row.querySelector('.origin-input');
    var autoInput = row.querySelector('.auto-input');
    var silentInput = row.querySelector('.silent-input');
    var raw = originInput.value.trim();
    if (!raw) return;

    var origin = '';
    try { origin = new URL(raw).origin; }
    catch (e) { invalidLines.push(raw + ' — invalid URL'); return; }

    if (seen[origin]) return;
    seen[origin] = true;

    var site = { origin: origin };
    if (autoInput && autoInput.checked) site.alwaysAllow = true;
    if (silentInput && silentInput.checked) site.silent = true;
    out.push(site);
  });

  return { values: out, invalidLines: invalidLines };
}

function renderSiteRows(sites, containerId) {
  containerId = containerId || 'origin-rows';
  var container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';

  (Array.isArray(sites) ? sites : []).forEach(function (site) {
    container.appendChild(createSiteRow(site.origin, site.alwaysAllow, site.silent));
  });

  if (container.children.length === 0) {
    container.appendChild(createSiteRow());
  }
}

// Show the "no sites configured" warning whenever settings has zero sites.
function updateNoSitesWarning() {
  var warn = document.getElementById('no-origins-warning');
  if (!warn) return;
  var collected = collectSites();
  warn.hidden = collected.values.length > 0;
}

function setCheckItem(id, status, label) {
  var iconEl = document.getElementById(id + '-icon');
  var labelEl = document.getElementById(id + '-label');
  if (iconEl) {
    iconEl.className = 'check-icon ' + status;
    iconEl.textContent = status === 'pass' ? '✓' : status === 'fail' ? '✗' : '•';
  }
  if (labelEl) labelEl.textContent = label;
}

async function verifySetup() {
  var checklistEl = document.getElementById('setup-checklist');
  if (checklistEl) checklistEl.hidden = false;

  setCheckItem('check-key', 'pending', 'Checking SSH keys...');
  setCheckItem('check-origins', 'pending', 'Checking sites...');
  setCheckItem('check-server', 'pending', 'Checking backend...');

  // Check that at least one discovered key is loaded in the agent (signable).
  try {
    var data = await App.getKeys();
    var keys = (data && data.keys) || [];
    var loaded = keys.filter(function (k) { return k.agentLoaded; });
    setCheckItem('check-key', loaded.length > 0 ? 'pass' : 'fail',
      loaded.length > 0 ? loaded.length + ' agent-loaded key(s)' : 'No agent-loaded keys (ssh-add a key)');
  } catch (err) {
    setCheckItem('check-key', 'fail', 'SSH keys: ' + (err.message || err));
  }

  // Check sites.
  var collected = collectSites();
  var n = collected.values.length;
  setCheckItem('check-origins', n > 0 ? 'pass' : 'fail',
    n > 0 ? n + ' site(s) configured' : 'No sites configured (they can be added on first use)');

  // Check backend.
  try {
    var status = await App.getStatus();
    var serverOk = status.running === true;
    setCheckItem('check-server', serverOk ? 'pass' : 'fail',
      serverOk ? 'Backend running on ' + status.address : 'Backend not running');
  } catch (err) {
    setCheckItem('check-server', 'fail', 'Backend: ' + (err.message || err));
  }

  setTimeout(function () {
    if (checklistEl) checklistEl.hidden = true;
  }, 6000);
}

function renderSettingsConfig(cfg) {
  renderToggle(cfg.enabled !== false);
  var serverPortInput = document.getElementById('server-port');
  if (serverPortInput) {
    serverPortInput.value = cfg.serverPort || 7890;
  }
  renderKeysList('keys-list');
  renderSiteRows(cfg.sites || []);
  updateNoSitesWarning();
}

async function saveSettingsConfig() {
  var serverPortInput = document.getElementById('server-port');
  var serverPort = serverPortInput ? parseInt(serverPortInput.value, 10) : 7890;
  if (isNaN(serverPort) || serverPort < 1024 || serverPort > 65535) serverPort = 7890;

  var parsed = collectSites();
  var errorsEl = document.getElementById('origin-row-errors');
  if (parsed.invalidLines.length > 0) {
    if (errorsEl) { errorsEl.textContent = parsed.invalidLines.join(' | '); errorsEl.hidden = false; }
    setStatus('Error: invalid site(s)', 'error');
    return;
  }
  if (errorsEl) { errorsEl.textContent = ''; errorsEl.hidden = true; }

  var toggleBtn = document.getElementById('toggle-enabled');
  var enabled = toggleBtn ? toggleBtn.getAttribute('aria-pressed') === 'true' : true;
  try {
    await App.setConfig({
      enabled: enabled,
      sites: parsed.values,
      serverPort: serverPort
    });
    var cfg = await App.getConfig();
    renderSettingsConfig(cfg);
    setStatus('Config saved.', 'success');
  } catch (err) {
    setStatus('Error: ' + (err.message || err), 'error');
  }
}

function initSettings(cfg) {
  renderSettingsConfig(cfg);

  var toggleBtn = document.getElementById('toggle-enabled');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', async function () {
      var currentlyEnabled = toggleBtn.getAttribute('aria-pressed') === 'true';
      try {
        var newCfg = await App.setEnabled(!currentlyEnabled);
        renderSettingsConfig(newCfg);
      } catch (err) {
        setStatus('Error: ' + (err.message || err), 'error');
      }
    });
  }

  var saveBtn = document.getElementById('save-config');
  if (saveBtn) saveBtn.addEventListener('click', function () { saveSettingsConfig(); });

  var verifyBtn = document.getElementById('verify-setup');
  if (verifyBtn) verifyBtn.addEventListener('click', function () { verifySetup(); });

  var addBtn = document.getElementById('add-origin-row');
  var container = document.getElementById('origin-rows');
  if (addBtn && container) {
    addBtn.addEventListener('click', function () {
      container.appendChild(createSiteRow());
      updateNoSitesWarning();
    });
  }
}
