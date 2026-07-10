// Settings view.

var MAX_SITE_ROWS = 100;

// normalizeSiteValue canonicalizes a site input. Returns {scheme, value} for a
// supported entry (http(s) web origin, or an ssh:// target — note URL.origin is
// "null" for ssh, so it's reconstructed), or null if unsupported/invalid.
function normalizeSiteValue(raw) {
  if (!raw) return null;
  var u;
  try { u = new URL(raw); } catch (e) { return null; }
  if (u.protocol === 'http:' || u.protocol === 'https:') {
    return { scheme: u.protocol, value: u.origin };
  }
  if (u.protocol === 'ssh:') {
    if (!u.hostname) return null;
    var v = 'ssh://' + (u.username ? u.username + '@' : '') + u.hostname + (u.port ? ':' + u.port : '');
    return { scheme: 'ssh:', value: v };
  }
  return null;
}

function setStatus(text, level) {
  var el = document.getElementById('status');
  if (!el) return;
  el.textContent = text;
  el.classList.remove('status-success', 'status-error');
  if (level) el.classList.add('status-' + level);
  el.hidden = !text;
}

// showNotice pops the transient overlay for ~3 seconds, then runs action —
// which the button also fires immediately on click (whichever comes first).
// Used by the unregistered-key path before opening the RP's registration page.
function showNotice(title, text, actionLabel, action) {
  var overlay = document.getElementById('notice-overlay');
  var btn = document.getElementById('notice-action');
  document.getElementById('notice-title').textContent = title;
  document.getElementById('notice-text').textContent = text;
  btn.textContent = actionLabel;
  var done = false;
  function fire() {
    if (done) return;
    done = true;
    overlay.hidden = true;
    btn.removeEventListener('click', fire);
    action();
  }
  btn.addEventListener('click', fire);
  overlay.hidden = false;
  btn.focus();
  setTimeout(fire, 3000);
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

// Light client-side charset gate for tunnel/jump values — the strict grammar
// (per-segment hosts/ports, colon-count → -L/-D) lives server-side in
// internal/terminal and runs at launch.
var SSH_OPTION_CHARSET = /^[A-Za-z0-9.:@,_\s-]*$/;

function createSiteRow(origin, alwaysAllow, silent, tunnels, jump) {
  var row = document.createElement('div');
  row.className = 'origin-row';

  var originInput = document.createElement('input');
  originInput.type = 'text';
  originInput.placeholder = 'https://example.com  or  ssh://user@host';
  originInput.value = origin || '';
  originInput.className = 'origin-input';
  originInput.addEventListener('input', function () { validateSiteRow(row); updateLaunchIcon(); });

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

  // Per-site tunnels (-L/-D) and jump hosts (-J), ssh:// rows only. The two
  // inputs wrap onto a second line (flex-wrap) and hide behind a toggle.
  var tunnelsInput = document.createElement('input');
  tunnelsInput.type = 'text';
  tunnelsInput.className = 'tunnels-input';
  tunnelsInput.placeholder = 'tunnels: 8080:localhost:80, 1080  (port = SOCKS -D, port:host:port = -L; comma-separated)';
  tunnelsInput.value = (tunnels || []).join(', ');

  var jumpInput = document.createElement('input');
  jumpInput.type = 'text';
  jumpInput.className = 'jump-input';
  jumpInput.placeholder = 'jump: user@bastion[:port][,hop2]';
  jumpInput.value = jump || '';

  [tunnelsInput, jumpInput].forEach(function (inp) {
    inp.addEventListener('input', function () {
      inp.classList.toggle('invalid', !SSH_OPTION_CHARSET.test(inp.value));
    });
  });

  var optionsToggle = document.createElement('span');
  optionsToggle.className = 'options-toggle';
  optionsToggle.setAttribute('role', 'button');
  optionsToggle.tabIndex = 0;
  optionsToggle.textContent = 'tunnels';
  optionsToggle.title = 'Per-site tunnels (-L/-D) and jump hosts (-J) for the terminal launcher';
  var optionsOpen = !!((tunnels && tunnels.length) || jump);
  function renderOptions() {
    tunnelsInput.hidden = !optionsOpen;
    jumpInput.hidden = !optionsOpen;
    optionsToggle.classList.toggle('on', optionsOpen);
  }
  function toggleOptions() { optionsOpen = !optionsOpen; renderOptions(); }
  optionsToggle.addEventListener('click', toggleOptions);
  optionsToggle.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); toggleOptions(); }
  });
  renderOptions();

  var launchBtn = document.createElement('span');
  launchBtn.className = 'launch-row-btn';
  launchBtn.setAttribute('role', 'button');
  launchBtn.tabIndex = 0;

  var launchImg = document.createElement('img');
  launchImg.className = 'row-btn-glyph';
  launchImg.alt = '';
  launchBtn.appendChild(launchImg);

  var sftpBtn = document.createElement('span');
  sftpBtn.className = 'launch-row-btn';
  sftpBtn.setAttribute('role', 'button');
  sftpBtn.tabIndex = 0;
  var sftpImg = document.createElement('img');
  sftpImg.className = 'row-btn-glyph';
  sftpImg.alt = '';
  sftpImg.src = 'icons/wedge-glyph-sftp.svg';
  sftpBtn.appendChild(sftpImg);
  sftpBtn.title = 'Browse this host’s files over SFTP';
  sftpBtn.setAttribute('aria-label', sftpBtn.title);

  function updateLaunchIcon() {
    var t = normalizeSiteValue(originInput.value.trim());
    var ssh = t && t.scheme === 'ssh:';
    launchImg.src = ssh ? 'icons/wedge-glyph-terminal.svg' : 'icons/wedge-glyph-open.svg';
    var label = ssh ? 'Open an SSH terminal to this host' : 'Sign in with wedge and open this site';
    launchBtn.title = label;
    launchBtn.setAttribute('aria-label', label);
    sftpBtn.style.display = ssh ? '' : 'none';
    optionsToggle.style.display = ssh ? '' : 'none';
    if (!ssh) { optionsOpen = false; renderOptions(); }
  }
  function launch() {
    var t = normalizeSiteValue(originInput.value.trim());
    if (!t) { setStatus('Invalid site — use http(s):// or ssh://', 'error'); return; }
    if (t.scheme === 'ssh:') {
      App.openSSH(t.value)
        .then(function () { setStatus('Opened ' + t.value, 'success'); })
        .catch(function (err) { setStatus('Could not open: ' + (err.message || err), 'error'); });
      return;
    }
    // http(s): wedge signs in first, then opens the browser already logged in.
    // Show the "approve in wedge" hint now; the request resolves with the final
    // outcome (consent runs concurrently), which we then report.
    setStatus('Signing in to ' + t.value + ' — approve in wedge…', '');
    App.signInThenOpen(t.value)
      .then(function (res) {
        if (res && res.status === 'unregistered' && res.registrationUrl) {
          // The RP has no account for this key. Give the user a moment to read
          // why before the browser takes over, then open the registration page
          // (same-origin with the site — the server re-validates on /api/open).
          setStatus('', '');
          showNotice(
            'Key not registered',
            'Your key isn’t registered at ' + t.value + ' yet — taking you to its key-registration page.',
            'Open now',
            function () {
              App.openSite(res.registrationUrl)
                .then(function () { setStatus('Opened the registration page for ' + t.value + ' — add your key there, then sign in again.', ''); })
                .catch(function (err) { setStatus('Could not open the registration page: ' + (err.message || err), 'error'); });
            }
          );
          return;
        }
        var msg = (res && res.message) || 'Done.';
        setStatus(msg, res && res.status === 'success' ? 'success' : 'error');
      })
      .catch(function (err) { setStatus('Could not sign in: ' + (err.message || err), 'error'); });
  }
  launchBtn.addEventListener('click', launch);
  launchBtn.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); launch(); }
  });

  function launchSFTP() {
    var t = normalizeSiteValue(originInput.value.trim());
    if (!t || t.scheme !== 'ssh:') { setStatus('SFTP needs an ssh:// site', 'error'); return; }
    App.openSFTP(t.value)
      .then(function () { setStatus('Opened file manager for ' + t.value, 'success'); })
      .catch(function (err) { setStatus('Could not open: ' + (err.message || err), 'error'); });
  }
  sftpBtn.addEventListener('click', launchSFTP);
  sftpBtn.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); launchSFTP(); }
  });
  updateLaunchIcon();

  var removeBtn = document.createElement('span');
  removeBtn.className = 'remove-row-btn';
  var removeImg = document.createElement('img');
  removeImg.className = 'row-btn-glyph';
  removeImg.alt = '';
  removeImg.src = 'icons/wedge-glyph-remove.svg';
  removeBtn.appendChild(removeImg);
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
  row.appendChild(optionsToggle);
  row.appendChild(launchBtn);
  row.appendChild(sftpBtn);
  row.appendChild(removeBtn);
  // Second line (flex-wrap): the optional tunnel/jump inputs.
  row.appendChild(tunnelsInput);
  row.appendChild(jumpInput);
  return row;
}

function validateSiteRow(row) {
  var originInput = row.querySelector('.origin-input');
  var valid = true;
  var raw = originInput.value.trim();
  if (raw) {
    if (normalizeSiteValue(raw)) { originInput.classList.remove('invalid'); }
    else { originInput.classList.add('invalid'); valid = false; }
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

    var t = normalizeSiteValue(raw);
    if (!t) { invalidLines.push(raw + ' — use http(s):// or ssh://'); return; }
    var origin = t.value;

    if (seen[origin]) return;
    seen[origin] = true;

    var site = { origin: origin };
    if (autoInput && autoInput.checked) site.alwaysAllow = true;
    if (silentInput && silentInput.checked) site.silent = true;
    if (t.scheme === 'ssh:') {
      var tunnelsInput = row.querySelector('.tunnels-input');
      var jumpInput = row.querySelector('.jump-input');
      var tunnelsRaw = tunnelsInput ? tunnelsInput.value.trim() : '';
      var jumpRaw = jumpInput ? jumpInput.value.trim() : '';
      if (!SSH_OPTION_CHARSET.test(tunnelsRaw) || !SSH_OPTION_CHARSET.test(jumpRaw)) {
        invalidLines.push(origin + ' — tunnels/jump: unsupported characters');
        return;
      }
      // Specs can't legally contain whitespace, so strip it (forgiving paste).
      var specs = tunnelsRaw.split(',').map(function (s) { return s.replace(/\s+/g, ''); }).filter(Boolean);
      if (specs.length) site.tunnels = specs;
      if (jumpRaw) site.jump = jumpRaw.replace(/\s+/g, '');
    }
    out.push(site);
  });

  return { values: out, invalidLines: invalidLines };
}

// mergeSites merges an imported sites list into the current one: adds origins
// that are missing, ORs the alwaysAllow/silent flags on ones that exist, never
// deletes. Import is a user-initiated local file choice, so added trust flags
// are equivalent to the user ticking them by hand.
function mergeSites(current, imported) {
  var out = current.slice();
  var byOrigin = {};
  out.forEach(function (s, i) { byOrigin[s.origin] = i; });
  var added = 0, updated = 0;
  (imported || []).forEach(function (s) {
    if (!s || typeof s.origin !== 'string') return;
    var t = normalizeSiteValue(s.origin.trim());
    if (!t) return; // skip entries that aren't http(s)/ssh — never import junk
    var origin = t.value;
    // Tunnels/jump ride along sanitized to strings; on merge they're adopted
    // only when the existing entry has none — an import never overwrites the
    // user's local tunnel setup.
    var impTunnels = Array.isArray(s.tunnels)
      ? s.tunnels.filter(function (x) { return typeof x === 'string' && x; })
      : [];
    var impJump = typeof s.jump === 'string' ? s.jump : '';
    if (Object.prototype.hasOwnProperty.call(byOrigin, origin)) {
      var cur = out[byOrigin[origin]];
      var changed = false;
      if (s.alwaysAllow && !cur.alwaysAllow) { cur.alwaysAllow = true; changed = true; }
      if (s.silent && !cur.silent) { cur.silent = true; changed = true; }
      if (impTunnels.length && !(cur.tunnels && cur.tunnels.length)) { cur.tunnels = impTunnels; changed = true; }
      if (impJump && !cur.jump) { cur.jump = impJump; changed = true; }
      if (changed) updated++;
    } else {
      var site = { origin: origin };
      if (s.alwaysAllow) site.alwaysAllow = true;
      if (s.silent) site.silent = true;
      if (impTunnels.length) site.tunnels = impTunnels;
      if (impJump) site.jump = impJump;
      byOrigin[origin] = out.length;
      out.push(site);
      added++;
    }
  });
  return { sites: out, added: added, updated: updated };
}

// exportSites downloads the current rows as wedge-sites.json ({"sites":[...]}),
// the file-based multi-machine story: sync it however you like (scp, git,
// Syncthing) and Import… it on the other machine.
function exportSites() {
  var parsed = collectSites();
  if (parsed.invalidLines.length > 0) { setStatus('Fix invalid site(s) before exporting', 'error'); return; }
  var blob = new Blob([JSON.stringify({ sites: parsed.values }, null, 2) + '\n'], { type: 'application/json' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'wedge-sites.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
  setStatus('Exported ' + parsed.values.length + ' site(s) to wedge-sites.json', 'success');
}

// importSitesFile merges a wedge-sites.json (or a bare sites array) into the
// rows. It only edits the form — the user reviews and clicks Save to persist.
function importSitesFile(file) {
  var reader = new FileReader();
  reader.onload = function () {
    var data;
    try { data = JSON.parse(String(reader.result)); }
    catch (e) { setStatus('Import failed: not valid JSON', 'error'); return; }
    var list = Array.isArray(data) ? data : (data && Array.isArray(data.sites) ? data.sites : null);
    if (!list) { setStatus('Import failed: expected {"sites":[...]}', 'error'); return; }
    var parsed = collectSites();
    if (parsed.invalidLines.length > 0) { setStatus('Fix invalid site(s) before importing', 'error'); return; }
    var res = mergeSites(parsed.values, list);
    renderSiteRows(res.sites);
    updateNoSitesWarning();
    if (res.added + res.updated > 0) {
      setStatus('Imported: ' + res.added + ' added, ' + res.updated + ' updated — click Save to persist', 'success');
    } else {
      setStatus('Import: nothing new — all sites already present', 'success');
    }
  };
  reader.onerror = function () { setStatus('Import failed: could not read file', 'error'); };
  reader.readAsText(file);
}

// importSSHConfig pulls the literal Host aliases from ~/.ssh/config (via the
// server) and merges them into the rows as ssh://<alias> sites. Launching such
// a row runs `ssh <alias>`, so OpenSSH resolves HostName/User/Port/ProxyJump —
// including the wildcard/Match blocks wedge doesn't parse — at connect time.
// Like file import, it only edits the form — the user reviews and clicks Save.
// Used from both settings (defaults) and onboarding step 2 (containerId +
// report override, since the settings #status line is hidden there).
function importSSHConfig(containerId, report) {
  report = report || setStatus;
  var persistHint = containerId ? '' : ' — click Save to persist';
  var parsed = collectSites(containerId);
  if (parsed.invalidLines.length > 0) { report('Fix invalid site(s) before importing', 'error'); return; }
  apiGet('/api/sshconfig').then(function (data) {
    var hosts = (data && Array.isArray(data.hosts)) ? data.hosts : [];
    var skipped = (data && data.skipped) || 0;
    var skippedNote = skipped > 0 ? ' (' + skipped + ' skipped — unsupported name)' : '';
    if (hosts.length === 0) {
      report('No hosts found in ~/.ssh/config' + skippedNote);
      return;
    }
    var res = mergeSites(parsed.values, hosts.map(function (h) { return { origin: 'ssh://' + h }; }));
    renderSiteRows(res.sites, containerId);
    if (!containerId) updateNoSitesWarning();
    if (res.added > 0) {
      report('Imported ' + res.added + ' host(s) from ~/.ssh/config' + skippedNote + persistHint, 'success');
    } else {
      report('Import: nothing new — all hosts already present' + skippedNote, 'success');
    }
  }).catch(function (err) {
    report('Import failed: ' + err.message, 'error');
  });
}

function renderSiteRows(sites, containerId) {
  containerId = containerId || 'origin-rows';
  var container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';

  (Array.isArray(sites) ? sites : []).forEach(function (site) {
    container.appendChild(createSiteRow(site.origin, site.alwaysAllow, site.silent, site.tunnels, site.jump));
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

  var exportBtn = document.getElementById('export-sites');
  if (exportBtn) exportBtn.addEventListener('click', exportSites);
  var importBtn = document.getElementById('import-sites');
  var importFile = document.getElementById('import-sites-file');
  if (importBtn && importFile) {
    importBtn.addEventListener('click', function () { importFile.click(); });
    importFile.addEventListener('change', function () {
      var f = importFile.files && importFile.files[0];
      importFile.value = ''; // allow re-importing the same filename later
      if (f) importSitesFile(f);
    });
  }
  var sshConfigBtn = document.getElementById('import-sshconfig');
  // Wrapped so the click Event doesn't land in the containerId parameter.
  if (sshConfigBtn) sshConfigBtn.addEventListener('click', function () { importSSHConfig(); });
}
