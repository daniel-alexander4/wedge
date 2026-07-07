// Settings view.

var KEY_PATHS = {
  ed25519: '~/.ssh/id_ed25519',
  rsa: '~/.ssh/id_rsa',
  ecdsa: '~/.ssh/id_ecdsa'
};
var NAMESPACE_REGEX = /^[A-Za-z0-9._:-]{1,64}$/;
var MAX_ORIGIN_ROWS = 100;

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

function detectKeyType(keyPath) {
  var v = (keyPath || '').trim();
  if (v.endsWith('id_ed25519')) return 'ed25519';
  if (v.endsWith('id_rsa')) return 'rsa';
  if (v.endsWith('id_ecdsa')) return 'ecdsa';
  return null;
}

function renderKeyTypeTabs(active) {
  var tabs = document.querySelectorAll('#view-settings [data-key-type]:not([data-onboarding])');
  tabs.forEach(function (tab) {
    tab.setAttribute('aria-pressed', tab.dataset.keyType === active ? 'true' : 'false');
  });
}

function splitOriginParts(origin) {
  try {
    var url = new URL(origin);
    var port = url.port || '';
    // Reconstruct host from URL parts rather than a fragile string replace.
    var host = url.protocol + '//' + url.hostname;
    return { host: host, port: port };
  } catch (e) {
    return { host: origin, port: '' };
  }
}

function createOriginRow(origin, namespace, port, alwaysAllow, company, silent) {
  origin = origin || '';
  namespace = namespace || '';
  port = port || '';

  var row = document.createElement('div');
  row.className = 'origin-row';
  // Carry fields the UI does not surface (company, silent) so a round-trip
  // through save doesn't drop them.
  row._company = company || '';
  row._silent = !!silent;

  var originInput = document.createElement('input');
  originInput.type = 'text';
  originInput.placeholder = 'https://example.com';
  originInput.value = origin;
  originInput.className = 'origin-input';
  originInput.addEventListener('input', function () { validateOriginRow(row); });

  var portInput = document.createElement('input');
  portInput.type = 'text';
  portInput.placeholder = 'port';
  portInput.value = port;
  portInput.className = 'port-input';
  portInput.addEventListener('input', function () { validateOriginRow(row); });

  var nsInput = document.createElement('input');
  nsInput.type = 'text';
  nsInput.placeholder = 'namespace';
  nsInput.value = namespace;
  nsInput.className = 'namespace-input';
  nsInput.addEventListener('input', function () { validateOriginRow(row); });

  var autoLabel = document.createElement('label');
  autoLabel.className = 'auto-allow';
  autoLabel.title = 'Always allow — skip the detail screen for this site (you still confirm each sign with a presence tap)';
  var autoInput = document.createElement('input');
  autoInput.type = 'checkbox';
  autoInput.className = 'auto-input';
  autoInput.checked = !!alwaysAllow;
  autoLabel.appendChild(autoInput);
  autoLabel.appendChild(document.createTextNode('auto'));

  var removeBtn = document.createElement('span');
  removeBtn.className = 'remove-row-btn';
  removeBtn.textContent = '🗑';
  removeBtn.setAttribute('role', 'button');
  removeBtn.setAttribute('aria-label', 'Remove target');
  removeBtn.tabIndex = 0;
  function removeRow() {
    row.remove();
    updateNoOriginsWarning();
  }
  removeBtn.addEventListener('click', removeRow);
  removeBtn.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
      e.preventDefault();
      removeRow();
    }
  });

  row.appendChild(originInput);
  row.appendChild(portInput);
  row.appendChild(nsInput);
  row.appendChild(autoLabel);
  row.appendChild(removeBtn);
  return row;
}

function validateOriginRow(row) {
  var originInput = row.querySelector('.origin-input');
  var portInput = row.querySelector('.port-input');
  var nsInput = row.querySelector('.namespace-input');
  var valid = true;

  var rawOrigin = originInput.value.trim();
  if (rawOrigin) {
    try { new URL(rawOrigin); originInput.classList.remove('invalid'); }
    catch (e) { originInput.classList.add('invalid'); valid = false; }
  } else {
    originInput.classList.remove('invalid');
  }

  var portVal = portInput.value.trim();
  if (portVal) {
    var portNum = Number(portVal);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      portInput.classList.add('invalid'); valid = false;
    } else {
      portInput.classList.remove('invalid');
    }
  } else {
    portInput.classList.remove('invalid');
  }

  var nsVal = nsInput.value.trim();
  if (nsVal && !NAMESPACE_REGEX.test(nsVal)) {
    nsInput.classList.add('invalid'); valid = false;
  } else {
    nsInput.classList.remove('invalid');
  }

  updateNoOriginsWarning();
  return valid;
}

function collectOriginScopes(containerId) {
  containerId = containerId || 'origin-rows';
  var container = document.getElementById(containerId);
  var out = {};
  var invalidLines = [];
  if (!container) return { values: out, invalidLines: invalidLines };

  var rows = container.querySelectorAll('.origin-row');
  if (rows.length > MAX_ORIGIN_ROWS) {
    return { values: out, invalidLines: ['Too many target systems (max ' + MAX_ORIGIN_ROWS + ')'] };
  }

  rows.forEach(function (row) {
    var originInput = row.querySelector('.origin-input');
    var portInput = row.querySelector('.port-input');
    var nsInput = row.querySelector('.namespace-input');
    var autoInput = row.querySelector('.auto-input');
    var rawHost = originInput.value.trim();
    var rawPort = portInput.value.trim();
    var nsVal = nsInput.value.trim();

    if (!rawHost && !nsVal && !rawPort) return;

    if (!rawHost || !nsVal) {
      invalidLines.push((rawHost || '(empty host)') + ' — host and namespace are required');
      return;
    }

    if (rawPort) {
      var portNum = Number(rawPort);
      if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
        invalidLines.push(rawHost + ' — invalid port "' + rawPort + '"');
        return;
      }
    }

    var fullUrl = rawPort ? rawHost + ':' + rawPort : rawHost;
    var origin = '';
    try { origin = new URL(fullUrl).origin; }
    catch (e) { invalidLines.push(fullUrl + ' — invalid URL'); return; }

    if (!NAMESPACE_REGEX.test(nsVal)) {
      invalidLines.push(rawHost + ' — invalid namespace "' + nsVal + '"');
      return;
    }

    var scope = { namespace: nsVal, alwaysAllow: !!(autoInput && autoInput.checked) };
    if (row._company) scope.company = row._company;
    if (row._silent) scope.silent = true;

    if (!out[origin]) out[origin] = [];
    var exists = out[origin].some(function (e) { return e.namespace === nsVal; });
    if (!exists) out[origin].push(scope);
  });

  return { values: out, invalidLines: invalidLines };
}

function renderOriginRows(scopes, containerId) {
  containerId = containerId || 'origin-rows';
  var container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';

  var entries = Object.entries(scopes || {}).sort(function (a, b) { return a[0].localeCompare(b[0]); });
  entries.forEach(function (entry) {
    var origin = entry[0];
    var scopeList = entry[1];
    var parts = splitOriginParts(origin);
    (Array.isArray(scopeList) ? scopeList : []).forEach(function (scope) {
      container.appendChild(createOriginRow(parts.host, scope.namespace, parts.port, scope.alwaysAllow, scope.company, scope.silent));
    });
  });

  if (container.children.length === 0) {
    container.appendChild(createOriginRow());
  }
}

// Show the "no targets configured" warning whenever settings has zero valid
// target systems. Wired to render, typing, and add/remove.
function updateNoOriginsWarning() {
  var warn = document.getElementById('no-origins-warning');
  if (!warn) return;
  var collected = collectOriginScopes();
  warn.hidden = Object.keys(collected.values).length > 0;
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

  setCheckItem('check-key', 'pending', 'Checking SSH key...');
  setCheckItem('check-origins', 'pending', 'Checking target systems...');
  setCheckItem('check-server', 'pending', 'Checking backend...');

  // Check SSH key (validate the path currently in the field).
  try {
    var keyPathInput = document.getElementById('key-path');
    var kp = keyPathInput ? keyPathInput.value.trim() : '';
    var keyResult = await App.validateKey(kp);
    var keyOk = keyResult.valid === true;
    setCheckItem('check-key', keyOk ? 'pass' : 'fail',
      keyOk ? 'SSH key valid' : 'SSH key: ' + (keyResult.error || 'validation failed'));
  } catch (err) {
    setCheckItem('check-key', 'fail', 'SSH key: ' + (err.message || err));
  }

  // Check target systems.
  var collected = collectOriginScopes();
  var hasOrigins = Object.keys(collected.values).length > 0;
  setCheckItem('check-origins', hasOrigins ? 'pass' : 'fail',
    hasOrigins ? Object.keys(collected.values).length + ' target system(s) configured' : 'No target systems configured');

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
  var keyPathInput = document.getElementById('key-path');
  if (keyPathInput) {
    keyPathInput.value = cfg.keyPath || '';
    renderKeyTypeTabs(detectKeyType(cfg.keyPath || ''));
  }
  var serverPortInput = document.getElementById('server-port');
  if (serverPortInput) {
    serverPortInput.value = cfg.serverPort || 7890;
  }
  renderOriginRows(cfg.originScopes || {});
  updateNoOriginsWarning();
}

async function saveSettingsConfig() {
  var keyPathInput = document.getElementById('key-path');
  var serverPortInput = document.getElementById('server-port');
  var keyPath = (keyPathInput ? keyPathInput.value : '').trim();
  var serverPort = serverPortInput ? parseInt(serverPortInput.value, 10) : 7890;
  if (isNaN(serverPort) || serverPort < 1024 || serverPort > 65535) serverPort = 7890;

  var parsed = collectOriginScopes();
  var errorsEl = document.getElementById('origin-row-errors');
  if (parsed.invalidLines.length > 0) {
    if (errorsEl) { errorsEl.textContent = parsed.invalidLines.join(' | '); errorsEl.hidden = false; }
    setStatus('Error: invalid target system(s)', 'error');
    return;
  }
  if (errorsEl) { errorsEl.textContent = ''; errorsEl.hidden = true; }

  var toggleBtn = document.getElementById('toggle-enabled');
  var enabled = toggleBtn ? toggleBtn.getAttribute('aria-pressed') === 'true' : true;
  var allowedOrigins = Object.keys(parsed.values);
  try {
    await App.setConfig({
      enabled: enabled,
      keyPath: keyPath,
      allowedOrigins: allowedOrigins,
      originScopes: parsed.values,
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
      container.appendChild(createOriginRow());
      updateNoOriginsWarning();
    });
  }

  var tabs = document.querySelectorAll('#view-settings [data-key-type]:not([data-onboarding])');
  var keyPathInput = document.getElementById('key-path');
  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      var type = tab.dataset.keyType;
      var nextPath = KEY_PATHS[type];
      if (!nextPath || !keyPathInput) return;
      keyPathInput.value = nextPath;
      renderKeyTypeTabs(type);
    });
  });
}
