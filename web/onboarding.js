// Onboarding view (2 functional steps + ready).

function activateStep(stepNum) {
  for (var i = 1; i <= 3; i++) {
    var el = document.getElementById('step-' + i);
    if (!el) continue;
    el.classList.remove('active');
    if (i === stepNum) el.classList.add('active');
  }
}

function markStepDone(stepNum, statusText) {
  var el = document.getElementById('step-' + stepNum);
  var statusEl = document.getElementById('step-' + stepNum + '-status');
  if (el) el.classList.add('done');
  if (statusEl) statusEl.textContent = statusText;
}

function showResult(containerId, pass, text) {
  var el = document.getElementById(containerId);
  if (!el) return;
  el.hidden = false;
  el.className = 'step-result ' + (pass ? 'result-pass' : 'result-fail');
  el.textContent = text;
}

function initOnboarding(cfg) {
  for (var i = 1; i <= 3; i++) {
    (function (stepNum) {
      var header = document.querySelector('#step-' + stepNum + ' .step-header');
      if (header) header.addEventListener('click', function () { activateStep(stepNum); });
    })(i);
  }

  // Step 1: show discovered keys (read-only — nothing to configure). Mark done
  // if at least one key is loaded in the agent, and advance to sites.
  renderKeysList('onboarding-keys-list').then(async function () {
    try {
      var data = await App.getKeys();
      var keys = (data && data.keys) || [];
      var loaded = keys.filter(function (k) { return k.agentLoaded; });
      if (loaded.length > 0) {
        markStepDone(1, loaded.length + ' key(s)');
      } else {
        markStepDone(1, 'ssh-add a key');
      }
    } catch (e) { /* leave step 1 unmarked on error */ }
  });

  // Step 2: site rows.
  var originRows = document.getElementById('onboarding-origin-rows');
  if (originRows) originRows.appendChild(createSiteRow());
  var addRowBtn = document.getElementById('onboarding-add-origin-row');
  if (addRowBtn && originRows) {
    addRowBtn.addEventListener('click', function () {
      originRows.appendChild(createSiteRow());
    });
  }

  // Save & Finish.
  var saveFinishBtn = document.getElementById('save-and-finish');
  if (saveFinishBtn) {
    saveFinishBtn.addEventListener('click', async function () {
      var parsed = collectSites('onboarding-origin-rows');
      var errorsEl = document.getElementById('onboarding-origin-row-errors');
      if (parsed.invalidLines.length > 0) {
        if (errorsEl) { errorsEl.textContent = parsed.invalidLines.join(' | '); errorsEl.hidden = false; }
        return;
      }

      // Require one bootstrap site — an empty list re-launches straight back into
      // onboarding. wedge adds any further sites on first use.
      if (parsed.values.length === 0) {
        if (errorsEl) {
          errorsEl.textContent = 'Add at least one site before finishing.';
          errorsEl.hidden = false;
        }
        return;
      }
      if (errorsEl) { errorsEl.textContent = ''; errorsEl.hidden = true; }

      var statusEl = document.getElementById('onboarding-status');
      try {
        await App.setConfig({
          enabled: true,
          sites: parsed.values,
          serverPort: 7890
        });

        if (statusEl) {
          statusEl.hidden = false;
          statusEl.textContent = 'Setup complete!';
          statusEl.className = 'status status-success';
        }
        markStepDone(2, 'Configured');
        markStepDone(3, 'Ready');

        setTimeout(async function () {
          var newCfg = await App.getConfig();
          showView('view-settings');
          initSettings(newCfg);
        }, 1000);
      } catch (err) {
        if (statusEl) {
          statusEl.hidden = false;
          statusEl.textContent = 'Error: ' + (err.message || err);
          statusEl.className = 'status status-error';
        }
      }
    });
  }
}
