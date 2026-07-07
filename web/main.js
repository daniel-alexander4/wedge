// View routing + app init.

function showView(id) {
  document.querySelectorAll('.view').forEach(function (v) {
    v.classList.remove('active');
  });
  var el = document.getElementById(id);
  if (el) el.classList.add('active');
}

function showLoadError(err) {
  // On a config-load failure we must NOT drop the user onto an inert settings
  // screen (every control would be unbound). Hide all views and show a clear
  // error instead.
  document.querySelectorAll('.view').forEach(function (v) { v.classList.remove('active'); });
  var el = document.getElementById('load-error');
  if (el) {
    el.textContent = 'Could not load configuration: ' +
      (err && err.message ? err.message : err) +
      '. Is the wedge backend running?';
    el.hidden = false;
  }
}

async function initApp() {
  try {
    var cfg = await App.getConfig();
    if (!cfg.allowedOrigins || cfg.allowedOrigins.length === 0) {
      showView('view-onboarding');
      initOnboarding(cfg);
    } else {
      showView('view-settings');
      initSettings(cfg);
    }
  } catch (err) {
    console.error('Failed to init app:', err);
    showLoadError(err);
  }
}

document.addEventListener('DOMContentLoaded', function () {
  // Sign-request polling runs independently of the config load, so it starts
  // even if the settings/onboarding init fails.
  if (window.startConsentLoop) window.startConsentLoop();
  initApp();
});
