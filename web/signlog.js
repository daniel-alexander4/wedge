// Sign-log view — lists past signatures. Empty in Phase 1 (nothing signs yet).

async function showSignLog() {
  showView('view-signlog');
  var tbody = document.getElementById('signlog-body');
  var empty = document.getElementById('signlog-empty');
  if (tbody) tbody.innerHTML = '';
  if (empty) { empty.hidden = true; empty.textContent = 'No signatures yet.'; }

  try {
    var data = await App.getSignLog();
    var entries = (data && data.entries) || [];
    if (entries.length === 0) {
      if (empty) empty.hidden = false;
      return;
    }
    entries.forEach(function (e) {
      var tr = document.createElement('tr');
      [e.time, e.origin, e.namespace, e.approval].forEach(function (v) {
        var td = document.createElement('td');
        td.textContent = v || '';
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (empty) { empty.hidden = false; empty.textContent = 'Could not load sign log: ' + (err.message || err); }
  }
}

document.addEventListener('DOMContentLoaded', function () {
  var openBtn = document.getElementById('open-signlog');
  if (openBtn) openBtn.addEventListener('click', function () { showSignLog(); });
  var backBtn = document.getElementById('signlog-back');
  if (backBtn) backBtn.addEventListener('click', function () { showView('view-settings'); });
});
