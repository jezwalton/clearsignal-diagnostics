<?php
/** @var int $ticketId */
/** @var array $config */

$enabledChecks = $config['enabled_checks'] ?? array_keys(PluginClearsignaldiagConfig::ALL_CHECKS);
$allChecks = PluginClearsignaldiagConfig::ALL_CHECKS;
$showRaw = (int)($config['allow_raw_output'] ?? 1) === 1;
$pluginRoot = Plugin::getWebDir('clearsignaldiag');
?>
<div class="card" id="clearsignaldiag-panel">
  <div class="card-header d-flex justify-content-between align-items-center">
    <h3 class="card-title mb-0">
      <i class="ti ti-stethoscope me-1"></i>ClearSignal Diagnostics
    </h3>
    <span class="badge bg-secondary" id="csd-status-badge" style="display:none;"></span>
  </div>
  <div class="card-body">

    <form id="clearsignaldiag-form" autocomplete="off">
      <input type="hidden" name="tickets_id" value="<?php echo (int)$ticketId; ?>">
      <input type="hidden" name="_glpi_csrf_token" value="<?php echo htmlspecialchars(Session::getNewCSRFToken(), ENT_QUOTES, 'UTF-8'); ?>">

      <!-- Target input -->
      <div class="row mb-3">
        <div class="col-md-8">
          <label for="csd-target" class="form-label fw-bold">Target</label>
          <input type="text" id="csd-target" name="target" class="form-control"
                 placeholder="hostname, domain, IP address or URL" required>
          <div class="form-text">Enter the hostname, domain, IP, or URL to diagnose.</div>
        </div>
        <div class="col-md-4">
          <label for="csd-selector" class="form-label fw-bold">DKIM selector</label>
          <input type="text" id="csd-selector" name="dkim_selector" class="form-control"
                 placeholder="e.g. selector1"
                 value="<?php echo htmlspecialchars((string)($config['default_selector'] ?? 'selector1'), ENT_QUOTES, 'UTF-8'); ?>">
        </div>
      </div>

      <!-- Checks grid -->
      <div class="mb-3">
        <label class="form-label fw-bold">Checks</label>
        <div class="mb-1">
          <a href="#" id="csd-select-all" class="me-2 small">Select all</a>
          <a href="#" id="csd-select-none" class="small">Select none</a>
        </div>
        <div class="row">
          <?php foreach ($allChecks as $value => $label): ?>
            <?php if (!in_array($value, $enabledChecks, true)) continue; ?>
            <div class="col-md-4 col-lg-3 mb-1">
              <div class="form-check">
                <input class="form-check-input csd-check-input" type="checkbox"
                       name="checks[]"
                       id="csd-chk-<?php echo htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); ?>"
                       value="<?php echo htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); ?>">
                <label class="form-check-label" for="csd-chk-<?php echo htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); ?>">
                  <?php echo htmlspecialchars($label, ENT_QUOTES, 'UTF-8'); ?>
                </label>
              </div>
            </div>
          <?php endforeach; ?>
        </div>
      </div>

      <!-- Action buttons -->
      <div class="mb-3 d-flex gap-2">
        <button type="button" class="btn btn-primary" id="csd-btn-run">
          <i class="ti ti-player-play me-1"></i>Run diagnostics
        </button>
        <button type="button" class="btn btn-outline-secondary" id="csd-btn-addtoticket" disabled>
          <i class="ti ti-notes me-1"></i>Add results to ticket
        </button>
      </div>
    </form>

    <!-- Loading indicator -->
    <div id="csd-loading" style="display:none;" class="mb-3">
      <div class="d-flex align-items-center text-primary">
        <div class="spinner-border spinner-border-sm me-2" role="status"></div>
        <span>Running diagnostics&hellip; this may take a moment.</span>
      </div>
    </div>

    <!-- Error display -->
    <div id="csd-error" class="alert alert-danger mb-3" style="display:none;" role="alert"></div>

    <!-- Results section -->
    <div id="csd-results-section" style="display:none;">
      <hr>

      <!-- Summary card -->
      <div class="card mb-3">
        <div class="card-header">
          <h4 class="card-title mb-0">Formatted summary</h4>
        </div>
        <div class="card-body p-0">
          <pre id="csd-summary" class="mb-0 p-3" style="white-space:pre-wrap; background:transparent; border:0; font-size:0.875rem;"></pre>
        </div>
      </div>

      <!-- Per-check detail cards -->
      <div id="csd-check-details"></div>

      <?php if ($showRaw): ?>
      <!-- Raw JSON (collapsible) -->
      <div class="card mb-3">
        <div class="card-header" style="cursor:pointer;" data-bs-toggle="collapse" data-bs-target="#csd-raw-collapse">
          <h4 class="card-title mb-0">
            <i class="ti ti-chevron-down me-1"></i>Raw JSON
          </h4>
        </div>
        <div class="collapse" id="csd-raw-collapse">
          <div class="card-body p-0">
            <pre id="csd-raw-json" class="mb-0 p-3" style="white-space:pre-wrap; max-height:500px; overflow:auto; background:transparent; border:0; font-size:0.8rem;"></pre>
          </div>
        </div>
      </div>
      <?php endif; ?>
    </div>

    <!-- Toast-style success message -->
    <div id="csd-toast" class="alert alert-success mb-0 mt-2" style="display:none;" role="alert"></div>

  </div>
</div>

<script>
(function() {
  'use strict';

  const PLUGIN_ROOT = '<?php echo addslashes($pluginRoot); ?>';
  const SHOW_RAW = <?php echo $showRaw ? 'true' : 'false'; ?>;

  let lastResult = null;
  let lastSummary = '';

  // Element references
  const form        = document.getElementById('clearsignaldiag-form');
  const btnRun      = document.getElementById('csd-btn-run');
  const btnAdd      = document.getElementById('csd-btn-addtoticket');
  const loading     = document.getElementById('csd-loading');
  const errorDiv    = document.getElementById('csd-error');
  const resultsDiv  = document.getElementById('csd-results-section');
  const summaryPre  = document.getElementById('csd-summary');
  const detailsDiv  = document.getElementById('csd-check-details');
  const rawPre      = document.getElementById('csd-raw-json');
  const toast       = document.getElementById('csd-toast');
  const badge       = document.getElementById('csd-status-badge');

  // Select all / none
  document.getElementById('csd-select-all').addEventListener('click', function(e) {
    e.preventDefault();
    form.querySelectorAll('.csd-check-input').forEach(cb => cb.checked = true);
  });
  document.getElementById('csd-select-none').addEventListener('click', function(e) {
    e.preventDefault();
    form.querySelectorAll('.csd-check-input').forEach(cb => cb.checked = false);
  });

  function setFormEnabled(enabled) {
    form.querySelectorAll('input, button').forEach(el => {
      if (el.id !== 'csd-btn-addtoticket') {
        el.disabled = !enabled;
      }
    });
    btnRun.disabled = !enabled;
  }

  function showError(msg) {
    errorDiv.textContent = msg;
    errorDiv.style.display = 'block';
  }

  function hideError() {
    errorDiv.style.display = 'none';
  }

  function showToast(msg, type) {
    toast.className = 'alert mb-0 mt-2 alert-' + (type || 'success');
    toast.textContent = msg;
    toast.style.display = 'block';
    setTimeout(() => { toast.style.display = 'none'; }, 4000);
  }

  function escHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function statusIcon(summary) {
    const lower = (summary || '').toLowerCase();
    if (lower.includes('fail') || lower.includes('error') || lower.includes('stopped') || lower.includes('mismatch') || lower.includes('no ')) {
      return '<span class="badge bg-danger me-1">FAIL</span>';
    }
    if (lower.includes('warning') || lower.includes('disagree') || lower.includes('possible') || lower.includes('proxied') || lower.includes('multiple')) {
      return '<span class="badge bg-warning text-dark me-1">WARN</span>';
    }
    return '<span class="badge bg-success me-1">OK</span>';
  }

  function buildSummary(result) {
    const lines = [];
    lines.push('=== ClearSignal Diagnostics Report ===');
    lines.push('Date: ' + new Date().toISOString().replace('T', ' ').substring(0, 19));
    lines.push('Target: ' + (result.target?.input || 'unknown'));
    lines.push('');

    (result.checks || []).forEach(check => {
      lines.push('  [' + (check.name || 'Unknown') + '] ' + (check.summary || 'No summary'));
    });

    const causes = [];
    const fixes = [];
    (result.checks || []).forEach(check => {
      if (check.likely_root_cause) causes.push('  - ' + check.likely_root_cause);
      if (check.recommended_fix) fixes.push('  - ' + check.recommended_fix);
    });

    if (causes.length) {
      lines.push('');
      lines.push('--- Likely Root Cause ---');
      [...new Set(causes)].forEach(line => lines.push(line));
    }

    if (fixes.length) {
      lines.push('');
      lines.push('--- Recommended Fix ---');
      [...new Set(fixes)].forEach(line => lines.push(line));
    }

    lines.push('');
    lines.push('=== End of Report ===');
    return lines.join('\n');
  }

  function renderCheckDetails(checks) {
    detailsDiv.innerHTML = '';
    if (!checks || checks.length === 0) return;

    checks.forEach(check => {
      const card = document.createElement('div');
      card.className = 'card mb-2';
      card.innerHTML =
        '<div class="card-header py-2 d-flex align-items-center">' +
          statusIcon(check.summary) +
          '<strong>' + escHtml(check.name || 'Check') + '</strong>' +
          '<span class="ms-2 text-muted small">' + escHtml(check.summary || '') + '</span>' +
        '</div>';

      // If the check has sub-checks (like dns_diagnostic), show them
      if (check.details && check.details.checks && Array.isArray(check.details.checks)) {
        const body = document.createElement('div');
        body.className = 'card-body py-2 px-3';
        check.details.checks.forEach(sub => {
          body.innerHTML +=
            '<div class="d-flex align-items-center mb-1">' +
              statusIcon(sub.summary) +
              '<span class="fw-bold me-1">' + escHtml(sub.name || '') + ':</span> ' +
              '<span class="small">' + escHtml(sub.summary || '') + '</span>' +
            '</div>';
          if (sub.likely_root_cause) {
            body.innerHTML += '<div class="ms-4 small text-danger">Cause: ' + escHtml(sub.likely_root_cause) + '</div>';
          }
          if (sub.recommended_fix) {
            body.innerHTML += '<div class="ms-4 small text-info">Fix: ' + escHtml(sub.recommended_fix) + '</div>';
          }
        });
        card.appendChild(body);
      } else {
        if (check.likely_root_cause || check.recommended_fix) {
          const body = document.createElement('div');
          body.className = 'card-body py-2 px-3';
          if (check.likely_root_cause) {
            body.innerHTML += '<div class="small text-danger">Cause: ' + escHtml(check.likely_root_cause) + '</div>';
          }
          if (check.recommended_fix) {
            body.innerHTML += '<div class="small text-info">Fix: ' + escHtml(check.recommended_fix) + '</div>';
          }
          card.appendChild(body);
        }
      }

      detailsDiv.appendChild(card);
    });
  }

  // Run diagnostics
  btnRun.addEventListener('click', function() {
    const target = document.getElementById('csd-target').value.trim();
    if (!target) {
      showError('Please enter a target hostname, domain, IP, or URL.');
      return;
    }

    const checked = form.querySelectorAll('.csd-check-input:checked');
    if (checked.length === 0) {
      showError('Please select at least one check.');
      return;
    }

    hideError();
    resultsDiv.style.display = 'none';
    loading.style.display = 'block';
    setFormEnabled(false);
    btnAdd.disabled = true;
    badge.style.display = 'inline-block';
    badge.textContent = 'Running...';
    badge.className = 'badge bg-primary';

    const data = new FormData(form);

    fetch(PLUGIN_ROOT + '/ajax/run.php', {
      method: 'POST',
      body: data,
      credentials: 'same-origin'
    })
    .then(r => r.json())
    .then(resp => {
      loading.style.display = 'none';
      setFormEnabled(true);

      if (!resp.success) {
        throw new Error(resp.message || 'Diagnostics failed.');
      }

      lastResult = resp.data;
      lastSummary = buildSummary(resp.data);

      summaryPre.textContent = lastSummary;
      renderCheckDetails(resp.data.checks || []);

      if (SHOW_RAW && rawPre) {
        rawPre.textContent = JSON.stringify(resp.data, null, 2);
      }

      resultsDiv.style.display = 'block';
      btnAdd.disabled = false;

      const failCount = (resp.data.checks || []).filter(c =>
        (c.summary || '').toLowerCase().match(/fail|error|stopped|no /)).length;
      if (failCount > 0) {
        badge.textContent = failCount + ' issue(s)';
        badge.className = 'badge bg-danger';
      } else {
        badge.textContent = 'All OK';
        badge.className = 'badge bg-success';
      }
    })
    .catch(err => {
      loading.style.display = 'none';
      setFormEnabled(true);
      showError(String(err.message || err));
      badge.textContent = 'Error';
      badge.className = 'badge bg-danger';
    });
  });

  // Add results to ticket
  btnAdd.addEventListener('click', function() {
    if (!lastSummary) {
      showError('Run diagnostics first.');
      return;
    }

    hideError();
    btnAdd.disabled = true;
    btnAdd.innerHTML = '<div class="spinner-border spinner-border-sm me-1" role="status"></div>Adding...';

    const data = new FormData();
    data.append('tickets_id', form.querySelector('input[name="tickets_id"]').value);
    data.append('summary', lastSummary);
    data.append('_glpi_csrf_token', form.querySelector('input[name="_glpi_csrf_token"]').value);

    fetch(PLUGIN_ROOT + '/ajax/addtoticket.php', {
      method: 'POST',
      body: data,
      credentials: 'same-origin'
    })
    .then(r => r.json())
    .then(resp => {
      btnAdd.innerHTML = '<i class="ti ti-notes me-1"></i>Add results to ticket';
      btnAdd.disabled = false;

      if (!resp.success) {
        throw new Error(resp.message || 'Failed to add follow-up.');
      }
      showToast('Results added to ticket as a private follow-up.', 'success');
    })
    .catch(err => {
      btnAdd.innerHTML = '<i class="ti ti-notes me-1"></i>Add results to ticket';
      btnAdd.disabled = false;
      showError(String(err.message || err));
    });
  });

})();
</script>
