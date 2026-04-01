<?php
include('../../../inc/includes.php');

Session::checkLoginUser();

Html::header(__('Domain Health Dashboard'), $_SERVER['PHP_SELF'], 'tools', 'pluginclearsignaldiagmenu', 'dashboard');

$config = PluginClearsignaldiagConfig::getConfig();
$pluginRoot = Plugin::getWebDir('clearsignaldiag');
?>

<ul class="nav nav-pills mb-3">
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-world-search me-1"></i>DNS</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/email_diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-mail-check me-1"></i>Email</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/header_analyser.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-mail-code me-1"></i>Analyser</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/website_diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-lock-check me-1"></i>Website</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/port_scanner.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-plug me-1"></i>Ports</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/health_check.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-heart-rate-monitor me-1"></i>Health Check</a></li>
  <li class="nav-item"><a class="nav-link active" href="<?php echo htmlspecialchars($pluginRoot . '/front/dashboard.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-dashboard me-1"></i>Dashboard</a></li>
</ul>

<!-- Summary cards -->
<div class="row mb-3" id="db-summary-row" style="display:none;">
  <div class="col"><div class="card text-center"><div class="card-body py-2"><div class="small text-muted">Domains</div><span class="fs-4 fw-bold" id="db-total">0</span></div></div></div>
  <div class="col"><div class="card text-center"><div class="card-body py-2"><div class="small text-muted">Clients</div><span class="fs-4 fw-bold" id="db-entities">0</span></div></div></div>
  <div class="col"><div class="card text-center border-success"><div class="card-body py-2"><div class="small text-muted">OK</div><span class="fs-4 fw-bold text-success" id="db-ok">0</span></div></div></div>
  <div class="col"><div class="card text-center border-warning"><div class="card-body py-2"><div class="small text-muted">Warnings</div><span class="fs-4 fw-bold text-warning" id="db-warn">0</span></div></div></div>
  <div class="col"><div class="card text-center border-danger"><div class="card-body py-2"><div class="small text-muted">Failing</div><span class="fs-4 fw-bold text-danger" id="db-fail">0</span></div></div></div>
  <div class="col"><div class="card text-center"><div class="card-body py-2"><div class="small text-muted">Stale (30d+)</div><span class="fs-4 fw-bold text-secondary" id="db-stale">0</span></div></div></div>
  <div class="col"><div class="card text-center"><div class="card-body py-2"><div class="small text-muted">Never Checked</div><span class="fs-4 fw-bold text-muted" id="db-never">0</span></div></div></div>
</div>

<!-- Controls -->
<div class="card mb-3">
  <div class="card-body py-2 d-flex justify-content-between align-items-center">
    <div class="d-flex gap-2 align-items-center">
      <span class="fw-bold">Filter:</span>
      <button class="btn btn-sm btn-outline-secondary db-filter active" data-filter="all">All</button>
      <button class="btn btn-sm btn-outline-danger db-filter" data-filter="fail">Failing</button>
      <button class="btn btn-sm btn-outline-warning db-filter" data-filter="warn">Warnings</button>
      <button class="btn btn-sm btn-outline-success db-filter" data-filter="ok">OK</button>
      <button class="btn btn-sm btn-outline-dark db-filter" data-filter="stale">Stale</button>
      <button class="btn btn-sm btn-outline-secondary db-filter" data-filter="never">Never Checked</button>
    </div>
    <div class="d-flex gap-2">
      <input type="text" id="db-search" class="form-control form-control-sm" placeholder="Search client or domain..." style="width:250px;">
      <button class="btn btn-sm btn-primary" id="db-refresh"><i class="ti ti-refresh me-1"></i>Refresh</button>
      <button class="btn btn-sm btn-success" id="db-scan-all" disabled><i class="ti ti-heart-rate-monitor me-1"></i>Scan All Now</button>
    </div>
  </div>
</div>

<!-- Loading -->
<div id="db-loading" class="mb-3">
  <div class="card"><div class="card-body text-center py-4">
    <div class="spinner-border text-primary me-2" role="status"></div>
    <span>Loading fleet data&hellip;</span>
  </div></div>
</div>

<!-- Scan progress -->
<div id="db-scan-progress" class="card mb-3" style="display:none;">
  <div class="card-body py-3">
    <div class="d-flex justify-content-between align-items-center mb-2">
      <span id="db-scan-text" class="fw-bold">Scanning...</span>
      <span id="db-scan-counter" class="small text-muted"></span>
    </div>
    <div class="progress" style="height:6px;">
      <div class="progress-bar progress-bar-striped progress-bar-animated" id="db-scan-bar" style="width:0%"></div>
    </div>
    <div id="db-scan-errors" class="mt-2"></div>
  </div>
</div>

<!-- Fleet table -->
<div class="card" id="db-table-card" style="display:none;">
  <div class="card-body p-0">
    <table class="table table-sm table-striped table-hover mb-0">
      <thead class="table-light">
        <tr>
          <th style="cursor:pointer;" data-sort="entity">Client <i class="ti ti-arrows-sort"></i></th>
          <th style="cursor:pointer;" data-sort="domain">Domain <i class="ti ti-arrows-sort"></i></th>
          <th style="width:80px;">Status</th>
          <th style="width:50px;">OK</th>
          <th style="width:50px;">Warn</th>
          <th style="width:50px;">Fail</th>
          <th style="width:130px; cursor:pointer;" data-sort="date">Last Checked <i class="ti ti-arrows-sort"></i></th>
          <th style="width:80px;">Age</th>
          <th style="width:80px;"></th>
        </tr>
      </thead>
      <tbody id="db-tbody"></tbody>
    </table>
  </div>
  <div class="card-footer small text-muted" id="db-footer"></div>
</div>

<script>
(function() {
  'use strict';
  const PLUGIN_ROOT = '<?php echo addslashes($pluginRoot); ?>';
  let fleetData = [];
  let currentFilter = 'all';
  let currentSearch = '';
  let sortCol = 'entity';
  let sortAsc = true;

  function getCsrfToken() { const m=document.querySelector('meta[property="glpi:csrf_token"]'); return m?m.getAttribute('content'):''; }
  function esc(s) { const d=document.createElement('div'); d.textContent=String(s||''); return d.innerHTML; }

  function statusBadge(st) {
    if (!st) return '<span class="badge bg-secondary">—</span>';
    const c = st==='ok'?'bg-success':st==='warn'?'bg-warning text-dark':'bg-danger';
    return '<span class="badge '+c+'">'+esc(st.toUpperCase())+'</span>';
  }

  function ageBadge(days, neverChecked) {
    if (neverChecked) return '<span class="badge bg-secondary">Never</span>';
    if (days === null) return '—';
    if (days > 30) return '<span class="badge bg-dark">'+days+'d</span>';
    if (days > 7) return '<span class="badge bg-warning text-dark">'+days+'d</span>';
    return '<span class="text-success">'+days+'d</span>';
  }

  function loadFleet() {
    document.getElementById('db-loading').style.display = 'block';
    document.getElementById('db-table-card').style.display = 'none';

    fetch(PLUGIN_ROOT+'/ajax/dashboard_data.php?action=fleet_overview', {
      credentials: 'same-origin',
      headers: {'X-Requested-With':'XMLHttpRequest','X-Glpi-Csrf-Token':getCsrfToken()}
    })
    .then(r=>r.json())
    .then(resp=>{
      if (!resp.success) throw new Error(resp.message);
      fleetData = resp.fleet;

      // Summary
      const s = resp.summary;
      document.getElementById('db-total').textContent = s.total_domains;
      document.getElementById('db-entities').textContent = s.total_entities;
      document.getElementById('db-ok').textContent = s.ok;
      document.getElementById('db-warn').textContent = s.warn;
      document.getElementById('db-fail').textContent = s.fail;
      document.getElementById('db-stale').textContent = s.stale;
      document.getElementById('db-never').textContent = s.never_checked;
      document.getElementById('db-summary-row').style.display = 'flex';

      renderTable();
      document.getElementById('db-loading').style.display = 'none';
      document.getElementById('db-table-card').style.display = 'block';
      document.getElementById('db-scan-all').disabled = false;
      document.getElementById('db-scan-progress').style.display = 'none';
    })
    .catch(err=>{
      document.getElementById('db-loading').innerHTML = '<div class="alert alert-danger">'+esc(err.message)+'</div>';
    });
  }

  function filterData() {
    let data = [...fleetData];

    // Filter
    if (currentFilter === 'fail') data = data.filter(d=>d.last_report?.status==='fail');
    else if (currentFilter === 'warn') data = data.filter(d=>d.last_report?.status==='warn');
    else if (currentFilter === 'ok') data = data.filter(d=>d.last_report?.status==='ok');
    else if (currentFilter === 'stale') data = data.filter(d=>d.stale && !d.never_checked);
    else if (currentFilter === 'never') data = data.filter(d=>d.never_checked);

    // Search
    if (currentSearch) {
      const q = currentSearch.toLowerCase();
      data = data.filter(d=>d.entity_name.toLowerCase().includes(q) || d.domain.toLowerCase().includes(q));
    }

    // Sort
    data.sort((a, b) => {
      let va, vb;
      if (sortCol === 'entity') { va = a.entity_name.toLowerCase(); vb = b.entity_name.toLowerCase(); }
      else if (sortCol === 'domain') { va = a.domain; vb = b.domain; }
      else if (sortCol === 'date') { va = a.last_report?.date_creation || ''; vb = b.last_report?.date_creation || ''; }
      else { va = a.entity_name.toLowerCase(); vb = b.entity_name.toLowerCase(); }
      if (va < vb) return sortAsc ? -1 : 1;
      if (va > vb) return sortAsc ? 1 : -1;
      return 0;
    });

    return data;
  }

  function renderTable() {
    const data = filterData();
    const tbody = document.getElementById('db-tbody');

    if (!data.length) {
      tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted py-3">No domains match the current filter.</td></tr>';
      document.getElementById('db-footer').textContent = '0 domains shown';
      return;
    }

    let html = '';
    for (const d of data) {
      const r = d.last_report;
      const rowClass = d.never_checked ? '' : (r?.status==='fail'?' table-danger':r?.status==='warn'?' table-warning':'');
      const date = r ? r.date_creation.substring(0, 16) : '—';

      html += '<tr class="'+rowClass+'">';
      html += '<td><strong>'+esc(d.entity_name)+'</strong></td>';
      html += '<td><code>'+esc(d.domain)+'</code>'+(d.is_primary?' <span class="badge bg-primary" style="font-size:0.6rem;">P</span>':'')+'</td>';
      html += '<td>'+statusBadge(r?.status)+'</td>';
      html += '<td class="text-success">'+(r?r.checks_ok:'—')+'</td>';
      html += '<td class="text-warning">'+(r?r.checks_warn:'—')+'</td>';
      html += '<td class="text-danger">'+(r?r.checks_fail:'—')+'</td>';
      html += '<td class="small">'+esc(date)+'</td>';
      html += '<td>'+ageBadge(d.days_since_check, d.never_checked)+'</td>';
      html += '<td><a href="'+PLUGIN_ROOT+'/front/health_check.php?entities_id='+d.entities_id+'&domain='+encodeURIComponent(d.domain)+'&entity_name='+encodeURIComponent(d.entity_name)+'" class="btn btn-sm btn-outline-primary" title="Run health check for '+esc(d.domain)+'"><i class="ti ti-player-play"></i></a></td>';
      html += '</tr>';
    }
    tbody.innerHTML = html;
    document.getElementById('db-footer').textContent = data.length + ' of ' + fleetData.length + ' domains shown';
  }

  // Filter buttons
  document.querySelectorAll('.db-filter').forEach(btn => {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.db-filter').forEach(b=>b.classList.remove('active'));
      this.classList.add('active');
      currentFilter = this.dataset.filter;
      renderTable();
    });
  });

  // Search
  document.getElementById('db-search').addEventListener('input', function() {
    currentSearch = this.value.trim();
    renderTable();
  });

  // Sort
  document.querySelectorAll('th[data-sort]').forEach(th => {
    th.addEventListener('click', function() {
      const col = this.dataset.sort;
      if (sortCol === col) sortAsc = !sortAsc;
      else { sortCol = col; sortAsc = true; }
      renderTable();
    });
  });

  // Refresh
  document.getElementById('db-refresh').addEventListener('click', loadFleet);

  // Scan All
  const scanAllBtn = document.getElementById('db-scan-all');
  const scanProgress = document.getElementById('db-scan-progress');
  const scanText = document.getElementById('db-scan-text');
  const scanCounter = document.getElementById('db-scan-counter');
  const scanBar = document.getElementById('db-scan-bar');
  const scanErrors = document.getElementById('db-scan-errors');

  scanAllBtn.addEventListener('click', async function() {
    const filtered = filterData();
    if (!filtered.length) return;

    if (!confirm('This will run a full health check on ' + filtered.length + ' domain(s). This may take several minutes. Continue?')) return;

    scanAllBtn.disabled = true;
    scanProgress.style.display = 'block';
    scanErrors.innerHTML = '';
    let completed = 0;
    let errors = 0;
    const total = filtered.length;
    const CONCURRENCY = 1; // Sequential to avoid exhausting PHP-FPM workers

    function updateProgress(currentDomains) {
      const pct = Math.round((completed / total) * 100);
      scanText.textContent = 'Scanning: ' + currentDomains.join(', ');
      scanCounter.textContent = completed + ' / ' + total + (errors > 0 ? ' (' + errors + ' error' + (errors>1?'s':'') + ')' : '');
      scanBar.style.width = pct + '%';
    }

    async function scanOne(item) {
      try {
        const data = new FormData();
        data.append('domain', item.domain);
        data.append('entities_id', item.entities_id);
        data.append('store_result', '1');
        data.append('dkim_selector', 'selector1');

        const r = await fetch(PLUGIN_ROOT + '/ajax/health_check.php', {
          method: 'POST', body: data, credentials: 'same-origin',
          headers: {'X-Requested-With':'XMLHttpRequest','X-Glpi-Csrf-Token':getCsrfToken()}
        });

        const ct = r.headers.get('content-type') || '';
        if (!ct.includes('json')) {
          throw new Error('Non-JSON response (HTTP ' + r.status + ') — possible session/CSRF timeout');
        }

        const resp = await r.json();
        if (!resp.success) throw new Error(resp.message);
      } catch (err) {
        errors++;
        scanErrors.innerHTML += '<div class="small text-danger"><code>' + esc(item.domain) + '</code>: ' + esc(err.message) + '</div>';
      }
      completed++;
    }

    async function refreshFleetData() {
      try {
        const resp = await fetch(PLUGIN_ROOT+'/ajax/dashboard_data.php?action=fleet_overview', {
          credentials: 'same-origin',
          headers: {'X-Requested-With':'XMLHttpRequest','X-Glpi-Csrf-Token':getCsrfToken()}
        }).then(r=>r.json());
        if (resp.success) {
          fleetData = resp.fleet;
          const s = resp.summary;
          document.getElementById('db-total').textContent = s.total_domains;
          document.getElementById('db-entities').textContent = s.total_entities;
          document.getElementById('db-ok').textContent = s.ok;
          document.getElementById('db-warn').textContent = s.warn;
          document.getElementById('db-fail').textContent = s.fail;
          document.getElementById('db-stale').textContent = s.stale;
          document.getElementById('db-never').textContent = s.never_checked;
          renderTable();
        }
      } catch(e) {}
    }

    // Process in batches of CONCURRENCY, refresh table after each batch
    const queue = [...filtered];
    while (queue.length > 0) {
      const batch = queue.splice(0, CONCURRENCY);
      updateProgress(batch.map(b => b.domain));
      await Promise.all(batch.map(item => scanOne(item)));
      await refreshFleetData();
    }

    scanText.textContent = 'Scan complete — ' + total + ' domains, ' + errors + ' error' + (errors!==1?'s':'');
    scanBar.style.width = '100%';
    scanBar.classList.remove('progress-bar-animated');
    scanAllBtn.disabled = false;

    // Final refresh
    setTimeout(loadFleet, 1000);
  });

  // Initial load
  loadFleet();
})();
</script>

<?php Html::footer(); ?>
