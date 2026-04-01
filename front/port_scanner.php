<?php
include('../../../inc/includes.php');

Session::checkLoginUser();

Html::header(__('Port / Service Scanner'), $_SERVER['PHP_SELF'], 'tools', 'pluginclearsignaldiagmenu', 'ports');

$config = PluginClearsignaldiagConfig::getConfig();
$pluginRoot = Plugin::getWebDir('clearsignaldiag');
?>

<?php include __DIR__ . '/../templates/nav_pills.php'; ?>

<div class="card mb-3">
  <div class="card-header d-flex justify-content-between align-items-center">
    <h3 class="card-title mb-0"><i class="ti ti-plug me-1"></i>Port / Service Scanner</h3>
    <span class="badge bg-secondary" id="csd-badge" style="display:none;"></span>
  </div>
  <div class="card-body">
    <form id="csd-form" autocomplete="off">
      <input type="hidden" name="_glpi_csrf_token" value="<?php echo htmlspecialchars(Session::getNewCSRFToken(), ENT_QUOTES, 'UTF-8'); ?>">
      <input type="hidden" name="scan_preset" id="csd-preset-value" value="full">

      <div class="row mb-3">
        <div class="col-md-6">
          <label for="csd-target" class="form-label fw-bold">Target Host / IP</label>
          <input type="text" id="csd-target" name="target" class="form-control form-control-lg"
                 placeholder="e.g. server.example.com or 192.168.1.1" required>
        </div>
        <div class="col-md-4">
          <label class="form-label fw-bold">Scan Preset</label>
          <select id="csd-preset" class="form-select form-select-lg">
            <option value="full" selected>Comprehensive (all common ports)</option>
            <option value="quick">Quick Scan (SSH, SMTP, DNS, HTTP, HTTPS, RDP)</option>
            <option value="mail">Mail Server (SMTP, POP3, IMAP, submission)</option>
            <option value="web">Web Server (HTTP, HTTPS, alt ports)</option>
            <option value="remote">Remote Access (SSH, RDP, VNC, Splashtop)</option>
            <option value="voip">VoIP (SIP TCP/UDP, SIP TLS)</option>
            <option value="management">Management (SNMP, SSH, HTTPS, RMM)</option>
            <option value="custom">Custom ports&hellip;</option>
          </select>
        </div>
        <div class="col-md-2 d-flex align-items-end">
          <button type="button" class="btn btn-primary btn-lg w-100" id="csd-btn-run">
            <i class="ti ti-player-play me-1"></i>Scan
          </button>
        </div>
      </div>

      <!-- Custom ports (hidden by default) -->
      <div class="mb-3" id="csd-custom-row" style="display:none;">
        <label for="csd-custom-ports" class="form-label fw-bold">Custom Ports</label>
        <input type="text" id="csd-custom-ports" class="form-control"
               placeholder="e.g. 22, 80, 443, 3389, 161/udp, 4081">
        <div class="form-text">Comma-separated. Append /udp for UDP ports (default is TCP). e.g. <code>22, 80, 443, 161/udp</code></div>
      </div>
    </form>

    <div id="csd-loading" style="display:none;" class="mb-3">
      <div class="d-flex align-items-center text-primary">
        <div class="spinner-border spinner-border-sm me-2" role="status"></div>
        <span>Scanning ports&hellip; this may take 15–30 seconds depending on filtered ports.</span>
      </div>
      <div class="progress mt-2" style="height:3px;"><div class="progress-bar progress-bar-striped progress-bar-animated" style="width:100%"></div></div>
    </div>
    <div id="csd-error" class="alert alert-danger mb-3" style="display:none;" role="alert"></div>
  </div>
</div>

<div id="csd-results" style="display:none;">
  <!-- Summary -->
  <div class="card mb-3"><div class="card-body py-3" id="csd-summary-body"></div></div>

  <!-- Results table -->
  <div class="card mb-3">
    <div class="card-header d-flex justify-content-between align-items-center">
      <h5 class="card-title mb-0">Scan Results</h5>
      <div>
        <button class="btn btn-sm btn-outline-secondary me-1" id="csd-filter-all">All</button>
        <button class="btn btn-sm btn-outline-success" id="csd-filter-open">Open</button>
        <button class="btn btn-sm btn-outline-danger" id="csd-filter-closed">Closed</button>
        <button class="btn btn-sm btn-outline-warning" id="csd-filter-filtered">Filtered</button>
      </div>
    </div>
    <div class="card-body p-0">
      <table class="table table-sm table-striped mb-0" id="csd-port-table">
        <thead><tr><th style="width:80px;">Port</th><th style="width:70px;">Proto</th><th style="width:140px;">Service</th><th style="width:100px;">State</th><th>Banner / Info</th><th style="width:90px;">Response</th></tr></thead>
        <tbody id="csd-port-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- Copy to ticket -->
  <div class="card">
    <div class="card-header"><h5 class="card-title mb-0"><i class="ti ti-clipboard-copy me-1"></i>Copy to Ticket</h5></div>
    <div class="card-body">
      <div class="row">
        <div class="col-md-4">
          <label for="csd-ticket-id" class="form-label fw-bold">Ticket ID</label>
          <input type="number" id="csd-ticket-id" class="form-control" placeholder="e.g. 2217" min="1">
        </div>
        <div class="col-md-8 d-flex align-items-end gap-2">
          <button type="button" class="btn btn-outline-primary" id="csd-btn-copy-note" disabled><i class="ti ti-lock me-1"></i>Add as Private Note</button>
          <button type="button" class="btn btn-outline-secondary" id="csd-btn-copy-client" disabled><i class="ti ti-send me-1"></i>Add as Client Summary</button>
        </div>
      </div>
      <div id="csd-copy-toast" class="alert alert-success mt-2" style="display:none;" role="alert"></div>
    </div>
  </div>
</div>

<script>
(function() {
  'use strict';
  const PLUGIN_ROOT = '<?php echo addslashes($pluginRoot); ?>';
  let lastData = null;
  let lastScanDetails = null;

  const form = document.getElementById('csd-form');
  const btnRun = document.getElementById('csd-btn-run');
  const loading = document.getElementById('csd-loading');
  const errDiv = document.getElementById('csd-error');
  const resultsEl = document.getElementById('csd-results');
  const badge = document.getElementById('csd-badge');
  const presetSelect = document.getElementById('csd-preset');
  const presetValue = document.getElementById('csd-preset-value');
  const customRow = document.getElementById('csd-custom-row');
  const btnNote = document.getElementById('csd-btn-copy-note');
  const btnClient = document.getElementById('csd-btn-copy-client');
  const ticketInput = document.getElementById('csd-ticket-id');
  const copyToast = document.getElementById('csd-copy-toast');

  function getCsrfToken() { const m=document.querySelector('meta[property="glpi:csrf_token"]'); return m?m.getAttribute('content'):(document.querySelector('input[name="_glpi_csrf_token"]')?.value||''); }
  function esc(s) { const d=document.createElement('div'); d.textContent=String(s||''); return d.innerHTML; }
  function showErr(m) { errDiv.textContent=m; errDiv.style.display='block'; }
  function hideErr() { errDiv.style.display='none'; }
  function showToast(msg) { copyToast.textContent=msg; copyToast.style.display='block'; setTimeout(()=>{copyToast.style.display='none';},4000); }

  // Preset toggle
  presetSelect.addEventListener('change', function() {
    presetValue.value = this.value;
    customRow.style.display = this.value === 'custom' ? 'block' : 'none';
  });

  function stateBadge(state) {
    if (state === 'open') return '<span class="badge bg-success">OPEN</span>';
    if (state === 'closed') return '<span class="badge bg-danger">CLOSED</span>';
    if (state === 'filtered') return '<span class="badge bg-warning text-dark">FILTERED</span>';
    if (state === 'open|filtered') return '<span class="badge bg-info text-dark">OPEN|FILTERED</span>';
    return '<span class="badge bg-secondary">'+esc(state)+'</span>';
  }

  function renderSummary(d) {
    const body = document.getElementById('csd-summary-body');
    let html = '<div class="row text-center">';
    html += '<div class="col"><div class="small text-muted">Host</div><code class="fw-bold">'+esc(d.host)+'</code></div>';
    html += '<div class="col"><div class="small text-muted">Preset</div><span class="fw-bold">'+esc(d.preset_label)+'</span></div>';
    html += '<div class="col"><div class="small text-muted">Scanned</div><span class="fw-bold">'+d.total_scanned+'</span></div>';
    html += '<div class="col"><div class="small text-muted">Open</div><span class="fw-bold text-success">'+d.open_count+'</span></div>';
    html += '<div class="col"><div class="small text-muted">Closed</div><span class="fw-bold text-danger">'+d.closed_count+'</span></div>';
    html += '<div class="col"><div class="small text-muted">Filtered</div><span class="fw-bold text-warning">'+d.filtered_count+'</span></div>';
    html += '</div>';
    body.innerHTML = html;
  }

  function renderTable(results, filter) {
    const tbody = document.getElementById('csd-port-tbody');
    let html = '';
    for (const r of results) {
      if (filter && r.state !== filter) continue;
      const banner = r.banner ? '<code class="small" style="word-break:break-all;">'+esc(r.banner)+'</code>' : '';
      const tls = r.tls_version ? '<span class="badge bg-info text-dark ms-1">'+esc(r.tls_version)+'</span>' : '';
      const note = r.note ? '<span class="small text-muted">'+esc(r.note)+'</span>' : '';
      const resp = r.response_time_ms ? r.response_time_ms+'ms' : '—';
      html += '<tr data-state="'+esc(r.state)+'">';
      html += '<td class="fw-bold">'+r.port+'</td>';
      html += '<td><code>'+esc(r.protocol.toUpperCase())+'</code></td>';
      html += '<td>'+esc(r.service)+'</td>';
      html += '<td>'+stateBadge(r.state)+'</td>';
      html += '<td>'+banner+tls+note+'</td>';
      html += '<td>'+resp+'</td>';
      html += '</tr>';
    }
    tbody.innerHTML = html || '<tr><td colspan="6" class="text-muted text-center">No results for this filter.</td></tr>';
  }

  // Filters
  document.getElementById('csd-filter-all').addEventListener('click', ()=>renderTable(lastScanDetails.results));
  document.getElementById('csd-filter-open').addEventListener('click', ()=>renderTable(lastScanDetails.results, 'open'));
  document.getElementById('csd-filter-closed').addEventListener('click', ()=>renderTable(lastScanDetails.results, 'closed'));
  document.getElementById('csd-filter-filtered').addEventListener('click', ()=>renderTable(lastScanDetails.results, 'filtered'));

  // Parse custom ports string into array
  function parseCustomPorts(str) {
    const ports = [];
    for (const part of str.split(',')) {
      const p = part.trim();
      if (!p) continue;
      const match = p.match(/^(\d+)\s*\/?\s*(tcp|udp)?$/i);
      if (match) {
        ports.push({port: parseInt(match[1]), protocol: (match[2]||'tcp').toLowerCase(), service: ''});
      }
    }
    return ports;
  }

  // Copy to ticket
  function buildEngineerSummary() {
    if (!lastScanDetails) return '';
    const d = lastScanDetails;
    const lines = ['=== ClearSignal Port Scan ===','Date: '+new Date().toISOString().replace('T',' ').substring(0,19),'Host: '+d.host,'Preset: '+d.preset_label,''];
    lines.push('Open: '+d.open_count+' | Closed: '+d.closed_count+' | Filtered: '+d.filtered_count+' | Total: '+d.total_scanned);
    lines.push('');
    lines.push('Port     Proto  Service              State      Banner');
    lines.push('-------  -----  -------------------  ---------  ------');
    for (const r of d.results) {
      const port = String(r.port).padEnd(7);
      const proto = r.protocol.toUpperCase().padEnd(5);
      const svc = (r.service||'').padEnd(19);
      const state = r.state.toUpperCase().padEnd(9);
      const banner = r.banner ? r.banner.substring(0,40) : '';
      lines.push(port+'  '+proto+'  '+svc+'  '+state+'  '+banner);
    }
    lines.push('','=== End of Report ===');
    return lines.join('\n');
  }

  function buildClientSummary() {
    if (!lastScanDetails) return '';
    const d = lastScanDetails;
    const lines = ['Port Scan Report for '+d.host,'Date: '+new Date().toISOString().replace('T',' ').substring(0,19),''];
    lines.push('Scanned '+d.total_scanned+' ports: '+d.open_count+' open, '+d.closed_count+' closed, '+d.filtered_count+' filtered.');
    lines.push('');
    const open = d.results.filter(r=>r.state==='open');
    if (open.length) {
      lines.push('Open services:');
      for (const r of open) lines.push('  - Port '+r.port+' ('+r.protocol.toUpperCase()+') — '+r.service+(r.tls_version?' ['+r.tls_version+']':''));
    }
    const filtered = d.results.filter(r=>r.state==='filtered');
    if (filtered.length) {
      lines.push('');
      lines.push('Filtered (may be blocked by firewall):');
      for (const r of filtered) lines.push('  - Port '+r.port+' ('+r.protocol.toUpperCase()+') — '+r.service);
    }
    lines.push('','Report generated by ClearSignal Diagnostics');
    return lines.join('\n');
  }

  function copyToTicket(summary) {
    const tid = parseInt(ticketInput.value,10);
    if (!tid||tid<=0) { showErr('Enter a valid ticket ID.'); return; }
    hideErr();
    const data = new FormData();
    data.append('tickets_id',tid);
    data.append('summary',summary);
    fetch(PLUGIN_ROOT+'/ajax/addtoticket.php',{method:'POST',body:data,credentials:'same-origin',headers:{'X-Requested-With':'XMLHttpRequest','X-Glpi-Csrf-Token':getCsrfToken()}})
    .then(r=>{if(!r.headers.get('content-type')?.includes('json')) throw new Error('Non-JSON');return r.json();})
    .then(resp=>{if(!resp.success)throw new Error(resp.message);showToast('Added to ticket #'+tid+'.');})
    .catch(err=>showErr(String(err.message||err)));
  }
  btnNote.addEventListener('click',()=>copyToTicket(buildEngineerSummary()));
  btnClient.addEventListener('click',()=>copyToTicket(buildClientSummary()));

  // Run
  btnRun.addEventListener('click', function() {
    const target = document.getElementById('csd-target').value.trim();
    if (!target) { showErr('Enter a target host or IP.'); return; }
    hideErr();

    const preset = presetSelect.value;
    const data = new FormData(form);
    data.append('checks[]', 'port_scan');

    if (preset === 'custom') {
      const customStr = document.getElementById('csd-custom-ports').value.trim();
      if (!customStr) { showErr('Enter custom ports.'); return; }
      const customPorts = parseCustomPorts(customStr);
      if (customPorts.length === 0) { showErr('No valid ports parsed.'); return; }
      data.set('scan_preset', 'custom');
      data.append('custom_ports', JSON.stringify(customPorts));
    } else {
      data.set('scan_preset', preset);
    }

    resultsEl.style.display='none'; loading.style.display='block'; btnRun.disabled=true;
    badge.style.display='inline-block'; badge.textContent='Scanning...'; badge.className='badge bg-primary';

    fetch(PLUGIN_ROOT+'/ajax/run_standalone.php',{method:'POST',body:data,credentials:'same-origin',headers:{'X-Requested-With':'XMLHttpRequest','X-Glpi-Csrf-Token':getCsrfToken()}})
    .then(r=>{if(!r.headers.get('content-type')?.includes('json'))return r.text().then(()=>{throw new Error('Non-JSON (HTTP '+r.status+')');});return r.json();})
    .then(resp=>{
      loading.style.display='none'; btnRun.disabled=false;
      if (!resp.success) throw new Error(resp.message);

      lastData = resp.data;
      const check = (resp.data.checks||[])[0];
      if (!check || !check.details) throw new Error('No scan data returned.');
      lastScanDetails = check.details;

      renderSummary(check.details);
      renderTable(check.details.results);
      resultsEl.style.display='block'; btnNote.disabled=false; btnClient.disabled=false;

      const d = check.details;
      if (d.open_count === 0) { badge.textContent='No open ports'; badge.className='badge bg-warning text-dark'; }
      else { badge.textContent=d.open_count+' open'; badge.className='badge bg-success'; }
    })
    .catch(err=>{loading.style.display='none';btnRun.disabled=false;showErr(String(err.message||err));badge.textContent='Error';badge.className='badge bg-danger';});
  });
})();
</script>

<?php Html::footer(); ?>
