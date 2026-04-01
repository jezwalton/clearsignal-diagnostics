<?php
include('../../../inc/includes.php');

Session::checkLoginUser();

Html::header(__('Domain Health Check'), $_SERVER['PHP_SELF'], 'tools', 'pluginclearsignaldiagmenu', 'health');

$config = PluginClearsignaldiagConfig::getConfig();
$pluginRoot = Plugin::getWebDir('clearsignaldiag');
?>

<?php include __DIR__ . '/../templates/nav_pills.php'; ?>

<!-- Mode selector -->
<ul class="nav nav-tabs mb-3" id="hc-mode-tabs">
  <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#hc-entity-mode">Client / Entity</a></li>
  <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#hc-quick-mode">Quick Domain Check</a></li>
</ul>

<div class="tab-content">

  <!-- ==================== ENTITY MODE ==================== -->
  <div class="tab-pane fade show active" id="hc-entity-mode">
    <div class="card mb-3">
      <div class="card-header"><h5 class="card-title mb-0"><i class="ti ti-building me-1"></i>Client Health Check</h5></div>
      <div class="card-body">

        <!-- Entity search -->
        <div class="row mb-3">
          <div class="col-md-6">
            <label class="form-label fw-bold">Search Client / Entity</label>
            <input type="text" id="hc-entity-search" class="form-control" placeholder="Start typing client name...">
            <div id="hc-entity-results" class="list-group position-absolute" style="z-index:1000; max-height:250px; overflow:auto; display:none;"></div>
          </div>
          <div class="col-md-6">
            <div id="hc-selected-entity" style="display:none;" class="alert alert-info mb-0 mt-4">
              <strong>Selected:</strong> <span id="hc-entity-name"></span>
              <input type="hidden" id="hc-entity-id" value="">
            </div>
          </div>
        </div>

        <!-- Domain management -->
        <div id="hc-domain-section" style="display:none;">
          <h6 class="fw-bold">Domains for this client</h6>
          <table class="table table-sm table-striped mb-2" id="hc-domain-table">
            <thead><tr><th>Domain</th><th>Label</th><th>Primary</th><th style="width:60px;"></th></tr></thead>
            <tbody id="hc-domain-tbody"></tbody>
          </table>

          <!-- Add domain form -->
          <div class="row g-2 mb-3">
            <div class="col-md-4"><input type="text" id="hc-add-domain" class="form-control form-control-sm" placeholder="domain.co.uk"></div>
            <div class="col-md-3"><input type="text" id="hc-add-label" class="form-control form-control-sm" placeholder="Label (optional)"></div>
            <div class="col-md-2"><div class="form-check mt-1"><input class="form-check-input" type="checkbox" id="hc-add-primary"><label class="form-check-label small" for="hc-add-primary">Primary</label></div></div>
            <div class="col-md-2"><button class="btn btn-sm btn-outline-primary w-100" id="hc-btn-add-domain"><i class="ti ti-plus me-1"></i>Add</button></div>
          </div>

          <!-- DKIM selector -->
          <div class="row mb-3">
            <div class="col-md-3">
              <label class="form-label fw-bold">DKIM Selector</label>
              <input type="text" id="hc-dkim-selector" class="form-control" value="<?php echo htmlspecialchars((string)($config['default_selector'] ?? 'selector1'), ENT_QUOTES, 'UTF-8'); ?>">
            </div>
            <div class="col-md-9 d-flex align-items-end">
              <button class="btn btn-primary btn-lg" id="hc-btn-run-entity" disabled><i class="ti ti-heart-rate-monitor me-1"></i>Run Health Check — All Domains</button>
            </div>
          </div>
        </div>

      </div>
    </div>

    <!-- Entity results -->
    <div id="hc-entity-loading" style="display:none;" class="mb-3">
      <div class="card"><div class="card-body">
        <div class="d-flex align-items-center text-primary">
          <div class="spinner-border spinner-border-sm me-2" role="status"></div>
          <span id="hc-entity-loading-text">Running health checks&hellip;</span>
        </div>
        <div class="progress mt-2" style="height:3px;"><div class="progress-bar progress-bar-striped progress-bar-animated" style="width:100%"></div></div>
      </div></div>
    </div>
    <div id="hc-entity-error" class="alert alert-danger mb-3" style="display:none;"></div>
    <div id="hc-entity-results-section" style="display:none;"></div>

    <!-- History -->
    <div id="hc-history-section" style="display:none;">
      <div class="card mt-3">
        <div class="card-header"><h5 class="card-title mb-0"><i class="ti ti-history me-1"></i>Previous Reports</h5></div>
        <div class="card-body p-0">
          <table class="table table-sm table-striped mb-0">
            <thead><tr><th>Date</th><th>Domain</th><th>Status</th><th>OK</th><th>Warn</th><th>Fail</th></tr></thead>
            <tbody id="hc-history-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- ==================== QUICK MODE ==================== -->
  <div class="tab-pane fade" id="hc-quick-mode">
    <div class="card mb-3">
      <div class="card-header"><h5 class="card-title mb-0"><i class="ti ti-rocket me-1"></i>Quick Domain Health Check</h5></div>
      <div class="card-body">
        <div class="row mb-3">
          <div class="col-md-6">
            <label class="form-label fw-bold">Domain</label>
            <input type="text" id="hc-quick-domain" class="form-control form-control-lg" placeholder="e.g. example.co.uk">
          </div>
          <div class="col-md-3">
            <label class="form-label fw-bold">DKIM Selector</label>
            <input type="text" id="hc-quick-selector" class="form-control form-control-lg" value="<?php echo htmlspecialchars((string)($config['default_selector'] ?? 'selector1'), ENT_QUOTES, 'UTF-8'); ?>">
          </div>
          <div class="col-md-3 d-flex align-items-end">
            <button class="btn btn-primary btn-lg w-100" id="hc-btn-run-quick"><i class="ti ti-player-play me-1"></i>Run</button>
          </div>
        </div>
      </div>
    </div>
    <div id="hc-quick-loading" style="display:none;" class="mb-3">
      <div class="card"><div class="card-body">
        <div class="d-flex align-items-center text-primary">
          <div class="spinner-border spinner-border-sm me-2" role="status"></div>
          <span>Running comprehensive health check&hellip; this may take 30–60 seconds.</span>
        </div>
        <div class="progress mt-2" style="height:3px;"><div class="progress-bar progress-bar-striped progress-bar-animated" style="width:100%"></div></div>
      </div></div>
    </div>
    <div id="hc-quick-error" class="alert alert-danger mb-3" style="display:none;"></div>
    <div id="hc-quick-results-section" style="display:none;"></div>
  </div>

</div>

<script>
(function() {
  'use strict';
  const PLUGIN_ROOT = '<?php echo addslashes($pluginRoot); ?>';
  let currentEntityId = 0;
  let currentEntityName = '';
  let entityDomains = [];

  function getCsrfToken() { const m=document.querySelector('meta[property="glpi:csrf_token"]'); return m?m.getAttribute('content'):(document.querySelector('input[name="_glpi_csrf_token"]')?.value||''); }
  function esc(s) { const d=document.createElement('div'); d.textContent=String(s||''); return d.innerHTML; }

  function statusBadge(st) {
    const c = st==='ok'?'bg-success':st==='warn'?'bg-warning text-dark':'bg-danger';
    return '<span class="badge '+c+'">'+esc(st.toUpperCase())+'</span>';
  }

  function ajaxPost(url, data) {
    return fetch(url, {method:'POST', body:data, credentials:'same-origin',
      headers:{'X-Requested-With':'XMLHttpRequest','X-Glpi-Csrf-Token':getCsrfToken()}
    }).then(r=>{
      if(!r.headers.get('content-type')?.includes('json')) return r.text().then(()=>{throw new Error('Non-JSON (HTTP '+r.status+')');});
      return r.json();
    }).then(resp=>{if(!resp.success) throw new Error(resp.message); return resp;});
  }

  function ajaxGet(url) {
    return fetch(url, {credentials:'same-origin',
      headers:{'X-Requested-With':'XMLHttpRequest','X-Glpi-Csrf-Token':getCsrfToken()}
    }).then(r=>{
      if(!r.headers.get('content-type')?.includes('json')) return r.text().then(()=>{throw new Error('Non-JSON');});
      return r.json();
    }).then(resp=>{if(!resp.success) throw new Error(resp.message); return resp;});
  }

  // ---- Entity search ----
  let searchTimer = null;
  const searchInput = document.getElementById('hc-entity-search');
  const searchResults = document.getElementById('hc-entity-results');

  searchInput.addEventListener('input', function() {
    clearTimeout(searchTimer);
    const q = this.value.trim();
    if (q.length < 2) { searchResults.style.display='none'; return; }
    searchTimer = setTimeout(()=>{
      ajaxGet(PLUGIN_ROOT+'/ajax/entity_domains.php?action=search_entities&q='+encodeURIComponent(q))
      .then(resp=>{
        if (!resp.entities.length) { searchResults.innerHTML='<div class="list-group-item text-muted">No results</div>'; searchResults.style.display='block'; return; }
        searchResults.innerHTML = resp.entities.map(e=>'<a href="#" class="list-group-item list-group-item-action" data-id="'+e.id+'">'+esc(e.name)+'</a>').join('');
        searchResults.style.display='block';
      }).catch(()=>{ searchResults.style.display='none'; });
    }, 300);
  });

  searchResults.addEventListener('click', function(e) {
    e.preventDefault();
    const item = e.target.closest('[data-id]');
    if (!item) return;
    currentEntityId = parseInt(item.dataset.id);
    currentEntityName = item.textContent;
    document.getElementById('hc-entity-name').textContent = currentEntityName;
    document.getElementById('hc-entity-id').value = currentEntityId;
    document.getElementById('hc-selected-entity').style.display='block';
    searchResults.style.display='none';
    searchInput.value = currentEntityName;
    loadDomains();
    loadHistory();
  });

  document.addEventListener('click', (e)=>{ if(!searchResults.contains(e.target)&&e.target!==searchInput) searchResults.style.display='none'; });

  // ---- Domain management ----
  function loadDomains() {
    const data = new FormData();
    data.append('action','list');
    data.append('entities_id', currentEntityId);
    ajaxPost(PLUGIN_ROOT+'/ajax/entity_domains.php', data).then(resp=>{
      entityDomains = resp.domains;
      renderDomains();
      document.getElementById('hc-domain-section').style.display='block';
      document.getElementById('hc-btn-run-entity').disabled = entityDomains.length === 0;
    });
  }

  function renderDomains() {
    const tbody = document.getElementById('hc-domain-tbody');
    if (!entityDomains.length) { tbody.innerHTML='<tr><td colspan="4" class="text-muted text-center">No domains registered. Add one below.</td></tr>'; return; }
    tbody.innerHTML = entityDomains.map(d=>
      '<tr><td><code>'+esc(d.domain)+'</code></td><td>'+esc(d.label)+'</td><td>'+(d.is_primary?'<span class="badge bg-primary">Primary</span>':'')+'</td>'
      +'<td><button class="btn btn-sm btn-outline-danger hc-remove-domain" data-id="'+d.id+'"><i class="ti ti-trash"></i></button></td></tr>'
    ).join('');
  }

  document.getElementById('hc-domain-tbody').addEventListener('click', function(e) {
    const btn = e.target.closest('.hc-remove-domain');
    if (!btn) return;
    if (!confirm('Remove this domain?')) return;
    const data = new FormData();
    data.append('action','remove');
    data.append('entities_id', currentEntityId);
    data.append('domain_id', btn.dataset.id);
    ajaxPost(PLUGIN_ROOT+'/ajax/entity_domains.php', data).then(()=>loadDomains());
  });

  document.getElementById('hc-btn-add-domain').addEventListener('click', function() {
    const domain = document.getElementById('hc-add-domain').value.trim();
    if (!domain) return;
    const data = new FormData();
    data.append('action','add');
    data.append('entities_id', currentEntityId);
    data.append('domain', domain);
    data.append('label', document.getElementById('hc-add-label').value.trim());
    data.append('is_primary', document.getElementById('hc-add-primary').checked ? '1' : '0');
    ajaxPost(PLUGIN_ROOT+'/ajax/entity_domains.php', data).then(()=>{
      document.getElementById('hc-add-domain').value='';
      document.getElementById('hc-add-label').value='';
      document.getElementById('hc-add-primary').checked=false;
      loadDomains();
    }).catch(err=>alert(err.message));
  });

  // ---- History ----
  function loadHistory() {
    const data = new FormData();
    data.append('action','reports');
    data.append('entities_id', currentEntityId);
    ajaxPost(PLUGIN_ROOT+'/ajax/entity_domains.php', data).then(resp=>{
      const tbody = document.getElementById('hc-history-tbody');
      if (!resp.reports.length) { tbody.innerHTML='<tr><td colspan="6" class="text-muted text-center">No previous reports.</td></tr>'; }
      else {
        tbody.innerHTML = resp.reports.map(r=>
          '<tr><td class="small">'+esc(r.date_creation)+'</td><td><code>'+esc(r.domain)+'</code></td><td>'+statusBadge(r.status)+'</td>'
          +'<td class="text-success">'+r.checks_ok+'</td><td class="text-warning">'+r.checks_warn+'</td><td class="text-danger">'+r.checks_fail+'</td></tr>'
        ).join('');
      }
      document.getElementById('hc-history-section').style.display='block';
    });
  }

  // ---- Render health results for a domain ----
  function renderDomainResult(domain, data) {
    const checks = data.checks || [];
    const ok = checks.filter(c=>c.status==='ok').length;
    const warn = checks.filter(c=>c.status==='warn').length;
    const fail = checks.filter(c=>c.status==='fail').length;
    const overall = fail>0?'fail':warn>0?'warn':'ok';

    // Group by category
    const categories = {
      'DNS': ['Full Record Scan','SOA Record','Nameservers','Delegation Trace','DNSSEC','Cloudflare','Resolver Comparison','Domain Registration'],
      'Email': ['MX Records','SMTP Connectivity','SPF','DKIM','DMARC'],
      'Website': ['HTTP Response','TLS Certificate','Security Headers','HTTP/2 Support','CAA Records','Cloudflare SSL Mode'],
    };

    let html = '<div class="card mb-3"><div class="card-header d-flex justify-content-between align-items-center">';
    html += '<h5 class="mb-0">'+statusBadge(overall)+' <code>'+esc(domain)+'</code></h5>';
    html += '<span class="small text-muted">'+ok+' OK, '+warn+' Warn, '+fail+' Fail ('+checks.length+' checks)</span>';
    html += '</div><div class="card-body">';

    for (const [catName, checkNames] of Object.entries(categories)) {
      const catChecks = checks.filter(c=>checkNames.includes(c.name));
      if (!catChecks.length) continue;
      const catWorst = catChecks.reduce((w,c)=>c.status==='fail'?'fail':(c.status==='warn'&&w!=='fail'?'warn':w),'ok');
      html += '<h6 class="mt-2">'+statusBadge(catWorst)+' '+esc(catName)+'</h6>';
      html += '<table class="table table-sm table-striped mb-2"><tbody>';
      for (const c of catChecks) {
        const dot = c.status==='ok'?'text-success':c.status==='warn'?'text-warning':'text-danger';
        html += '<tr><td style="width:200px;"><i class="ti ti-circle-filled '+dot+' me-1" style="font-size:0.6rem;"></i>'+esc(c.name)+'</td>';
        html += '<td class="small">'+esc(c.summary)+'</td></tr>';
        if (c.likely_root_cause) html += '<tr><td></td><td class="small text-danger">'+esc(c.likely_root_cause)+'</td></tr>';
      }
      html += '</tbody></table>';
    }

    html += '</div></div>';
    return html;
  }

  // ---- Copy to ticket helper ----
  function buildFullReport(allResults) {
    const lines = ['=== ClearSignal Domain Health Check ===','Date: '+new Date().toISOString().replace('T',' ').substring(0,19)];
    if (currentEntityName) lines.push('Client: '+currentEntityName);
    lines.push('');
    for (const [domain, data] of Object.entries(allResults)) {
      const checks = data.checks||[];
      const ok=checks.filter(c=>c.status==='ok').length;
      const warn=checks.filter(c=>c.status==='warn').length;
      const fail=checks.filter(c=>c.status==='fail').length;
      lines.push('--- '+domain+' --- ('+ok+' OK, '+warn+' Warn, '+fail+' Fail)');
      for (const c of checks) {
        lines.push('  ['+c.status.toUpperCase()+'] '+c.name+': '+c.summary);
        if (c.likely_root_cause) lines.push('    Cause: '+c.likely_root_cause);
      }
      lines.push('');
    }
    lines.push('=== End of Report ===');
    return lines.join('\n');
  }

  function buildClientReport(allResults) {
    const lines = ['Domain Health Report'+(currentEntityName?' for '+currentEntityName:''),'Date: '+new Date().toISOString().replace('T',' ').substring(0,19),''];
    for (const [domain, data] of Object.entries(allResults)) {
      const checks = data.checks||[];
      const issues = checks.filter(c=>c.status!=='ok');
      lines.push(domain+': '+(issues.length===0?'All checks passed':issues.length+' item(s) need attention'));
      if (issues.length) for (const c of issues) lines.push('  - '+c.name+': '+c.summary);
    }
    const allFixes = [];
    for (const data of Object.values(allResults)) for (const c of (data.checks||[])) if (c.recommended_fix) allFixes.push(c.recommended_fix);
    if (allFixes.length) { lines.push('','Recommendations:'); [...new Set(allFixes)].forEach(f=>lines.push('  - '+f)); }
    else lines.push('','No issues found across all domains.');
    lines.push('','Report generated by ClearSignal Diagnostics');
    return lines.join('\n');
  }

  function copyToTicket(summary) {
    const tid = prompt('Enter ticket ID:');
    if (!tid || parseInt(tid)<=0) return;
    const data = new FormData();
    data.append('tickets_id', tid);
    data.append('summary', summary);
    ajaxPost(PLUGIN_ROOT+'/ajax/addtoticket.php', data).then(()=>alert('Added to ticket #'+tid+'.')).catch(err=>alert(err.message));
  }

  // ---- Entity mode: Run all ----
  document.getElementById('hc-btn-run-entity').addEventListener('click', async function() {
    if (!entityDomains.length) return;
    const selector = document.getElementById('hc-dkim-selector').value.trim();
    const loadingEl = document.getElementById('hc-entity-loading');
    const loadingText = document.getElementById('hc-entity-loading-text');
    const errorEl = document.getElementById('hc-entity-error');
    const resultsSection = document.getElementById('hc-entity-results-section');

    errorEl.style.display='none';
    resultsSection.innerHTML='';
    resultsSection.style.display='none';
    loadingEl.style.display='block';
    this.disabled = true;

    const allResults = {};
    let hasError = false;

    for (let i = 0; i < entityDomains.length; i++) {
      const dom = entityDomains[i].domain;
      loadingText.textContent = 'Checking '+dom+' ('+(i+1)+'/'+entityDomains.length+')...';

      try {
        const data = new FormData();
        data.append('domain', dom);
        data.append('entities_id', currentEntityId);
        data.append('store_result', '1');
        data.append('dkim_selector', selector);
        const resp = await ajaxPost(PLUGIN_ROOT+'/ajax/health_check.php', data);
        allResults[dom] = resp.data;
        resultsSection.innerHTML += renderDomainResult(dom, resp.data);
        resultsSection.style.display='block';
      } catch (err) {
        resultsSection.innerHTML += '<div class="alert alert-danger">'+esc(dom)+': '+esc(err.message)+'</div>';
        resultsSection.style.display='block';
      }
    }

    loadingEl.style.display='none';
    this.disabled = false;

    // Add copy buttons
    if (Object.keys(allResults).length) {
      resultsSection.innerHTML += '<div class="card mt-3"><div class="card-header"><h5 class="card-title mb-0"><i class="ti ti-clipboard-copy me-1"></i>Copy to Ticket</h5></div>'
        +'<div class="card-body d-flex gap-2">'
        +'<button class="btn btn-outline-primary" onclick="window._hcCopyNote()"><i class="ti ti-lock me-1"></i>Add as Private Note</button>'
        +'<button class="btn btn-outline-secondary" onclick="window._hcCopyClient()"><i class="ti ti-send me-1"></i>Add as Client Summary</button>'
        +'</div></div>';
      window._hcCopyNote = ()=>copyToTicket(buildFullReport(allResults));
      window._hcCopyClient = ()=>copyToTicket(buildClientReport(allResults));
    }

    loadHistory(); // Refresh history
  });

  // ---- Quick mode ----
  document.getElementById('hc-btn-run-quick').addEventListener('click', async function() {
    const domain = document.getElementById('hc-quick-domain').value.trim();
    if (!domain) { document.getElementById('hc-quick-error').textContent='Enter a domain.'; document.getElementById('hc-quick-error').style.display='block'; return; }
    const selector = document.getElementById('hc-quick-selector').value.trim();
    const loadingEl = document.getElementById('hc-quick-loading');
    const errorEl = document.getElementById('hc-quick-error');
    const resultsSection = document.getElementById('hc-quick-results-section');

    errorEl.style.display='none';
    resultsSection.innerHTML='';
    resultsSection.style.display='none';
    loadingEl.style.display='block';
    this.disabled = true;

    try {
      const data = new FormData();
      data.append('domain', domain);
      data.append('entities_id', '0');
      data.append('store_result', '0');
      data.append('dkim_selector', selector);
      const resp = await ajaxPost(PLUGIN_ROOT+'/ajax/health_check.php', data);

      resultsSection.innerHTML = renderDomainResult(domain, resp.data);

      const allResults = {};
      allResults[domain] = resp.data;
      resultsSection.innerHTML += '<div class="card mt-3"><div class="card-header"><h5 class="card-title mb-0"><i class="ti ti-clipboard-copy me-1"></i>Copy to Ticket</h5></div>'
        +'<div class="card-body d-flex gap-2">'
        +'<button class="btn btn-outline-primary" onclick="window._hcQCopyNote()"><i class="ti ti-lock me-1"></i>Add as Private Note</button>'
        +'<button class="btn btn-outline-secondary" onclick="window._hcQCopyClient()"><i class="ti ti-send me-1"></i>Add as Client Summary</button>'
        +'</div></div>';
      window._hcQCopyNote = ()=>copyToTicket(buildFullReport(allResults));
      window._hcQCopyClient = ()=>copyToTicket(buildClientReport(allResults));

      resultsSection.style.display='block';
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.style.display='block';
    }

    loadingEl.style.display='none';
    this.disabled = false;
  });

})();
</script>

<?php Html::footer(); ?>
