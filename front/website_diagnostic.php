<?php
include('../../../inc/includes.php');

Session::checkLoginUser();

Html::header(__('Website / SSL Diagnostic'), $_SERVER['PHP_SELF'], 'tools', 'pluginclearsignaldiagmenu', 'website');

$config = PluginClearsignaldiagConfig::getConfig();
$pluginRoot = Plugin::getWebDir('clearsignaldiag');
?>

<ul class="nav nav-pills mb-3">
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-world-search me-1"></i>DNS Diagnostic</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/email_diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-mail-check me-1"></i>Email Diagnostic</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/header_analyser.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-mail-code me-1"></i>Email Analyser</a></li>
  <li class="nav-item"><a class="nav-link active" href="<?php echo htmlspecialchars($pluginRoot . '/front/website_diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-lock-check me-1"></i>Website / SSL</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/port_scanner.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-plug me-1"></i>Port Scanner</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/health_check.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-heart-rate-monitor me-1"></i>Health Check</a></li>
</ul>

<div class="card mb-3" id="csd-panel">
  <div class="card-header d-flex justify-content-between align-items-center">
    <h3 class="card-title mb-0"><i class="ti ti-lock-check me-1"></i>ClearSignal Website / SSL Diagnostic</h3>
    <span class="badge bg-secondary" id="csd-badge" style="display:none;"></span>
  </div>
  <div class="card-body">
    <form id="csd-form" autocomplete="off">
      <input type="hidden" name="_glpi_csrf_token" value="<?php echo htmlspecialchars(Session::getNewCSRFToken(), ENT_QUOTES, 'UTF-8'); ?>">
      <div class="row mb-3">
        <div class="col-md-9">
          <label for="csd-target" class="form-label fw-bold">Website / Host</label>
          <input type="text" id="csd-target" name="target" class="form-control form-control-lg"
                 placeholder="e.g. www.example.com or https://example.com" required>
        </div>
        <div class="col-md-3 d-flex align-items-end">
          <button type="button" class="btn btn-primary btn-lg w-100" id="csd-btn-run">
            <i class="ti ti-player-play me-1"></i>Run
          </button>
        </div>
      </div>
    </form>
    <div id="csd-loading" style="display:none;" class="mb-3">
      <div class="d-flex align-items-center text-primary">
        <div class="spinner-border spinner-border-sm me-2" role="status"></div>
        <span>Running website &amp; SSL diagnostics&hellip;</span>
      </div>
      <div class="progress mt-2" style="height:3px;"><div class="progress-bar progress-bar-striped progress-bar-animated" style="width:100%"></div></div>
    </div>
    <div id="csd-error" class="alert alert-danger mb-3" style="display:none;" role="alert"></div>
  </div>
</div>

<div id="csd-results" style="display:none;">
  <div class="card mb-3"><div class="card-body py-3"><div class="row text-center" id="csd-overview-pills"></div></div></div>
  <div class="card">
    <div class="card-header p-0">
      <ul class="nav nav-tabs card-header-tabs" role="tablist">
        <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#tab-http" role="tab">HTTP Response</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-tls" role="tab">TLS Certificate</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-headers" role="tab">Security Headers</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-cloudflare" role="tab">Cloudflare</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-caa" role="tab">CAA &amp; HTTP/2</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-raw" role="tab">Raw JSON</a></li>
      </ul>
    </div>
    <div class="card-body">
      <div class="tab-content">
        <div class="tab-pane fade show active" id="tab-http" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-tls" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-headers" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-cloudflare" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-caa" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-raw" role="tabpanel"><pre id="csd-raw-json" style="white-space:pre-wrap; max-height:600px; overflow:auto; font-size:0.8rem;"></pre></div>
      </div>
    </div>
  </div>

  <div class="card mt-3">
    <div class="card-header"><h5 class="card-title mb-0"><i class="ti ti-clipboard-copy me-1"></i>Copy to Ticket</h5></div>
    <div class="card-body">
      <div class="row">
        <div class="col-md-4">
          <label for="csd-ticket-id" class="form-label fw-bold">Ticket ID</label>
          <input type="number" id="csd-ticket-id" class="form-control" placeholder="e.g. 2217" min="1">
        </div>
        <div class="col-md-8 d-flex align-items-end gap-2">
          <button type="button" class="btn btn-outline-primary" id="csd-btn-copy-note" disabled><i class="ti ti-lock me-1"></i>Add as Private Note</button>
          <button type="button" class="btn btn-outline-secondary" id="csd-btn-copy-client" disabled><i class="ti ti-send me-1"></i>Add as Client-Friendly Summary</button>
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

  const form = document.getElementById('csd-form');
  const btnRun = document.getElementById('csd-btn-run');
  const loading = document.getElementById('csd-loading');
  const errDiv = document.getElementById('csd-error');
  const resultsEl = document.getElementById('csd-results');
  const badge = document.getElementById('csd-badge');
  const btnNote = document.getElementById('csd-btn-copy-note');
  const btnClient = document.getElementById('csd-btn-copy-client');
  const ticketInput = document.getElementById('csd-ticket-id');
  const copyToast = document.getElementById('csd-copy-toast');

  function getCsrfToken() { const m=document.querySelector('meta[property="glpi:csrf_token"]'); return m?m.getAttribute('content'):(document.querySelector('input[name="_glpi_csrf_token"]')?.value||''); }
  function esc(s) { const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }
  function showErr(m) { errDiv.textContent=m; errDiv.style.display='block'; }
  function hideErr() { errDiv.style.display='none'; }
  function statusDot(st) { const c=st==='ok'?'text-success':st==='warn'?'text-warning':'text-danger'; return '<i class="ti ti-circle-filled '+c+' me-1" style="font-size:0.7rem;"></i>'; }
  function find(name) { return lastData?(lastData.checks||[]).find(c=>c.name===name):null; }
  function showToast(msg) { copyToast.textContent=msg; copyToast.style.display='block'; setTimeout(()=>{copyToast.style.display='none';},4000); }

  // ---- Overview ----
  function renderOverview() {
    const pills = document.getElementById('csd-overview-pills');
    const sections = {'HTTP':['HTTP Response'],'TLS':['TLS Certificate'],'Headers':['Security Headers'],'HTTP/2':['HTTP/2 Support'],'Cloudflare':['Cloudflare SSL Mode'],'CAA':['CAA Records']};
    let html = '';
    for (const [label,names] of Object.entries(sections)) {
      const m = (lastData.checks||[]).filter(c=>names.includes(c.name));
      if (!m.length) continue;
      const w = m.reduce((w,c)=>c.status==='fail'?'fail':(c.status==='warn'&&w!=='fail'?'warn':w),'ok');
      const cls = w==='ok'?'success':w==='warn'?'warning':'danger';
      html += '<div class="col"><span class="badge bg-'+cls+(w==='warn'?' text-dark':'')+' p-2" style="font-size:0.85rem;">'+esc(label)+'</span></div>';
    }
    pills.innerHTML = html;
  }

  // ---- HTTP Response tab ----
  function renderHttpTab() {
    const tab = document.getElementById('tab-http');
    const c = find('HTTP Response');
    if (!c) { tab.innerHTML='<p class="text-muted">No data.</p>'; return; }
    let html = '<h5 class="mb-2">'+statusDot(c.status)+'HTTP Response</h5><p>'+esc(c.summary)+'</p>';
    const d = c.details || {};
    html += '<div class="row small mb-3">';
    html += '<div class="col-md-2"><strong>Status:</strong> '+esc(String(d.status_code||'—'))+' '+esc(d.reason||'')+'</div>';
    html += '<div class="col-md-2"><strong>TTFB:</strong> '+(d.response_time_ms||'—')+'ms</div>';
    html += '<div class="col-md-2"><strong>Server:</strong> <code>'+esc(d.server||'—')+'</code></div>';
    html += '<div class="col-md-3"><strong>Content-Type:</strong> <code>'+esc(d.content_type||'—')+'</code></div>';
    html += '<div class="col-md-3"><strong>Final URL:</strong> <code>'+esc(d.final_url||'—')+'</code></div>';
    html += '</div>';
    if (d.redirect_chain && d.redirect_chain.length) {
      html += '<h6>Redirect Chain</h6><table class="table table-sm table-striped mb-3"><thead><tr><th>#</th><th>URL</th><th>Status</th><th>Location</th></tr></thead><tbody>';
      d.redirect_chain.forEach((r,i)=>{
        html += '<tr><td>'+(i+1)+'</td><td><code>'+esc(r.url)+'</code></td><td>'+r.status+'</td><td><code>'+esc(r.location||'')+'</code></td></tr>';
      });
      html += '</tbody></table>';
    }
    if (d.http_to_https_redirect) {
      const r = d.http_to_https_redirect;
      const icon = r.redirects_to_https?'<span class="text-success">&#10003; Yes</span>':'<span class="text-danger">&#10007; No</span>';
      html += '<div class="alert alert-light border"><strong>HTTP → HTTPS redirect:</strong> '+icon;
      if (r.location) html += ' → <code>'+esc(r.location)+'</code>';
      html += '</div>';
    }
    if (d.cloudflare && d.cloudflare.is_cloudflare) {
      html += '<div class="small text-muted">Cloudflare: CF-RAY <code>'+esc(d.cloudflare.cf_ray)+'</code>, Cache: '+esc(d.cloudflare.cf_cache_status||'—')+'</div>';
    }
    tab.innerHTML = html;
  }

  // ---- TLS Certificate tab ----
  function renderTlsTab() {
    const tab = document.getElementById('tab-tls');
    const c = find('TLS Certificate');
    if (!c) { tab.innerHTML='<p class="text-muted">No data.</p>'; return; }
    let html = '<h5 class="mb-2">'+statusDot(c.status)+'TLS Certificate</h5><p>'+esc(c.summary)+'</p>';
    const d = c.details || {};
    html += '<table class="table table-sm mb-3"><tbody>';
    html += '<tr><td class="fw-bold" style="width:180px;">Subject CN</td><td><code>'+esc(d.subject_cn||'—')+'</code></td></tr>';
    html += '<tr><td class="fw-bold">Organisation</td><td>'+esc(d.subject_org||'—')+'</td></tr>';
    html += '<tr><td class="fw-bold">Issuer</td><td>'+esc(d.issuer_org||d.issuer_cn||'—')+'</td></tr>';
    html += '<tr><td class="fw-bold">Type</td><td>'+esc(d.cert_type||'—')+'</td></tr>';
    html += '<tr><td class="fw-bold">Serial</td><td><code style="font-size:0.75rem;">'+esc(d.serial||'—')+'</code></td></tr>';
    html += '<tr><td class="fw-bold">Issued</td><td>'+esc(d.issued||'—')+'</td></tr>';
    const daysClass = d.days_remaining!=null&&d.days_remaining<30?'text-danger fw-bold':'';
    html += '<tr><td class="fw-bold">Expires</td><td class="'+daysClass+'">'+esc(d.expires||'—')+' ('+(d.days_remaining!=null?d.days_remaining+' days':'—')+')</td></tr>';
    html += '<tr><td class="fw-bold">TLS Version</td><td><code>'+esc(d.tls_version||'—')+'</code></td></tr>';
    if (d.cipher) html += '<tr><td class="fw-bold">Cipher</td><td><code>'+esc(Array.isArray(d.cipher)?d.cipher.join(', '):String(d.cipher))+'</code></td></tr>';
    const matchIcon = d.hostname_match?'<span class="text-success">&#10003; Match</span>':'<span class="text-danger">&#10007; Mismatch</span>';
    html += '<tr><td class="fw-bold">Hostname Match</td><td>'+matchIcon+'</td></tr>';
    html += '</tbody></table>';
    if (d.san && d.san.length) {
      html += '<h6>Subject Alternative Names ('+d.san_count+')</h6>';
      html += '<div class="bg-light p-2 rounded small" style="max-height:200px; overflow:auto;">';
      html += d.san.map(s=>'<code>'+esc(s)+'</code>').join(', ');
      html += '</div>';
    }
    if (c.likely_root_cause) html += '<div class="alert alert-danger mt-2">'+esc(c.likely_root_cause)+'</div>';
    if (c.recommended_fix) html += '<div class="alert alert-info mt-1">'+esc(c.recommended_fix)+'</div>';
    tab.innerHTML = html;
  }

  // ---- Security Headers tab ----
  function renderHeadersTab() {
    const tab = document.getElementById('tab-headers');
    const c = find('Security Headers');
    if (!c) { tab.innerHTML='<p class="text-muted">No data.</p>'; return; }
    let html = '<h5 class="mb-2">'+statusDot(c.status)+'Security Headers — '+esc(c.summary)+'</h5>';
    const d = c.details || {};
    if (d.server) html += '<div class="small text-muted mb-2">Server: <code>'+esc(d.server)+'</code>'+(d.x_powered_by?' | X-Powered-By: <code>'+esc(d.x_powered_by)+'</code>':'')+'</div>';
    if (d.headers) {
      html += '<table class="table table-sm table-striped"><thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Description</th></tr></thead><tbody>';
      for (const [name, h] of Object.entries(d.headers)) {
        const icon = h.present?'<span class="text-success">&#10003;</span>':'<span class="text-danger">&#10007;</span>';
        const val = h.present&&h.value?'<code style="word-break:break-all; font-size:0.75rem;">'+esc(h.value)+'</code>':'<span class="text-muted small">'+esc(h.recommendation||'Not set')+'</span>';
        html += '<tr><td class="fw-bold">'+esc(name)+'</td><td>'+icon+'</td><td>'+val+'</td><td class="small text-muted">'+esc(h.description||'')+'</td></tr>';
      }
      html += '</tbody></table>';
    }
    tab.innerHTML = html;
  }

  // ---- Cloudflare tab ----
  function renderCloudflareTab() {
    const tab = document.getElementById('tab-cloudflare');
    const c = find('Cloudflare SSL Mode');
    if (!c) { tab.innerHTML='<p class="text-muted">No data.</p>'; return; }
    let html = '<h5 class="mb-2">'+statusDot(c.status)+'Cloudflare SSL Mode</h5><p>'+esc(c.summary)+'</p>';
    const d = c.details || {};
    html += '<table class="table table-sm mb-3"><tbody>';
    html += '<tr><td class="fw-bold" style="width:200px;">Proxied through CF</td><td>'+(d.cloudflare_proxied?'<span class="text-success">&#10003; Yes</span>':'<span class="text-muted">No</span>')+'</td></tr>';
    if (d.https_works!=null) html += '<tr><td class="fw-bold">HTTPS works</td><td>'+(d.https_works?'<span class="text-success">&#10003;</span>':'<span class="text-danger">&#10007;</span>')+'</td></tr>';
    if (d.http_redirects_to_https!=null) html += '<tr><td class="fw-bold">HTTP → HTTPS redirect</td><td>'+(d.http_redirects_to_https?'<span class="text-success">&#10003;</span>':'<span class="text-danger">&#10007;</span>')+'</td></tr>';
    if (d.cf_ray) html += '<tr><td class="fw-bold">CF-RAY</td><td><code>'+esc(d.cf_ray)+'</code></td></tr>';
    if (d.inferred_mode) html += '<tr><td class="fw-bold">Inferred Mode</td><td><strong>'+esc(d.inferred_mode)+'</strong></td></tr>';
    html += '</tbody></table>';
    if (c.likely_root_cause) html += '<div class="alert alert-warning">'+esc(c.likely_root_cause)+'</div>';
    if (c.recommended_fix) html += '<div class="alert alert-info">'+esc(c.recommended_fix)+'</div>';
    tab.innerHTML = html;
  }

  // ---- CAA & HTTP/2 tab ----
  function renderCaaTab() {
    const tab = document.getElementById('tab-caa');
    let html = '';

    const caa = find('CAA Records');
    if (caa) {
      html += '<h5 class="mb-2">'+statusDot(caa.status)+'CAA Records</h5><p>'+esc(caa.summary)+'</p>';
      const d = caa.details || {};
      if (d.note) html += '<div class="small text-muted mb-1">'+esc(d.note)+'</div>';
      if (d.records && d.records.length) {
        html += '<table class="table table-sm table-striped mb-3"><thead><tr><th>Flags</th><th>Tag</th><th>Value</th></tr></thead><tbody>';
        for (const r of d.records) html += '<tr><td>'+esc(r.flags)+'</td><td><code>'+esc(r.tag)+'</code></td><td><code>'+esc(r.value)+'</code></td></tr>';
        html += '</tbody></table>';
      }
      if (caa.likely_root_cause) html += '<div class="text-warning small">'+esc(caa.likely_root_cause)+'</div>';
    }

    const h2 = find('HTTP/2 Support');
    if (h2) {
      html += '<h5 class="mb-2 mt-3">'+statusDot(h2.status)+'HTTP/2 Support</h5><p>'+esc(h2.summary)+'</p>';
      if (h2.details) {
        html += '<div class="small"><strong>ALPN negotiated:</strong> <code>'+esc(h2.details.alpn_negotiated||'none')+'</code></div>';
      }
    }

    tab.innerHTML = html || '<p class="text-muted">No data.</p>';
  }

  // ---- Copy to ticket ----
  function buildEngineerSummary() {
    if (!lastData) return '';
    const lines = ['=== ClearSignal Website/SSL Diagnostic ===','Date: '+new Date().toISOString().replace('T',' ').substring(0,19),'Target: '+(lastData.target?.input||''),''];
    for (const c of (lastData.checks||[])) {
      lines.push('['+c.status.toUpperCase()+'] '+c.name+': '+c.summary);
      if (c.likely_root_cause) lines.push('  Cause: '+c.likely_root_cause);
      if (c.recommended_fix) lines.push('  Fix: '+c.recommended_fix);
    }
    lines.push('','=== End of Report ===');
    return lines.join('\n');
  }

  function buildClientSummary() {
    if (!lastData) return '';
    const t = lastData.target?.input||'';
    const checks = lastData.checks||[];
    const lines = ['Website & SSL Report for '+t, 'Date: '+new Date().toISOString().replace('T',' ').substring(0,19),''];
    const tls = find('TLS Certificate');
    if (tls) {
      const d = tls.details||{};
      lines.push('SSL Certificate: '+(tls.status==='ok'?'Valid':'Needs attention'));
      if (d.expires) lines.push('  Expires: '+d.expires+(d.days_remaining!=null?' ('+d.days_remaining+' days)':''));
      if (d.issuer_org) lines.push('  Issued by: '+d.issuer_org);
    }
    const http = find('HTTP Response');
    if (http) lines.push('Website: '+(http.status==='ok'?'Accessible (HTTP '+((http.details||{}).status_code||'')+')':(http.summary)));
    const hdrs = find('Security Headers');
    if (hdrs) lines.push('Security Headers: '+hdrs.summary);
    lines.push('');
    const issues = checks.filter(c=>c.recommended_fix);
    if (issues.length) {
      lines.push('Recommendations:');
      for (const c of issues) lines.push('  - '+c.recommended_fix);
    } else {
      lines.push('No issues found. Website and SSL configuration looks healthy.');
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

  // ---- Run ----
  btnRun.addEventListener('click', function() {
    const target = document.getElementById('csd-target').value.trim();
    if (!target) { showErr('Enter a website or hostname.'); return; }
    hideErr();
    const checks = ['http_response','tls_certificate','security_headers','http2_support','caa_records','cf_ssl_mode'];
    const data = new FormData(form);
    checks.forEach(c=>data.append('checks[]',c));

    resultsEl.style.display='none'; loading.style.display='block'; btnRun.disabled=true;
    badge.style.display='inline-block'; badge.textContent='Running...'; badge.className='badge bg-primary';

    fetch(PLUGIN_ROOT+'/ajax/run_standalone.php',{method:'POST',body:data,credentials:'same-origin',headers:{'X-Requested-With':'XMLHttpRequest','X-Glpi-Csrf-Token':getCsrfToken()}})
    .then(r=>{if(!r.headers.get('content-type')?.includes('json'))return r.text().then(()=>{throw new Error('Non-JSON (HTTP '+r.status+')');});return r.json();})
    .then(resp=>{
      loading.style.display='none'; btnRun.disabled=false;
      if (!resp.success) throw new Error(resp.message);
      lastData = resp.data;
      renderOverview(); renderHttpTab(); renderTlsTab(); renderHeadersTab(); renderCloudflareTab(); renderCaaTab();
      document.getElementById('csd-raw-json').textContent = JSON.stringify(resp.data,null,2);
      resultsEl.style.display='block'; btnNote.disabled=false; btnClient.disabled=false;
      const fc=(resp.data.checks||[]).filter(c=>c.status==='fail').length;
      const wc=(resp.data.checks||[]).filter(c=>c.status==='warn').length;
      badge.textContent=fc?fc+' fail, '+wc+' warn':wc?wc+' warning(s)':'All OK';
      badge.className=fc?'badge bg-danger':wc?'badge bg-warning text-dark':'badge bg-success';
    })
    .catch(err=>{loading.style.display='none';btnRun.disabled=false;showErr(String(err.message||err));badge.textContent='Error';badge.className='badge bg-danger';});
  });
})();
</script>

<?php Html::footer(); ?>
