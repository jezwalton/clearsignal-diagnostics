<?php
include('../../../inc/includes.php');

Session::checkLoginUser();

Html::header(__('Email Analyser'), $_SERVER['PHP_SELF'], 'tools', 'pluginclearsignaldiagmenu', 'headers');

$config = PluginClearsignaldiagConfig::getConfig();
$pluginRoot = Plugin::getWebDir('clearsignaldiag');
?>

<ul class="nav nav-pills mb-3">
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-world-search me-1"></i>DNS Diagnostic</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/email_diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-mail-check me-1"></i>Email Diagnostic</a></li>
  <li class="nav-item"><a class="nav-link active" href="<?php echo htmlspecialchars($pluginRoot . '/front/header_analyser.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-mail-code me-1"></i>Email Analyser</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/website_diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-lock-check me-1"></i>Website / SSL</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/port_scanner.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-plug me-1"></i>Port Scanner</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/health_check.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-heart-rate-monitor me-1"></i>Health Check</a></li>
</ul>

<div class="card mb-3">
  <div class="card-header d-flex justify-content-between align-items-center">
    <h3 class="card-title mb-0"><i class="ti ti-mail-code me-1"></i>Email Analyser</h3>
    <span class="badge bg-secondary" id="csd-badge" style="display:none;"></span>
  </div>
  <div class="card-body">
    <form id="csd-form" autocomplete="off">
      <input type="hidden" name="_glpi_csrf_token" value="<?php echo htmlspecialchars(Session::getNewCSRFToken(), ENT_QUOTES, 'UTF-8'); ?>">
      <div class="mb-3">
        <label for="csd-headers" class="form-label fw-bold">Paste email headers below</label>
        <textarea id="csd-headers" name="raw_headers" class="form-control font-monospace" rows="10" placeholder="Paste the full internet headers from the email here...&#10;&#10;In Outlook: Open message → File → Properties → Internet Headers&#10;In Gmail: Open message → ⋮ → Show original" style="font-size:0.8rem;"></textarea>
      </div>
      <button type="button" class="btn btn-primary" id="csd-btn-run"><i class="ti ti-player-play me-1"></i>Analyse Headers</button>
    </form>
    <div id="csd-loading" style="display:none;" class="mt-3">
      <div class="d-flex align-items-center text-primary">
        <div class="spinner-border spinner-border-sm me-2" role="status"></div>
        <span>Analysing headers&hellip;</span>
      </div>
    </div>
    <div id="csd-error" class="alert alert-danger mt-3" style="display:none;" role="alert"></div>
  </div>
</div>

<div id="csd-results" style="display:none;">
  <!-- Summary banner -->
  <div class="card mb-3" id="csd-summary-card">
    <div class="card-body py-3" id="csd-summary-body"></div>
  </div>

  <div class="card">
    <div class="card-header p-0">
      <ul class="nav nav-tabs card-header-tabs" role="tablist">
        <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#tab-route" role="tab">Message Route</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-auth" role="tab">Authentication</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-envelope" role="tab">Envelope</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-security" role="tab">Spam &amp; Security</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-raw" role="tab">Raw Analysis</a></li>
      </ul>
    </div>
    <div class="card-body">
      <div class="tab-content">
        <div class="tab-pane fade show active" id="tab-route" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-auth" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-envelope" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-security" role="tabpanel"></div>
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
  let lastAnalysis = null;

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
  function esc(s) { const d=document.createElement('div'); d.textContent=String(s||''); return d.innerHTML; }
  function showErr(m) { errDiv.textContent=m; errDiv.style.display='block'; }
  function hideErr() { errDiv.style.display='none'; }
  function showToast(msg) { copyToast.textContent=msg; copyToast.style.display='block'; setTimeout(()=>{copyToast.style.display='none';},4000); }

  function authBadge(result) {
    if (!result) return '<span class="badge bg-secondary">N/A</span>';
    const r = result.toLowerCase();
    if (r === 'pass') return '<span class="badge bg-success">PASS</span>';
    if (r === 'fail') return '<span class="badge bg-danger">FAIL</span>';
    if (r === 'softfail') return '<span class="badge bg-warning text-dark">SOFTFAIL</span>';
    if (r === 'none') return '<span class="badge bg-secondary">NONE</span>';
    if (r === 'temperror' || r === 'permerror') return '<span class="badge bg-danger">'+esc(r.toUpperCase())+'</span>';
    return '<span class="badge bg-info text-dark">'+esc(r.toUpperCase())+'</span>';
  }

  function delayBar(seconds) {
    if (!seconds || seconds < 1) return '<span class="text-success">&#60;1s</span>';
    const cls = seconds > 60 ? 'bg-danger' : seconds > 10 ? 'bg-warning' : 'bg-success';
    const width = Math.min(100, Math.max(5, (seconds / 120) * 100));
    return '<div class="d-flex align-items-center gap-2"><div class="progress flex-grow-1" style="height:8px; max-width:200px;"><div class="progress-bar '+cls+'" style="width:'+width+'%"></div></div><span class="small fw-bold">' + Math.round(seconds) + 's</span></div>';
  }

  // ---- Summary banner ----
  function renderSummary(d) {
    const body = document.getElementById('csd-summary-body');
    const auth = d.auth_summary || {};
    let html = '<div class="row">';
    html += '<div class="col-md-2 text-center"><div class="small text-muted">SPF</div>'+authBadge(auth.spf)+'</div>';
    html += '<div class="col-md-2 text-center"><div class="small text-muted">DKIM</div>'+authBadge(auth.dkim)+'</div>';
    html += '<div class="col-md-2 text-center"><div class="small text-muted">DMARC</div>'+authBadge(auth.dmarc)+'</div>';
    html += '<div class="col-md-2 text-center"><div class="small text-muted">Hops</div><span class="fw-bold">'+d.hop_count+'</span></div>';
    html += '<div class="col-md-2 text-center"><div class="small text-muted">Transit Time</div><span class="fw-bold">'+(d.total_delay_seconds > 0 ? Math.round(d.total_delay_seconds)+'s' : '&#60;1s')+'</span></div>';
    if (d.slowest_hop && d.slowest_hop.delay_seconds > 5) {
      html += '<div class="col-md-2 text-center"><div class="small text-muted">Slowest Hop</div><span class="text-warning fw-bold">'+Math.round(d.slowest_hop.delay_seconds)+'s</span></div>';
    }
    html += '</div>';

    if (d.detected_services && d.detected_services.length) {
      html += '<div class="alert alert-info mt-2 mb-0 py-1 px-2 small"><i class="ti ti-info-circle me-1"></i><strong>Relayed via:</strong> '+d.detected_services.map(s=>'<span class="badge bg-info text-dark me-1">'+esc(s.service)+'</span>').join('')+'</div>';
    }
    if (d.info_notes && d.info_notes.length) {
      html += '<div class="alert alert-light border mt-2 mb-0 py-1 px-2 small">'+d.info_notes.map(n=>'<div>'+esc(n)+'</div>').join('')+'</div>';
    }
    if (d.issues && d.issues.length) {
      html += '<div class="alert alert-danger mt-2 mb-0 py-1 px-2 small"><strong>Issues:</strong> '+d.issues.map(i=>esc(i)).join(', ')+'</div>';
    }
    if (d.warnings && d.warnings.length) {
      html += '<div class="alert alert-warning mt-2 mb-0 py-1 px-2 small"><strong>Warnings:</strong> '+d.warnings.map(w=>esc(w)).join(', ')+'</div>';
    }

    body.innerHTML = html;
  }

  // ---- Route tab ----
  function renderRouteTab(d) {
    const tab = document.getElementById('tab-route');
    if (!d.hops || !d.hops.length) { tab.innerHTML='<p class="text-muted">No routing hops found.</p>'; return; }

    let html = '<h5 class="mb-2">Message Route — '+d.hop_count+' hop(s)</h5>';
    html += '<p class="small text-muted">Hops are shown in delivery order (first received → final destination).</p>';
    html += '<table class="table table-sm table-striped"><thead><tr><th style="width:40px;">#</th><th>From</th><th>By (received at)</th><th>Protocol</th><th>Time (UTC)</th><th>Delay</th></tr></thead><tbody>';

    // Reverse so oldest is first (delivery order)
    const hops = [...d.hops].reverse();
    hops.forEach((h, i) => {
      const from = h.from_host ? '<code>'+esc(h.from_host)+'</code>' : '<span class="text-muted">—</span>';
      const by = h.by_host ? '<code>'+esc(h.by_host)+'</code>' : '<span class="text-muted">—</span>';
      const proto = h.protocol ? '<code>'+esc(h.protocol)+'</code>' : '—';
      const ts = h.timestamp_utc || '—';
      const ips = h.ips ? '<div class="small text-muted">'+h.ips.map(ip=>'<code>'+esc(ip)+'</code>').join(', ')+'</div>' : '';
      // Delay — hops array was reversed, so find matching original index
      const origIdx = d.hops.length - 1 - i;
      const delay = d.hops[origIdx]?.delay_seconds;
      html += '<tr><td class="text-center fw-bold">'+(i+1)+'</td><td>'+from+ips+'</td><td>'+by+'</td><td>'+proto+'</td><td class="small">'+esc(ts)+'</td><td>'+delayBar(delay)+'</td></tr>';
    });
    html += '</tbody></table>';

    if (d.total_delay_seconds > 0) {
      html += '<div class="text-muted small">Total transit time: <strong>'+Math.round(d.total_delay_seconds)+'s</strong>';
      if (d.slowest_hop) html += ' — slowest hop at <code>'+esc(d.slowest_hop.host)+'</code> ('+Math.round(d.slowest_hop.delay_seconds)+'s)';
      html += '</div>';
    }

    tab.innerHTML = html;
  }

  // ---- Auth tab ----
  function renderAuthTab(d) {
    const tab = document.getElementById('tab-auth');
    let html = '<h5 class="mb-2">Authentication Results</h5>';

    const auth = d.auth_summary || {};
    html += '<table class="table table-sm mb-3" style="max-width:500px;"><tbody>';
    html += '<tr><td class="fw-bold" style="width:120px;">SPF</td><td>'+authBadge(auth.spf)+'</td></tr>';
    html += '<tr><td class="fw-bold">DKIM</td><td>'+authBadge(auth.dkim)+'</td></tr>';
    html += '<tr><td class="fw-bold">DMARC</td><td>'+authBadge(auth.dmarc)+'</td></tr>';
    if (auth.compauth) html += '<tr><td class="fw-bold">CompAuth</td><td>'+authBadge(auth.compauth)+'</td></tr>';
    html += '</tbody></table>';

    if (d.received_spf) {
      html += '<h6>Received-SPF</h6>';
      html += '<div class="bg-light p-2 rounded mb-3"><code style="word-break:break-all; font-size:0.75rem;">'+esc(d.received_spf)+'</code></div>';
    }

    if (d.dkim_signature && Object.keys(d.dkim_signature).length) {
      html += '<h6>DKIM Signature</h6>';
      html += '<table class="table table-sm table-striped mb-3"><tbody>';
      const keyLabels = {d:'Domain',s:'Selector',a:'Algorithm',v:'Version',b:'Signature (truncated)'};
      for (const [k,v] of Object.entries(d.dkim_signature)) {
        const label = keyLabels[k] || k;
        const val = k === 'b' ? (v.substring(0,40)+'...') : v;
        html += '<tr><td class="fw-bold" style="width:150px;">'+esc(label)+' ('+esc(k)+')</td><td><code>'+esc(val)+'</code></td></tr>';
      }
      html += '</tbody></table>';
    }

    if (d.auth_results && d.auth_results.length) {
      html += '<h6>Raw Authentication-Results Headers</h6>';
      for (const ar of d.auth_results) {
        html += '<div class="bg-light p-2 rounded mb-1"><code style="word-break:break-all; font-size:0.7rem;">'+esc(ar.raw)+'</code></div>';
      }
    }

    tab.innerHTML = html;
  }

  // ---- Envelope tab ----
  function renderEnvelopeTab(d) {
    const tab = document.getElementById('tab-envelope');
    const e = d.envelope || {};
    let html = '<h5 class="mb-2">Message Envelope</h5>';
    html += '<table class="table table-sm"><tbody>';
    const fields = [['From',e.from],['To',e.to],['CC',e.cc],['Subject',e.subject],['Date',e.date_parsed||e.date],['Message-ID',e.message_id],['Return-Path',e.return_path],['Reply-To',e.reply_to]];
    for (const [label,val] of fields) {
      if (!val) continue;
      html += '<tr><td class="fw-bold" style="width:130px;">'+esc(label)+'</td><td><code style="word-break:break-all;">'+esc(val)+'</code></td></tr>';
    }
    html += '</tbody></table>';
    tab.innerHTML = html;
  }

  // ---- Spam/Security tab ----
  function renderSecurityTab(d) {
    const tab = document.getElementById('tab-security');
    const sh = d.spam_headers || {};
    if (!Object.keys(sh).length) { tab.innerHTML='<p class="text-muted">No spam or security headers found.</p>'; return; }

    let html = '<h5 class="mb-2">Spam &amp; Security Headers</h5>';
    html += '<table class="table table-sm table-striped"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>';
    for (const [k,v] of Object.entries(sh)) {
      html += '<tr><td class="fw-bold" style="min-width:250px;">'+esc(k)+'</td><td><code style="word-break:break-all; font-size:0.75rem;">'+esc(v)+'</code></td></tr>';
    }
    html += '</tbody></table>';
    tab.innerHTML = html;
  }

  // ---- Copy to ticket ----
  function buildEngineerSummary() {
    if (!lastAnalysis) return '';
    const d = lastAnalysis;
    const e = d.envelope || {};
    const auth = d.auth_summary || {};
    const lines = ['=== ClearSignal Email Header Analysis ===','Date: '+new Date().toISOString().replace('T',' ').substring(0,19),''];
    lines.push('Subject: '+(e.subject||'—'));
    lines.push('From: '+(e.from||'—'));
    lines.push('To: '+(e.to||'—'));
    lines.push('Date: '+(e.date_parsed||e.date||'—'));
    lines.push('Message-ID: '+(e.message_id||'—'));
    lines.push('');
    lines.push('Authentication:');
    lines.push('  SPF: '+(auth.spf||'N/A'));
    lines.push('  DKIM: '+(auth.dkim||'N/A'));
    lines.push('  DMARC: '+(auth.dmarc||'N/A'));
    lines.push('');
    lines.push('Routing: '+d.hop_count+' hops, '+Math.round(d.total_delay_seconds||0)+'s total transit');
    if (d.slowest_hop) lines.push('Slowest hop: '+d.slowest_hop.host+' ('+Math.round(d.slowest_hop.delay_seconds)+'s)');
    if (d.issues && d.issues.length) { lines.push(''); lines.push('Issues: '+d.issues.join(', ')); }
    if (d.warnings && d.warnings.length) { lines.push('Warnings: '+d.warnings.join(', ')); }
    lines.push('','=== End of Report ===');
    return lines.join('\n');
  }

  function buildClientSummary() {
    if (!lastAnalysis) return '';
    const d = lastAnalysis;
    const e = d.envelope || {};
    const auth = d.auth_summary || {};
    const lines = ['Email Header Analysis Report','Date: '+new Date().toISOString().replace('T',' ').substring(0,19),''];
    lines.push('Message: '+(e.subject||'(no subject)'));
    lines.push('From: '+(e.from||'—'));
    lines.push('Sent: '+(e.date_parsed||e.date||'—'));
    lines.push('');
    const authOk = ['pass'].includes(auth.spf) && ['pass'].includes(auth.dkim) && ['pass'].includes(auth.dmarc);
    if (authOk) {
      lines.push('Email Authentication: All checks passed (SPF, DKIM, DMARC)');
    } else {
      lines.push('Email Authentication:');
      if (auth.spf) lines.push('  - SPF (sender verification): '+auth.spf);
      if (auth.dkim) lines.push('  - DKIM (message signing): '+auth.dkim);
      if (auth.dmarc) lines.push('  - DMARC (policy): '+auth.dmarc);
    }
    lines.push('');
    lines.push('Delivery: '+d.hop_count+' server(s) handled this message'+(d.total_delay_seconds>60?', total transit time was '+Math.round(d.total_delay_seconds/60)+' minute(s)':'.'));
    if (d.issues && d.issues.length) { lines.push(''); lines.push('Issues found: '+d.issues.join(', ')); }
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
    const headers = document.getElementById('csd-headers').value.trim();
    if (!headers) { showErr('Paste email headers first.'); return; }
    if (headers.length < 50) { showErr('Headers look too short — paste the full internet headers.'); return; }
    hideErr();

    const data = new FormData(form);
    data.append('target', '');
    data.append('checks[]', 'email_header_analysis');

    resultsEl.style.display='none'; loading.style.display='block'; btnRun.disabled=true;
    badge.style.display='inline-block'; badge.textContent='Analysing...'; badge.className='badge bg-primary';

    fetch(PLUGIN_ROOT+'/ajax/run_standalone.php',{method:'POST',body:data,credentials:'same-origin',headers:{'X-Requested-With':'XMLHttpRequest','X-Glpi-Csrf-Token':getCsrfToken()}})
    .then(r=>{if(!r.headers.get('content-type')?.includes('json'))return r.text().then(()=>{throw new Error('Non-JSON (HTTP '+r.status+')');});return r.json();})
    .then(resp=>{
      loading.style.display='none'; btnRun.disabled=false;
      if (!resp.success) throw new Error(resp.message);

      const check = (resp.data.checks||[])[0];
      if (!check || !check.details) throw new Error('No analysis returned.');

      lastAnalysis = check.details;
      renderSummary(check.details);
      renderRouteTab(check.details);
      renderAuthTab(check.details);
      renderEnvelopeTab(check.details);
      renderSecurityTab(check.details);
      document.getElementById('csd-raw-json').textContent = JSON.stringify(check.details, null, 2);
      resultsEl.style.display='block'; btnNote.disabled=false; btnClient.disabled=false;

      const st = check.status;
      badge.textContent = st==='ok'?'All OK':st==='warn'?'Warnings':'Issues Found';
      badge.className = st==='ok'?'badge bg-success':st==='warn'?'badge bg-warning text-dark':'badge bg-danger';
    })
    .catch(err=>{loading.style.display='none';btnRun.disabled=false;showErr(String(err.message||err));badge.textContent='Error';badge.className='badge bg-danger';});
  });
})();
</script>

<?php Html::footer(); ?>
