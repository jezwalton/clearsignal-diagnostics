<?php
include('../../../inc/includes.php');

Session::checkLoginUser();

Html::header(__('Email Diagnostic'), $_SERVER['PHP_SELF'], 'tools', 'PluginClearsignaldiagMenu', 'email');

$config = PluginClearsignaldiagConfig::getConfig();
$pluginRoot = Plugin::getWebDir('clearsignaldiag');
?>

<div class="card mb-3" id="csd-panel">
  <div class="card-header d-flex justify-content-between align-items-center">
    <h3 class="card-title mb-0"><i class="ti ti-mail-check me-1"></i>ClearSignal Email Diagnostic</h3>
    <span class="badge bg-secondary" id="csd-badge" style="display:none;"></span>
  </div>
  <div class="card-body">
    <form id="csd-form" autocomplete="off">
      <input type="hidden" name="_glpi_csrf_token" value="<?php echo htmlspecialchars(Session::getNewCSRFToken(), ENT_QUOTES, 'UTF-8'); ?>">
      <div class="row mb-3">
        <div class="col-md-6">
          <label for="csd-target" class="form-label fw-bold">Domain</label>
          <input type="text" id="csd-target" name="target" class="form-control form-control-lg"
                 placeholder="e.g. example.com" required>
        </div>
        <div class="col-md-3">
          <label for="csd-selector" class="form-label fw-bold">DKIM selector</label>
          <input type="text" id="csd-selector" name="dkim_selector" class="form-control form-control-lg"
                 value="<?php echo htmlspecialchars((string)($config['default_selector'] ?? 'selector1'), ENT_QUOTES, 'UTF-8'); ?>">
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
        <span>Running email diagnostics&hellip; blacklist checks may take 15–30 seconds.</span>
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
        <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#tab-mx" role="tab">MX &amp; SMTP</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-auth" role="tab">Authentication</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-blacklist" role="tab">Blacklists</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-transport" role="tab">Transport Security</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-autoconfig" role="tab">Autodiscover</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-raw" role="tab">Raw JSON</a></li>
      </ul>
    </div>
    <div class="card-body">
      <div class="tab-content">
        <div class="tab-pane fade show active" id="tab-mx" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-auth" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-blacklist" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-transport" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-autoconfig" role="tabpanel"></div>
        <div class="tab-pane fade" id="tab-raw" role="tabpanel"><pre id="csd-raw-json" style="white-space:pre-wrap; max-height:600px; overflow:auto; font-size:0.8rem;"></pre></div>
      </div>
    </div>
  </div>

  <!-- Copy to ticket controls -->
  <div class="card mt-3">
    <div class="card-header"><h5 class="card-title mb-0"><i class="ti ti-clipboard-copy me-1"></i>Copy to Ticket</h5></div>
    <div class="card-body">
      <div class="row">
        <div class="col-md-4">
          <label for="csd-ticket-id" class="form-label fw-bold">Ticket ID</label>
          <input type="number" id="csd-ticket-id" class="form-control" placeholder="e.g. 2217" min="1">
        </div>
        <div class="col-md-8 d-flex align-items-end gap-2">
          <button type="button" class="btn btn-outline-primary" id="csd-btn-copy-note" disabled>
            <i class="ti ti-lock me-1"></i>Add as Private Note
          </button>
          <button type="button" class="btn btn-outline-secondary" id="csd-btn-copy-client" disabled>
            <i class="ti ti-send me-1"></i>Add as Client-Friendly Summary
          </button>
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

  function getCsrfToken() {
    const m = document.querySelector('meta[property="glpi:csrf_token"]');
    return m ? m.getAttribute('content') : (document.querySelector('input[name="_glpi_csrf_token"]')?.value || '');
  }
  function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function showErr(m) { errDiv.textContent = m; errDiv.style.display = 'block'; }
  function hideErr() { errDiv.style.display = 'none'; }
  function statusDot(st) {
    const c = st==='ok'?'text-success':st==='warn'?'text-warning':'text-danger';
    return '<i class="ti ti-circle-filled '+c+' me-1" style="font-size:0.7rem;"></i>';
  }
  function find(name) { return lastData ? (lastData.checks||[]).find(c=>c.name===name) : null; }

  function showToast(msg) {
    copyToast.textContent = msg;
    copyToast.style.display = 'block';
    setTimeout(()=>{ copyToast.style.display='none'; }, 4000);
  }

  // ---------- build engineer summary ----------
  function buildEngineerSummary() {
    if (!lastData) return '';
    const lines = [];
    lines.push('=== ClearSignal Email Diagnostic ===');
    lines.push('Date: ' + new Date().toISOString().replace('T',' ').substring(0,19));
    lines.push('Domain: ' + (lastData.target?.input || ''));
    lines.push('');
    for (const c of (lastData.checks||[])) {
      lines.push('[' + c.status.toUpperCase() + '] ' + c.name + ': ' + c.summary);
      if (c.likely_root_cause) lines.push('  Cause: ' + c.likely_root_cause);
      if (c.recommended_fix) lines.push('  Fix: ' + c.recommended_fix);
    }
    lines.push(''); lines.push('=== End of Report ===');
    return lines.join('\n');
  }

  // ---------- build client-friendly summary ----------
  function buildClientSummary() {
    if (!lastData) return '';
    const domain = lastData.target?.input || '';
    const lines = [];
    lines.push('Email Configuration Report for ' + domain);
    lines.push('Date: ' + new Date().toISOString().replace('T',' ').substring(0,19));
    lines.push('');

    const mx = find('MX Records');
    if (mx && mx.details && mx.details.mx) {
      lines.push('Mail Servers:');
      for (const m of mx.details.mx) lines.push('  - ' + m.exchange + ' (priority ' + m.priority + ')');
      lines.push('');
    }

    const smtp = find('SMTP Connectivity');
    if (smtp) lines.push('Mail Server Connectivity: ' + smtp.summary);

    const spf = find('SPF');
    if (spf) lines.push('SPF (Sender Policy): ' + (spf.status==='ok'?'Configured correctly':'Needs attention — '+spf.summary));

    const dkim = find('DKIM');
    if (dkim) lines.push('DKIM (Email Signing): ' + (dkim.status==='ok'?'Configured correctly':'Needs attention — '+dkim.summary));

    const dmarc = find('DMARC');
    if (dmarc) lines.push('DMARC (Email Policy): ' + (dmarc.status==='ok'?'Configured correctly':'Needs attention — '+dmarc.summary));

    const bl = find('Blacklist Check');
    if (bl) lines.push('Blacklist Status: ' + (bl.status==='ok'?'Clean — not listed on any checked blacklists':'ATTENTION — '+bl.summary));

    lines.push('');

    // Recommendations
    const issues = (lastData.checks||[]).filter(c=>c.likely_root_cause);
    if (issues.length) {
      lines.push('Recommendations:');
      for (const c of issues) lines.push('  - ' + c.recommended_fix);
    } else {
      lines.push('No issues found. Email configuration looks healthy.');
    }

    lines.push('');
    lines.push('Report generated by ClearSignal Diagnostics');
    return lines.join('\n');
  }

  // ---------- copy to ticket ----------
  function copyToTicket(summary) {
    const ticketId = parseInt(ticketInput.value, 10);
    if (!ticketId || ticketId <= 0) { showErr('Enter a valid ticket ID.'); return; }
    hideErr();

    const data = new FormData();
    data.append('tickets_id', ticketId);
    data.append('summary', summary);

    fetch(PLUGIN_ROOT + '/ajax/addtoticket.php', {
      method: 'POST', body: data, credentials: 'same-origin',
      headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': getCsrfToken() }
    })
    .then(r => { if (!r.headers.get('content-type')?.includes('json')) throw new Error('Non-JSON (HTTP '+r.status+')'); return r.json(); })
    .then(resp => { if (!resp.success) throw new Error(resp.message); showToast('Added to ticket #' + ticketId + ' as a private follow-up.'); })
    .catch(err => showErr(String(err.message||err)));
  }

  btnNote.addEventListener('click', ()=>copyToTicket(buildEngineerSummary()));
  btnClient.addEventListener('click', ()=>copyToTicket(buildClientSummary()));

  // ---------- Tab renderers ----------

  function renderOverview() {
    const pills = document.getElementById('csd-overview-pills');
    const sections = {
      'MX/SMTP': ['MX Records','SMTP Connectivity'],
      'SPF': ['SPF'], 'DKIM': ['DKIM'], 'DMARC': ['DMARC'],
      'Blacklists': ['Blacklist Check'],
      'MTA-STS': ['MTA-STS'], 'DANE': ['DANE/TLSA'], 'BIMI': ['BIMI'],
      'Autodiscover': ['Autodiscover'],
    };
    let html = '';
    for (const [label, names] of Object.entries(sections)) {
      const matching = (lastData.checks||[]).filter(c=>names.includes(c.name));
      if (!matching.length) continue;
      const worst = matching.reduce((w,c)=>c.status==='fail'?'fail':(c.status==='warn'&&w!=='fail'?'warn':w),'ok');
      const cls = worst==='ok'?'success':worst==='warn'?'warning':'danger';
      html += '<div class="col"><span class="badge bg-'+cls+(worst==='warn'?' text-dark':'')+' p-2" style="font-size:0.85rem;">'+esc(label)+'</span></div>';
    }
    pills.innerHTML = html;
  }

  function renderMxTab() {
    const tab = document.getElementById('tab-mx');
    let html = '';

    const mx = find('MX Records');
    if (mx && mx.details && mx.details.mx && mx.details.mx.length) {
      html += '<h5 class="mb-2">'+statusDot(mx.status)+'MX Records</h5>';
      html += '<table class="table table-sm table-striped mb-3"><thead><tr><th>Priority</th><th>Mail Server</th></tr></thead><tbody>';
      for (const m of mx.details.mx) html += '<tr><td>'+m.priority+'</td><td><code>'+esc(m.exchange)+'</code></td></tr>';
      html += '</tbody></table>';
    } else if (mx) {
      html += '<h5>'+statusDot(mx.status)+'MX Records</h5><p class="text-muted">'+esc(mx.summary)+'</p>';
    }

    const smtp = find('SMTP Connectivity');
    if (smtp && smtp.details && smtp.details.mx_hosts) {
      html += '<h5 class="mb-2 mt-3">'+statusDot(smtp.status)+'SMTP Connectivity</h5>';
      html += '<table class="table table-sm table-striped"><thead><tr><th>Host</th><th>Priority</th><th>Status</th><th>STARTTLS</th><th>TLS Version</th><th>Connect Time</th></tr></thead><tbody>';
      for (const h of smtp.details.mx_hosts) {
        const stIcon = h.status==='ok'?'<span class="text-success">&#10003;</span>':'<span class="text-danger">&#10007;</span>';
        const tls = h.starttls===true?'<span class="text-success">&#10003; '+esc(h.tls_version||'')+'</span>':(h.starttls===false?'<span class="text-danger">&#10007;</span>':'—');
        const tlsVer = h.tls_version ? esc(h.tls_version) : '';
        const ct = h.connect_time_ms ? h.connect_time_ms+'ms' : '—';
        html += '<tr><td><code>'+esc(h.host)+'</code></td><td>'+h.priority+'</td><td>'+stIcon+'</td><td>'+tls+'</td><td>'+tlsVer+'</td><td>'+ct+'</td></tr>';
        if (h.error) html += '<tr><td colspan="6" class="text-danger small">'+esc(h.error)+'</td></tr>';
      }
      html += '</tbody></table>';
    }

    tab.innerHTML = html || '<p class="text-muted">No MX/SMTP data.</p>';
  }

  function renderAuthTab() {
    const tab = document.getElementById('tab-auth');
    let html = '';

    for (const name of ['SPF','DKIM','DMARC','BIMI']) {
      const c = find(name);
      if (!c) continue;
      html += '<h5 class="mb-2 mt-3">'+statusDot(c.status)+name+'</h5>';
      html += '<p>'+esc(c.summary)+'</p>';

      if (name==='SPF' && c.details && c.details.spf) {
        html += '<div class="bg-light p-2 rounded mb-2"><code style="word-break:break-all;">'+esc(c.details.spf)+'</code></div>';
        if (c.details.dns_lookup_count!=null) {
          const overClass = c.details.over_10_lookups?'text-danger fw-bold':'';
          html += '<div class="small '+overClass+'">DNS lookups: '+c.details.dns_lookup_count+'/10</div>';
        }
      }
      if (name==='DKIM' && c.details) {
        html += '<div class="small text-muted">Selector: <code>'+esc(c.details.selector||'')+'</code> → <code>'+esc(c.details.fqdn||'')+'</code></div>';
        if (c.details.records && c.details.records.length) {
          html += '<div class="bg-light p-2 rounded mt-1"><code style="word-break:break-all; font-size:0.75rem;">'+c.details.records.map(r=>esc(r)).join('<br>')+'</code></div>';
        }
      }
      if (name==='DMARC' && c.details && c.details.record) {
        html += '<div class="bg-light p-2 rounded mb-2"><code style="word-break:break-all;">'+esc(c.details.record)+'</code></div>';
        const d = c.details;
        html += '<div class="row small"><div class="col-md-3"><strong>Policy:</strong> '+esc(d.policy||'—')+'</div>';
        html += '<div class="col-md-3"><strong>Subdomain:</strong> '+esc(d.subdomain_policy||'—')+'</div>';
        html += '<div class="col-md-3"><strong>RUA:</strong> '+esc(d.rua||'none')+'</div>';
        html += '<div class="col-md-3"><strong>%:</strong> '+esc(d.pct||'100')+'</div></div>';
      }
      if (name==='BIMI' && c.details && c.details.logo_url) {
        html += '<div class="small"><strong>Logo:</strong> <code>'+esc(c.details.logo_url)+'</code></div>';
      }
      if (c.likely_root_cause) html += '<div class="text-danger small mt-1">'+esc(c.likely_root_cause)+'</div>';
      if (c.recommended_fix) html += '<div class="text-info small">'+esc(c.recommended_fix)+'</div>';
    }

    tab.innerHTML = html || '<p class="text-muted">No authentication data.</p>';
  }

  function renderBlacklistTab() {
    const tab = document.getElementById('tab-blacklist');
    const bl = find('Blacklist Check');
    if (!bl) { tab.innerHTML = '<p class="text-muted">No blacklist data.</p>'; return; }

    let html = '<h5 class="mb-2">'+statusDot(bl.status)+'Blacklist Check</h5>';
    html += '<p>'+esc(bl.summary)+'</p>';

    if (bl.details && bl.details.checks) {
      const ips = [...new Set(bl.details.checks.map(c=>c.ip))];
      for (const ip of ips) {
        const ipChecks = bl.details.checks.filter(c=>c.ip===ip);
        const source = ipChecks[0]?.source || '';
        const listedCount = ipChecks.filter(c=>c.listed).length;
        const headerClass = listedCount > 0 ? 'text-danger' : 'text-success';
        html += '<h6 class="mt-3 '+headerClass+'"><code>'+esc(ip)+'</code> ('+esc(source)+') — '+(listedCount>0?listedCount+' LISTED':'Clean')+'</h6>';
        html += '<table class="table table-sm table-striped"><thead><tr><th>Blacklist</th><th>Status</th></tr></thead><tbody>';
        for (const c of ipChecks) {
          const icon = c.listed ? '<span class="badge bg-danger">LISTED</span>' : '<span class="text-success">&#10003; Clean</span>';
          html += '<tr><td>'+esc(c.blacklist)+'</td><td>'+icon+'</td></tr>';
        }
        html += '</tbody></table>';
      }
    }

    if (bl.likely_root_cause) html += '<div class="alert alert-danger mt-2">'+esc(bl.likely_root_cause)+'</div>';
    tab.innerHTML = html;
  }

  function renderTransportTab() {
    const tab = document.getElementById('tab-transport');
    let html = '';

    const sts = find('MTA-STS');
    if (sts) {
      html += '<h5 class="mb-2">'+statusDot(sts.status)+'MTA-STS</h5>';
      html += '<p>'+esc(sts.summary)+'</p>';
      if (sts.details) {
        if (sts.details.txt_record) html += '<div class="small"><strong>TXT:</strong> <code>'+esc(sts.details.txt_record)+'</code></div>';
        if (sts.details.policy_content) html += '<div class="small mt-1"><strong>Policy:</strong></div><pre class="bg-light p-2 rounded small">'+esc(sts.details.policy_content)+'</pre>';
        if (sts.details.policy_error) html += '<div class="text-danger small">Policy error: '+esc(sts.details.policy_error)+'</div>';
        if (sts.details.tlsrpt_records && sts.details.tlsrpt_records.length) html += '<div class="small mt-1"><strong>TLS-RPT:</strong> <code>'+esc(sts.details.tlsrpt_records[0])+'</code></div>';
      }
    }

    const dane = find('DANE/TLSA');
    if (dane) {
      html += '<h5 class="mb-2 mt-3">'+statusDot(dane.status)+'DANE/TLSA</h5>';
      html += '<p>'+esc(dane.summary)+'</p>';
      if (dane.details && dane.details.mx_tlsa) {
        for (const t of dane.details.mx_tlsa) {
          html += '<div class="small"><code>'+esc(t.mx_host)+'</code>: ';
          html += t.records.length ? '<code>'+t.records.map(r=>esc(r)).join('</code>, <code>')+'</code>' : '<span class="text-muted">No TLSA record</span>';
          html += '</div>';
        }
      }
    }

    tab.innerHTML = html || '<p class="text-muted">No transport security data.</p>';
  }

  function renderAutoconfigTab() {
    const tab = document.getElementById('tab-autoconfig');
    const ac = find('Autodiscover');
    if (!ac) { tab.innerHTML = '<p class="text-muted">No autodiscover data.</p>'; return; }

    let html = '<h5 class="mb-2">'+statusDot(ac.status)+'Autodiscover / Autoconfig</h5>';
    html += '<p>'+esc(ac.summary)+'</p>';

    if (ac.details) {
      const d = ac.details;
      if (d.autodiscover_srv && d.autodiscover_srv.length) {
        html += '<div class="small mb-1"><strong>Autodiscover SRV:</strong> <code>'+d.autodiscover_srv.map(r=>esc(r)).join('</code>, <code>')+'</code></div>';
      }
      if (d.autodiscover_cname && d.autodiscover_cname.length) {
        html += '<div class="small mb-1"><strong>Autodiscover CNAME:</strong> <code>'+d.autodiscover_cname.map(r=>esc(r)).join('</code>, <code>')+'</code></div>';
      }
      // Show endpoint results
      for (const [key, val] of Object.entries(d)) {
        if (typeof val === 'object' && val !== null && 'reachable' in val) {
          const icon = val.reachable ? '<span class="text-success">&#10003;</span>' : '<span class="text-danger">&#10007;</span>';
          const url = val.url || key;
          html += '<div class="small">'+icon+' <code>'+esc(url)+'</code>';
          if (val.status) html += ' (HTTP '+val.status+')';
          if (val.error) html += ' <span class="text-muted">'+esc(val.error)+'</span>';
          html += '</div>';
        }
      }
    }

    if (ac.likely_root_cause) html += '<div class="text-warning small mt-2">'+esc(ac.likely_root_cause)+'</div>';
    if (ac.recommended_fix) html += '<div class="text-info small">'+esc(ac.recommended_fix)+'</div>';
    tab.innerHTML = html;
  }

  // ---------- Run ----------
  btnRun.addEventListener('click', function() {
    const target = document.getElementById('csd-target').value.trim();
    if (!target) { showErr('Enter a domain.'); return; }
    hideErr();

    const checks = [
      'mx_check','smtp_connectivity','spf_check','dkim_check','dmarc_check',
      'blacklist_check','mta_sts','autodiscover','dane_tlsa','bimi'
    ];

    const data = new FormData(form);
    checks.forEach(c => data.append('checks[]', c));

    resultsEl.style.display = 'none';
    loading.style.display = 'block';
    btnRun.disabled = true;
    badge.style.display = 'inline-block';
    badge.textContent = 'Running...';
    badge.className = 'badge bg-primary';

    fetch(PLUGIN_ROOT + '/ajax/run_standalone.php', {
      method: 'POST', body: data, credentials: 'same-origin',
      headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': getCsrfToken() }
    })
    .then(r => { if (!r.headers.get('content-type')?.includes('json')) return r.text().then(()=>{ throw new Error('Non-JSON (HTTP '+r.status+')'); }); return r.json(); })
    .then(resp => {
      loading.style.display = 'none';
      btnRun.disabled = false;
      if (!resp.success) throw new Error(resp.message);

      lastData = resp.data;
      renderOverview();
      renderMxTab();
      renderAuthTab();
      renderBlacklistTab();
      renderTransportTab();
      renderAutoconfigTab();
      document.getElementById('csd-raw-json').textContent = JSON.stringify(resp.data, null, 2);
      resultsEl.style.display = 'block';
      btnNote.disabled = false;
      btnClient.disabled = false;

      const fc = (resp.data.checks||[]).filter(c=>c.status==='fail').length;
      const wc = (resp.data.checks||[]).filter(c=>c.status==='warn').length;
      badge.textContent = fc?fc+' fail, '+wc+' warn':wc?wc+' warning(s)':'All OK';
      badge.className = fc?'badge bg-danger':wc?'badge bg-warning text-dark':'badge bg-success';
    })
    .catch(err => {
      loading.style.display = 'none';
      btnRun.disabled = false;
      showErr(String(err.message||err));
      badge.textContent = 'Error';
      badge.className = 'badge bg-danger';
    });
  });

})();
</script>

<?php Html::footer(); ?>
