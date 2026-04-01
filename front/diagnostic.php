<?php
include('../../../inc/includes.php');

Session::checkLoginUser();

Html::header(__('DNS Diagnostic'), $_SERVER['PHP_SELF'], 'tools', 'pluginclearsignaldiagmenu', 'dns');

$config = PluginClearsignaldiagConfig::getConfig();
$pluginRoot = Plugin::getWebDir('clearsignaldiag');
?>

<ul class="nav nav-pills mb-3">
  <li class="nav-item"><a class="nav-link active" href="<?php echo htmlspecialchars($pluginRoot . '/front/diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-world-search me-1"></i>DNS Diagnostic</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/email_diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-mail-check me-1"></i>Email Diagnostic</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/header_analyser.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-mail-code me-1"></i>Email Analyser</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/website_diagnostic.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-lock-check me-1"></i>Website / SSL</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/port_scanner.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-plug me-1"></i>Port Scanner</a></li>
  <li class="nav-item"><a class="nav-link" href="<?php echo htmlspecialchars($pluginRoot . '/front/health_check.php', ENT_QUOTES, 'UTF-8'); ?>"><i class="ti ti-heart-rate-monitor me-1"></i>Health Check</a></li>
</ul>

<div class="card mb-3" id="csd-panel">
  <div class="card-header d-flex justify-content-between align-items-center">
    <h3 class="card-title mb-0"><i class="ti ti-stethoscope me-1"></i>ClearSignal DNS Diagnostic</h3>
    <span class="badge bg-secondary" id="csd-badge" style="display:none;"></span>
  </div>
  <div class="card-body">

    <form id="csd-form" autocomplete="off">
      <input type="hidden" name="_glpi_csrf_token" value="<?php echo htmlspecialchars(Session::getNewCSRFToken(), ENT_QUOTES, 'UTF-8'); ?>">

      <div class="row mb-3">
        <div class="col-md-7">
          <label for="csd-target" class="form-label fw-bold">Target</label>
          <input type="text" id="csd-target" name="target" class="form-control form-control-lg"
                 placeholder="e.g. example.com, mail.example.co.uk, 1.2.3.4" required>
        </div>
        <div class="col-md-3">
          <label for="csd-selector" class="form-label fw-bold">DKIM selector</label>
          <input type="text" id="csd-selector" name="dkim_selector" class="form-control form-control-lg"
                 value="<?php echo htmlspecialchars((string)($config['default_selector'] ?? 'selector1'), ENT_QUOTES, 'UTF-8'); ?>">
        </div>
        <div class="col-md-2 d-flex align-items-end">
          <button type="button" class="btn btn-primary btn-lg w-100" id="csd-btn-run">
            <i class="ti ti-player-play me-1"></i>Run
          </button>
        </div>
      </div>
    </form>

    <div id="csd-loading" style="display:none;" class="mb-3">
      <div class="d-flex align-items-center text-primary">
        <div class="spinner-border spinner-border-sm me-2" role="status"></div>
        <span>Running comprehensive diagnostics&hellip; this may take 15–30 seconds.</span>
      </div>
      <div class="progress mt-2" style="height:3px;">
        <div class="progress-bar progress-bar-striped progress-bar-animated" style="width:100%"></div>
      </div>
    </div>

    <div id="csd-error" class="alert alert-danger mb-3" style="display:none;" role="alert"></div>
  </div>
</div>

<!-- Results — hidden until run -->
<div id="csd-results" style="display:none;">

  <!-- Overview banner -->
  <div class="card mb-3" id="csd-overview-card">
    <div class="card-body py-3">
      <div class="row text-center" id="csd-overview-pills"></div>
    </div>
  </div>

  <!-- Tabbed results -->
  <div class="card">
    <div class="card-header p-0">
      <ul class="nav nav-tabs card-header-tabs" id="csd-tabs" role="tablist">
        <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#csd-tab-records" role="tab">DNS Records</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#csd-tab-ns" role="tab">Nameservers</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#csd-tab-resolvers" role="tab">Resolver Comparison</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#csd-tab-delegation" role="tab">Delegation &amp; DNSSEC</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#csd-tab-mail" role="tab">Mail Security</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#csd-tab-network" role="tab">Network</a></li>
        <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#csd-tab-raw" role="tab">Raw JSON</a></li>
      </ul>
    </div>
    <div class="card-body">
      <div class="tab-content">

        <!-- DNS Records tab -->
        <div class="tab-pane fade show active" id="csd-tab-records" role="tabpanel"></div>

        <!-- Nameservers tab -->
        <div class="tab-pane fade" id="csd-tab-ns" role="tabpanel"></div>

        <!-- Resolver Comparison tab -->
        <div class="tab-pane fade" id="csd-tab-resolvers" role="tabpanel"></div>

        <!-- Delegation & DNSSEC tab -->
        <div class="tab-pane fade" id="csd-tab-delegation" role="tabpanel"></div>

        <!-- Mail Security tab -->
        <div class="tab-pane fade" id="csd-tab-mail" role="tabpanel"></div>

        <!-- Network tab -->
        <div class="tab-pane fade" id="csd-tab-network" role="tabpanel"></div>

        <!-- Raw JSON tab -->
        <div class="tab-pane fade" id="csd-tab-raw" role="tabpanel">
          <pre id="csd-raw-json" style="white-space:pre-wrap; max-height:600px; overflow:auto; font-size:0.8rem;"></pre>
        </div>

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

  const form    = document.getElementById('csd-form');
  const btnRun  = document.getElementById('csd-btn-run');
  const loading = document.getElementById('csd-loading');
  const errDiv  = document.getElementById('csd-error');
  const results = document.getElementById('csd-results');
  const badge   = document.getElementById('csd-badge');
  const btnNote   = document.getElementById('csd-btn-copy-note');
  const btnClient = document.getElementById('csd-btn-copy-client');
  const ticketInput = document.getElementById('csd-ticket-id');
  const copyToast   = document.getElementById('csd-copy-toast');

  function getCsrfToken() {
    const meta = document.querySelector('meta[property="glpi:csrf_token"]');
    return meta ? meta.getAttribute('content') : (document.querySelector('input[name="_glpi_csrf_token"]')?.value || '');
  }

  function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function showErr(m) { errDiv.textContent = m; errDiv.style.display = 'block'; }
  function hideErr() { errDiv.style.display = 'none'; }

  function statusBadge(status, label) {
    const cls = status === 'ok' ? 'bg-success' : status === 'warn' ? 'bg-warning text-dark' : 'bg-danger';
    return '<span class="badge ' + cls + ' me-1">' + esc(label || status.toUpperCase()) + '</span>';
  }

  function statusDot(status) {
    const cls = status === 'ok' ? 'text-success' : status === 'warn' ? 'text-warning' : 'text-danger';
    return '<i class="ti ti-circle-filled ' + cls + ' me-1" style="font-size:0.7rem;"></i>';
  }

  function recordTable(records, title) {
    if (!records || Object.keys(records).length === 0) return '<p class="text-muted">No records found.</p>';
    let html = '';
    if (title) html += '<h5 class="mb-2">' + esc(title) + '</h5>';
    html += '<table class="table table-sm table-striped mb-3"><thead><tr><th>Type</th><th>Records</th><th>TTL</th></tr></thead><tbody>';
    for (const [type, data] of Object.entries(records)) {
      if (!data || !data.records || data.records.length === 0) continue;
      const ttl = data.ttl != null ? data.ttl + 's' : '—';
      html += '<tr><td class="fw-bold" style="width:80px;">' + esc(type) + '</td>';
      html += '<td><code>' + data.records.map(r => esc(r)).join('</code><br><code>') + '</code></td>';
      html += '<td style="width:80px;">' + ttl + '</td></tr>';
    }
    html += '</tbody></table>';
    return html;
  }

  // -----------------------------------------------------------------------
  // Tab renderers
  // -----------------------------------------------------------------------

  function renderOverview(data) {
    const checks = data.checks || [];
    const pills = document.getElementById('csd-overview-pills');
    const sections = {
      'DNS': ['Full Record Scan', 'SOA Record', 'Forward Lookup'],
      'Nameservers': ['Nameservers', 'Delegation Trace', 'Parent vs Child NS'],
      'DNSSEC': ['DNSSEC'],
      'Cloudflare': ['Cloudflare'],
      'Resolvers': ['Resolver Comparison'],
      'Mail': ['MX Records', 'SPF', 'DKIM', 'DMARC'],
      'Network': ['Ping', 'Website Check'],
      'Registration': ['Domain Registration'],
    };

    let html = '';
    for (const [label, names] of Object.entries(sections)) {
      const matching = checks.filter(c => names.includes(c.name));
      if (matching.length === 0) continue;
      const worst = matching.reduce((w, c) => c.status === 'fail' ? 'fail' : (c.status === 'warn' && w !== 'fail' ? 'warn' : w), 'ok');
      const cls = worst === 'ok' ? 'success' : worst === 'warn' ? 'warning' : 'danger';
      html += '<div class="col"><span class="badge bg-' + cls + (worst === 'warn' ? ' text-dark' : '') + ' p-2" style="font-size:0.85rem;">' + esc(label) + '</span></div>';
    }
    pills.innerHTML = html;
  }

  function renderRecordsTab(data) {
    const tab = document.getElementById('csd-tab-records');
    const scan = findCheck(data, 'Full Record Scan');
    const soa = findCheck(data, 'SOA Record');

    let html = '';

    // SOA info bar
    if (soa && soa.details) {
      const d = soa.details;
      html += '<div class="alert alert-light border mb-3">';
      html += '<div class="row">';
      html += '<div class="col-md-3"><strong>SOA Serial:</strong> <code>' + esc(String(d.serial || '—')) + '</code></div>';
      html += '<div class="col-md-3"><strong>Primary NS:</strong> <code>' + esc(d.primary_ns || '—') + '</code></div>';
      html += '<div class="col-md-3"><strong>Refresh:</strong> ' + esc(String(d.refresh || '—')) + 's</div>';
      html += '<div class="col-md-3"><strong>Min TTL:</strong> ' + esc(String(d.minimum_ttl || '—')) + 's</div>';
      html += '</div>';
      if (d.note) html += '<div class="text-muted small mt-1">' + esc(d.note) + '</div>';
      html += '</div>';
    }

    // Record table
    if (scan && scan.details && scan.details.records) {
      html += recordTable(scan.details.records, scan.details.host);
    }

    tab.innerHTML = html || '<p class="text-muted">No record data available.</p>';
  }

  function renderNsTab(data) {
    const tab = document.getElementById('csd-tab-ns');
    const ns = findCheck(data, 'Nameservers');

    let html = '';
    if (ns && ns.details && ns.details.nameservers) {
      html += '<h5 class="mb-2">Nameservers for ' + esc(ns.details.domain || '') + '</h5>';
      html += '<table class="table table-sm table-striped"><thead><tr><th>Nameserver</th><th>IP</th><th>Responds</th><th>Cloudflare</th></tr></thead><tbody>';
      for (const n of ns.details.nameservers) {
        const respondIcon = n.responds ? '<span class="text-success">&#10003;</span>' : '<span class="text-danger">&#10007;</span>';
        const cfIcon = n.is_cloudflare ? '<span class="badge bg-orange text-white" style="background:#f48120;">CF</span>' : '—';
        html += '<tr><td><code>' + esc(n.nameserver) + '</code></td><td><code>' + esc(n.ip || '—') + '</code></td><td>' + respondIcon + '</td><td>' + cfIcon + '</td></tr>';
      }
      html += '</tbody></table>';
      if (ns.details.ttl) html += '<div class="text-muted small">TTL: ' + ns.details.ttl + 's</div>';
    }

    // Whois / registration
    const whois = findCheck(data, 'Domain Registration');
    if (whois) {
      html += '<div class="alert ' + (whois.status === 'ok' ? 'alert-light border' : whois.status === 'warn' ? 'alert-warning' : 'alert-danger') + ' mt-3">';
      html += statusDot(whois.status) + '<strong>Registration:</strong> ' + esc(whois.summary);
      if (whois.details && whois.details.registrar) html += ' — <span class="text-muted">' + esc(whois.details.registrar) + '</span>';
      html += '</div>';
    }

    tab.innerHTML = html || '<p class="text-muted">No nameserver data available.</p>';
  }

  function renderResolversTab(data) {
    const tab = document.getElementById('csd-tab-resolvers');
    const cmp = findCheck(data, 'Resolver Comparison');

    let html = '';
    if (cmp && cmp.details && cmp.details.resolvers) {
      html += '<div class="mb-2">' + statusBadge(cmp.status) + ' <strong>' + esc(cmp.summary) + '</strong></div>';
      html += '<table class="table table-sm table-striped"><thead><tr><th>Resolver</th><th>IP</th><th>Type</th><th>Result</th><th>TTL</th><th>Response</th></tr></thead><tbody>';
      for (const r of cmp.details.resolvers) {
        const typeLabel = r.type === 'authoritative' ? '<span class="badge bg-info text-dark">Auth</span>' : '<span class="badge bg-secondary">Public</span>';
        const records = (r.records || []).map(x => esc(x)).join(', ') || '<span class="text-muted">' + esc(r.rcode) + '</span>';
        const ttl = r.ttl != null ? r.ttl + 's' : '—';
        const resp = r.response_time_ms != null ? r.response_time_ms + 'ms' : '—';
        html += '<tr><td><strong>' + esc(r.resolver) + '</strong></td><td><code>' + esc(r.ip) + '</code></td><td>' + typeLabel + '</td>';
        html += '<td><code>' + records + '</code></td><td>' + ttl + '</td><td>' + resp + '</td></tr>';
      }
      html += '</tbody></table>';
    }

    tab.innerHTML = html || '<p class="text-muted">No resolver data available.</p>';
  }

  function renderDelegationTab(data) {
    const tab = document.getElementById('csd-tab-delegation');
    let html = '';

    // Delegation trace
    const trace = findCheck(data, 'Delegation Trace');
    if (trace && trace.details && trace.details.hops) {
      html += '<h5 class="mb-2">' + statusDot(trace.status) + 'Delegation Trace</h5>';
      html += '<table class="table table-sm table-striped mb-3"><thead><tr><th>Zone</th><th>Queried Server</th><th>NS Records</th></tr></thead><tbody>';
      for (const hop of trace.details.hops) {
        const server = hop.queried_server || (hop.queried_servers || []).join(', ') || '—';
        const nsRecs = hop.ns_records ? hop.ns_records.map(n => '<code>' + esc(n) + '</code>').join(', ') : '<span class="text-danger">' + esc(hop.error || 'Failed') + '</span>';
        html += '<tr><td><strong>' + esc(hop.zone) + '</strong></td><td><code>' + esc(server) + '</code></td><td>' + nsRecs + '</td></tr>';
      }
      html += '</tbody></table>';
      if (trace.likely_root_cause) html += '<div class="text-danger small mb-2">&#9888; ' + esc(trace.likely_root_cause) + '</div>';
    }

    // Parent vs Child NS
    const pcns = findCheck(data, 'Parent vs Child NS');
    if (pcns) {
      html += '<h5 class="mb-2 mt-3">' + statusDot(pcns.status) + 'Parent vs Child NS</h5>';
      html += '<p>' + esc(pcns.summary) + '</p>';
      if (pcns.likely_root_cause) html += '<div class="text-danger small">' + esc(pcns.likely_root_cause) + '</div>';
    }

    // DNSSEC
    const dnssec = findCheck(data, 'DNSSEC');
    if (dnssec) {
      html += '<h5 class="mb-2 mt-3">' + statusDot(dnssec.status) + 'DNSSEC</h5>';
      html += '<p>' + esc(dnssec.summary) + '</p>';
      if (dnssec.details) {
        const d = dnssec.details;
        html += '<div class="row mb-2">';
        html += '<div class="col-md-4"><strong>DS at parent:</strong> ' + (d.ds_record_exists ? '<span class="text-success">Yes</span>' : '<span class="text-muted">No</span>') + '</div>';
        html += '<div class="col-md-4"><strong>Standard query:</strong> <code>' + esc(d.standard_rcode || '—') + '</code></div>';
        html += '<div class="col-md-4"><strong>CD query:</strong> <code>' + esc(d.cd_rcode || '—') + '</code></div>';
        html += '</div>';
      }
      if (dnssec.likely_root_cause) html += '<div class="text-danger small">' + esc(dnssec.likely_root_cause) + '</div>';
      if (dnssec.recommended_fix) html += '<div class="text-info small">' + esc(dnssec.recommended_fix) + '</div>';
    }

    // Cloudflare
    const cf = findCheck(data, 'Cloudflare');
    if (cf) {
      html += '<h5 class="mb-2 mt-3">' + statusDot(cf.status) + 'Cloudflare</h5>';
      html += '<p>' + esc(cf.summary) + '</p>';
      if (cf.details) {
        const d = cf.details;
        if (d.cloudflare_nameservers && d.cloudflare_nameservers.length) {
          html += '<div class="small"><strong>CF Nameservers:</strong> <code>' + d.cloudflare_nameservers.map(n => esc(n)).join('</code>, <code>') + '</code></div>';
        }
        if (d.cloudflare_ips && d.cloudflare_ips.length) {
          html += '<div class="small"><strong>CF IPs (proxied):</strong> <code>' + d.cloudflare_ips.map(n => esc(n)).join('</code>, <code>') + '</code></div>';
        }
      }
    }

    tab.innerHTML = html || '<p class="text-muted">No delegation data available.</p>';
  }

  function renderMailTab(data) {
    const tab = document.getElementById('csd-tab-mail');
    let html = '';

    // MX
    const mx = findCheck(data, 'MX Records');
    if (mx) {
      html += '<h5 class="mb-2">' + statusDot(mx.status) + 'MX Records</h5>';
      if (mx.details && mx.details.mx && mx.details.mx.length) {
        html += '<table class="table table-sm table-striped mb-3"><thead><tr><th>Priority</th><th>Mail Server</th></tr></thead><tbody>';
        for (const m of mx.details.mx) {
          html += '<tr><td>' + m.priority + '</td><td><code>' + esc(m.exchange) + '</code></td></tr>';
        }
        html += '</tbody></table>';
      } else {
        html += '<p class="text-muted">' + esc(mx.summary) + '</p>';
      }
    }

    // SPF
    const spf = findCheck(data, 'SPF');
    if (spf) {
      html += '<h5 class="mb-2 mt-3">' + statusDot(spf.status) + 'SPF</h5>';
      html += '<p>' + esc(spf.summary) + '</p>';
      if (spf.details && spf.details.spf) {
        html += '<div class="bg-light p-2 rounded mb-2"><code style="word-break:break-all;">' + esc(spf.details.spf) + '</code></div>';
        if (spf.details.dns_lookup_count != null) {
          const overClass = spf.details.over_10_lookups ? 'text-danger fw-bold' : '';
          html += '<div class="small ' + overClass + '">DNS lookups: ' + spf.details.dns_lookup_count + '/10</div>';
        }
      }
      if (spf.likely_root_cause) html += '<div class="text-danger small">' + esc(spf.likely_root_cause) + '</div>';
    }

    // DKIM
    const dkim = findCheck(data, 'DKIM');
    if (dkim) {
      html += '<h5 class="mb-2 mt-3">' + statusDot(dkim.status) + 'DKIM</h5>';
      html += '<p>' + esc(dkim.summary) + '</p>';
      if (dkim.details) {
        html += '<div class="small text-muted">Selector: <code>' + esc(dkim.details.selector || '') + '</code> → <code>' + esc(dkim.details.fqdn || '') + '</code></div>';
        if (dkim.details.records && dkim.details.records.length) {
          html += '<div class="bg-light p-2 rounded mt-1"><code style="word-break:break-all; font-size:0.75rem;">' + dkim.details.records.map(r => esc(r)).join('<br>') + '</code></div>';
        }
      }
    }

    // DMARC
    const dmarc = findCheck(data, 'DMARC');
    if (dmarc) {
      html += '<h5 class="mb-2 mt-3">' + statusDot(dmarc.status) + 'DMARC</h5>';
      html += '<p>' + esc(dmarc.summary) + '</p>';
      if (dmarc.details && dmarc.details.record) {
        html += '<div class="bg-light p-2 rounded mb-2"><code style="word-break:break-all;">' + esc(dmarc.details.record) + '</code></div>';
        const d = dmarc.details;
        html += '<div class="row small">';
        html += '<div class="col-md-3"><strong>Policy:</strong> ' + esc(d.policy || '—') + '</div>';
        html += '<div class="col-md-3"><strong>Subdomain:</strong> ' + esc(d.subdomain_policy || '—') + '</div>';
        html += '<div class="col-md-3"><strong>RUA:</strong> ' + esc(d.rua || 'none') + '</div>';
        html += '<div class="col-md-3"><strong>%:</strong> ' + esc(d.pct || '100') + '</div>';
        html += '</div>';
      }
      if (dmarc.likely_root_cause) html += '<div class="text-warning small mt-1">' + esc(dmarc.likely_root_cause) + '</div>';
    }

    tab.innerHTML = html || '<p class="text-muted">No mail security data available.</p>';
  }

  function renderNetworkTab(data) {
    const tab = document.getElementById('csd-tab-network');
    let html = '';

    const ping = findCheck(data, 'Ping');
    if (ping) {
      html += '<h5 class="mb-2">' + statusDot(ping.status) + 'Ping</h5>';
      html += '<p>' + esc(ping.summary) + '</p>';
      if (ping.details && ping.details.stdout) {
        html += '<pre class="bg-light p-2 rounded small" style="max-height:200px; overflow:auto;">' + esc(ping.details.stdout) + '</pre>';
      }
    }

    const tracert = findCheck(data, 'Traceroute');
    if (tracert) {
      html += '<h5 class="mb-2 mt-3">' + statusDot(tracert.status) + 'Traceroute</h5>';
      html += '<p>' + esc(tracert.summary) + '</p>';
      if (tracert.details && tracert.details.stdout) {
        html += '<pre class="bg-light p-2 rounded small" style="max-height:300px; overflow:auto;">' + esc(tracert.details.stdout) + '</pre>';
      }
    }

    const web = findCheck(data, 'Website Check');
    if (web) {
      html += '<h5 class="mb-2 mt-3">' + statusDot(web.status) + 'Website Check</h5>';
      html += '<p>' + esc(web.summary) + '</p>';
      if (web.details) {
        const d = web.details;
        html += '<div class="row small mb-2">';
        html += '<div class="col-md-3"><strong>Status:</strong> ' + esc(String(d.status_code || '—')) + '</div>';
        html += '<div class="col-md-3"><strong>Server:</strong> ' + esc(d.server || '—') + '</div>';
        html += '<div class="col-md-3"><strong>Response:</strong> ' + esc(String(d.response_time_ms || '—')) + 'ms</div>';
        html += '<div class="col-md-3"><strong>Final URL:</strong> <code>' + esc(d.final_url || '—') + '</code></div>';
        html += '</div>';
        if (d.redirect_chain && d.redirect_chain.length) {
          html += '<div class="small text-muted">Redirects: ' + d.redirect_chain.map(u => '<code>' + esc(u) + '</code>').join(' → ') + '</div>';
        }
        if (d.tls_certificate && !d.tls_certificate.error) {
          const c = d.tls_certificate;
          html += '<div class="alert alert-light border mt-2 mb-0">';
          html += '<strong>TLS Certificate</strong><br>';
          html += '<div class="row small">';
          html += '<div class="col-md-3"><strong>CN:</strong> ' + esc(c.subject_cn || '—') + '</div>';
          html += '<div class="col-md-3"><strong>Issuer:</strong> ' + esc(c.issuer || '—') + '</div>';
          html += '<div class="col-md-3"><strong>Expires:</strong> ' + esc(c.expires || '—') + '</div>';
          const daysClass = c.days_remaining != null && c.days_remaining < 30 ? 'text-danger fw-bold' : '';
          html += '<div class="col-md-3 ' + daysClass + '"><strong>Days left:</strong> ' + (c.days_remaining != null ? c.days_remaining : '—') + '</div>';
          html += '</div>';
          if (c.san && c.san.length) {
            html += '<div class="small text-muted mt-1">SANs: ' + c.san.map(s => '<code>' + esc(s) + '</code>').join(', ') + '</div>';
          }
          html += '</div>';
        } else if (d.tls_certificate && d.tls_certificate.error) {
          html += '<div class="alert alert-danger mt-2 mb-0 small">' + esc(d.tls_certificate.error) + '</div>';
        }
      }
    }

    tab.innerHTML = html || '<p class="text-muted">No network data available.</p>';
  }

  function findCheck(data, name) {
    return (data.checks || []).find(c => c.name === name) || null;
  }

  // -----------------------------------------------------------------------
  // Run
  // -----------------------------------------------------------------------

  btnRun.addEventListener('click', function() {
    const target = document.getElementById('csd-target').value.trim();
    if (!target) { showErr('Enter a target.'); return; }
    hideErr();

    // Build the checks list — run everything for the standalone tool
    const checks = [
      'full_record_scan', 'soa', 'ns_detail', 'delegation_trace', 'dnssec',
      'parent_child_ns', 'cloudflare', 'resolver_comparison',
      'ping', 'traceroute', 'website_check',
      'mx_check', 'spf_check', 'dkim_check', 'dmarc_check',
      'forward_lookup', 'reverse_lookup', 'whois'
    ];

    const data = new FormData(form);
    checks.forEach(c => data.append('checks[]', c));

    results.style.display = 'none';
    loading.style.display = 'block';
    btnRun.disabled = true;
    badge.style.display = 'inline-block';
    badge.textContent = 'Running...';
    badge.className = 'badge bg-primary';

    fetch(PLUGIN_ROOT + '/ajax/run_standalone.php', {
      method: 'POST',
      body: data,
      credentials: 'same-origin',
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'X-Glpi-Csrf-Token': getCsrfToken()
      }
    })
    .then(r => {
      const ct = r.headers.get('content-type') || '';
      if (!ct.includes('json')) return r.text().then(() => { throw new Error('Non-JSON response (HTTP ' + r.status + ').'); });
      return r.json();
    })
    .then(resp => {
      loading.style.display = 'none';
      btnRun.disabled = false;
      if (!resp.success) throw new Error(resp.message || 'Failed.');

      lastData = resp.data;

      // Render all tabs
      renderOverview(resp.data);
      renderRecordsTab(resp.data);
      renderNsTab(resp.data);
      renderResolversTab(resp.data);
      renderDelegationTab(resp.data);
      renderMailTab(resp.data);
      renderNetworkTab(resp.data);
      document.getElementById('csd-raw-json').textContent = JSON.stringify(resp.data, null, 2);

      results.style.display = 'block';
      btnNote.disabled = false;
      btnClient.disabled = false;

      const failCount = (resp.data.checks || []).filter(c => c.status === 'fail').length;
      const warnCount = (resp.data.checks || []).filter(c => c.status === 'warn').length;
      if (failCount) {
        badge.textContent = failCount + ' fail, ' + warnCount + ' warn';
        badge.className = 'badge bg-danger';
      } else if (warnCount) {
        badge.textContent = warnCount + ' warning(s)';
        badge.className = 'badge bg-warning text-dark';
      } else {
        badge.textContent = 'All OK';
        badge.className = 'badge bg-success';
      }
    })
    .catch(err => {
      loading.style.display = 'none';
      btnRun.disabled = false;
      showErr(String(err.message || err));
      badge.textContent = 'Error';
      badge.className = 'badge bg-danger';
    });
  });

  // ---------- Copy to ticket ----------
  function showCopyToast(msg) {
    copyToast.textContent = msg; copyToast.style.display = 'block';
    setTimeout(()=>{ copyToast.style.display='none'; }, 4000);
  }

  function buildEngineerSummary() {
    if (!lastData) return '';
    const lines = ['=== ClearSignal DNS Diagnostic ===',
      'Date: ' + new Date().toISOString().replace('T',' ').substring(0,19),
      'Target: ' + (lastData.target?.input || ''), ''];
    for (const c of (lastData.checks||[])) {
      lines.push('[' + c.status.toUpperCase() + '] ' + c.name + ': ' + c.summary);
      if (c.likely_root_cause) lines.push('  Cause: ' + c.likely_root_cause);
      if (c.recommended_fix) lines.push('  Fix: ' + c.recommended_fix);
    }
    lines.push('', '=== End of Report ===');
    return lines.join('\n');
  }

  function buildClientSummary() {
    if (!lastData) return '';
    const target = lastData.target?.input || '';
    const lines = ['DNS & Network Report for ' + target,
      'Date: ' + new Date().toISOString().replace('T',' ').substring(0,19), ''];
    const checks = lastData.checks || [];
    const ok = checks.filter(c=>c.status==='ok').length;
    const issues = checks.filter(c=>c.status!=='ok');
    lines.push('Overall: ' + ok + '/' + checks.length + ' checks passed.');
    if (issues.length) {
      lines.push('', 'Items requiring attention:');
      for (const c of issues) lines.push('  - ' + c.name + ': ' + c.summary);
    }
    const fixes = checks.filter(c=>c.recommended_fix);
    if (fixes.length) {
      lines.push('', 'Recommendations:');
      for (const c of fixes) lines.push('  - ' + c.recommended_fix);
    } else {
      lines.push('', 'No issues found. Configuration looks healthy.');
    }
    lines.push('', 'Report generated by ClearSignal Diagnostics');
    return lines.join('\n');
  }

  function copyToTicket(summary) {
    const tid = parseInt(ticketInput.value, 10);
    if (!tid || tid <= 0) { showErr('Enter a valid ticket ID.'); return; }
    hideError();
    const data = new FormData();
    data.append('tickets_id', tid);
    data.append('summary', summary);
    fetch(PLUGIN_ROOT + '/ajax/addtoticket.php', {
      method: 'POST', body: data, credentials: 'same-origin',
      headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-Glpi-Csrf-Token': getCsrfToken() }
    })
    .then(r=>{ if(!r.headers.get('content-type')?.includes('json')) throw new Error('Non-JSON'); return r.json(); })
    .then(resp=>{ if(!resp.success) throw new Error(resp.message); showCopyToast('Added to ticket #'+tid+' as private follow-up.'); })
    .catch(err=>showErr(String(err.message||err)));
  }

  btnNote.addEventListener('click', ()=>copyToTicket(buildEngineerSummary()));
  btnClient.addEventListener('click', ()=>copyToTicket(buildClientSummary()));

})();
</script>

<?php
Html::footer();
