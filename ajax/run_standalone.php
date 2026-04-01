<?php
include('../../../inc/includes.php');

while (ob_get_level()) {
    ob_end_clean();
}
header('Content-Type: application/json; charset=UTF-8');

Session::checkLoginUser();

try {
    $target = trim((string)($_POST['target'] ?? ''));
    $checks = $_POST['checks'] ?? [];
    $dkimSelector = trim((string)($_POST['dkim_selector'] ?? ''));

    $rawHeadersInput = trim((string)($_POST['raw_headers'] ?? ''));
    $headerOnlyMode = ($rawHeadersInput !== '' && $target === '');

    if ($target === '' && !$headerOnlyMode) {
        throw new RuntimeException('Target is required.');
    }

    if (!is_array($checks) || count($checks) === 0) {
        throw new RuntimeException('Select at least one check.');
    }

    // Header analysis doesn't require a target
    $isHeaderOnly = (count($cleanChecks) === 1 && $cleanChecks[0] === 'email_header_analysis');

    $parsedTarget = PluginClearsignaldiagTargetParser::parse($target);
    if (!$parsedTarget['valid'] && !$isHeaderOnly) {
        throw new RuntimeException('Target is not a valid IP, hostname, domain, or URL.');
    }

    $allowedChecks = [
        'ping', 'traceroute', 'forward_lookup', 'reverse_lookup',
        'dns_diagnostic', 'website_check', 'mx_check',
        'spf_check', 'dkim_check', 'dmarc_check',
        // DNS standalone checks
        'full_record_scan', 'soa', 'ns_detail', 'delegation_trace',
        'dnssec', 'parent_child_ns', 'cloudflare', 'resolver_comparison',
        'whois',
        // Email diagnostic checks
        'smtp_connectivity', 'blacklist_check', 'mta_sts',
        'autodiscover', 'dane_tlsa', 'bimi',
        // Website/SSL diagnostic checks
        'tls_certificate', 'security_headers', 'http_response',
        'http2_support', 'caa_records', 'cf_ssl_mode',
        // Email header analysis
        'email_header_analysis',
    ];
    $cleanChecks = array_values(array_intersect($allowedChecks, $checks));
    if (count($cleanChecks) === 0) {
        throw new RuntimeException('No valid checks selected.');
    }

    $config = PluginClearsignaldiagConfig::getConfig();
    if ($dkimSelector === '') {
        $dkimSelector = (string)$config['default_selector'];
    }

    $payload = [
        'target'         => $parsedTarget,
        'checks'         => $cleanChecks,
        'dkim_selector'  => $dkimSelector,
        'requested_by'   => Session::getLoginUserID(),
        'requested_at'   => date('c'),
    ];

    // Pass raw headers for email header analysis
    $rawHeaders = trim((string)($_POST['raw_headers'] ?? ''));
    if ($rawHeaders !== '') {
        $payload['raw_headers'] = $rawHeaders;
    }

    $result = PluginClearsignaldiagPythonBridge::run($payload);

    echo json_encode([
        'success' => true,
        'data'    => $result
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

exit;
