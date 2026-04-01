<?php
include('../../../inc/includes.php');

while (ob_get_level()) {
    ob_end_clean();
}
header('Content-Type: application/json; charset=UTF-8');

Session::checkLoginUser();

try {
    $domain = strtolower(trim((string)($_POST['domain'] ?? '')));
    $entityId = (int)($_POST['entities_id'] ?? 0);
    $storeResult = (bool)($_POST['store_result'] ?? false);
    $dkimSelector = trim((string)($_POST['dkim_selector'] ?? 'selector1'));
    $mode = trim((string)($_POST['mode'] ?? 'auto')); // 'queue', 'direct', or 'auto'

    if ($domain === '') {
        throw new RuntimeException('Domain is required.');
    }

    $parsedTarget = PluginClearsignaldiagTargetParser::parse($domain);
    if (!$parsedTarget['valid']) {
        throw new RuntimeException('Not a valid domain or hostname.');
    }

    // Determine whether to use Core queue or run directly
    $useQueue = false;
    if ($mode === 'queue') {
        $useQueue = true;
    } elseif ($mode === 'auto') {
        // Auto: use queue if Core worker is available
        $useQueue = class_exists('PluginClearsignalcoreQueueWorker');
    }

    if ($useQueue && class_exists('PluginClearsignalcoreQueueWorker')) {
        // Dispatch to Core worker queue — returns instantly
        $worker = new PluginClearsignalcoreQueueWorker();
        $result = $worker->dispatch('health_check', [
            'domain'        => $domain,
            'entities_id'   => $entityId,
            'dkim_selector' => $dkimSelector,
            'users_id'      => (int)Session::getLoginUserID(),
        ], PluginClearsignalcoreQueueWorker::PRIORITY_NORMAL);

        echo json_encode([
            'success'  => true,
            'queued'   => true,
            'job_id'   => $result['job_id'] ?? null,
            'domain'   => $domain,
            'message'  => 'Health check queued for processing.',
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    } else {
        // Run directly via PythonBridge (fallback / quick mode)
        $checks = [
            'full_record_scan', 'soa', 'ns_detail', 'delegation_trace', 'dnssec',
            'cloudflare', 'resolver_comparison', 'whois',
            'mx_check', 'smtp_connectivity', 'spf_check', 'dkim_check', 'dmarc_check',
            'http_response', 'tls_certificate', 'security_headers', 'http2_support',
            'caa_records', 'cf_ssl_mode',
        ];

        $result = PluginClearsignaldiagPythonBridge::run([
            'target'        => $parsedTarget,
            'checks'        => $checks,
            'dkim_selector' => $dkimSelector,
            'requested_by'  => Session::getLoginUserID(),
            'requested_at'  => date('c'),
        ]);

        $reportId = null;
        if ($storeResult && $entityId > 0) {
            $reportId = PluginClearsignaldiagEntitydomain::storeReport(
                $entityId,
                $domain,
                $result,
                (int)Session::getLoginUserID()
            );
        }

        echo json_encode([
            'success'   => true,
            'queued'    => false,
            'data'      => $result,
            'report_id' => $reportId,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

exit;
