<?php
include('../../../inc/includes.php');

while (ob_get_level()) {
    ob_end_clean();
}
header('Content-Type: application/json; charset=UTF-8');

Session::checkLoginUser();

try {
    $action = trim((string)($_GET['action'] ?? ''));

    if ($action === 'poll_jobs') {
        // Check status of queued jobs by job IDs
        $jobIds = $_GET['job_ids'] ?? '';
        $ids = array_filter(array_map('intval', explode(',', $jobIds)));

        if (!$ids) {
            throw new RuntimeException('No job IDs provided.');
        }

        global $DB;
        $queueTable = 'glpi_plugin_clearsignalcore_queuejobs';

        if (!$DB->tableExists($queueTable)) {
            throw new RuntimeException('Core queue table not found.');
        }

        $jobs = [];
        $rows = $DB->request([
            'FROM' => $queueTable,
            'WHERE' => ['id' => $ids],
        ]);
        foreach ($rows as $row) {
            $jobs[] = [
                'job_id' => (int)$row['id'],
                'status' => (string)$row['status'],
                'job_type' => (string)($row['job_type'] ?? ''),
            ];
        }

        $allDone = !empty($jobs) && count(array_filter($jobs, fn($j) => in_array($j['status'], ['completed', 'failed', 'error']))) === count($jobs);
        $completed = count(array_filter($jobs, fn($j) => $j['status'] === 'completed'));
        $failed = count(array_filter($jobs, fn($j) => in_array($j['status'], ['failed', 'error'])));
        $pending = count(array_filter($jobs, fn($j) => in_array($j['status'], ['pending', 'queued', 'running'])));

        echo json_encode([
            'success' => true,
            'all_done' => $allDone,
            'completed' => $completed,
            'failed' => $failed,
            'pending' => $pending,
            'total' => count($jobs),
            'jobs' => $jobs,
        ], JSON_UNESCAPED_SLASHES);

    } elseif ($action === 'poll_reports') {
        // Check for recent health reports for given domains (alternative to job polling)
        $entityId = (int)($_GET['entities_id'] ?? 0);
        $sinceTimestamp = trim((string)($_GET['since'] ?? ''));

        if ($entityId <= 0 || $sinceTimestamp === '') {
            throw new RuntimeException('entities_id and since are required.');
        }

        global $DB;
        $reportTable = 'glpi_plugin_clearsignaldiag_health_reports';

        $rows = $DB->request([
            'FROM' => $reportTable,
            'WHERE' => [
                'entities_id' => $entityId,
                ['date_creation' => ['>=', $sinceTimestamp]],
            ],
        ]);

        $reports = [];
        foreach ($rows as $row) {
            $reports[] = [
                'domain' => (string)$row['domain'],
                'status' => (string)$row['status'],
                'checks_run' => (int)$row['checks_run'],
                'checks_ok' => (int)$row['checks_ok'],
                'checks_warn' => (int)$row['checks_warn'],
                'checks_fail' => (int)$row['checks_fail'],
                'date_creation' => (string)$row['date_creation'],
            ];
        }

        echo json_encode([
            'success' => true,
            'reports' => $reports,
            'count' => count($reports),
        ], JSON_UNESCAPED_SLASHES);

    } else {
        throw new RuntimeException('Unknown action.');
    }
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => $e->getMessage()], JSON_UNESCAPED_SLASHES);
}

exit;
