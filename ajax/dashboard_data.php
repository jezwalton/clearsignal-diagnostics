<?php
include('../../../inc/includes.php');

while (ob_get_level()) {
    ob_end_clean();
}
header('Content-Type: application/json; charset=UTF-8');

Session::checkLoginUser();

try {
    $action = trim((string)($_GET['action'] ?? ''));

    if ($action === 'fleet_overview') {
        global $DB;

        // Get all entity domains with their latest health report
        $domains = $DB->request([
            'FROM' => 'glpi_plugin_clearsignaldiag_entity_domains',
            'ORDER' => ['entities_id ASC', 'is_primary DESC', 'domain ASC'],
        ]);

        $entityMap = [];
        $domainList = [];
        foreach ($domains as $row) {
            $eid = (int)$row['entities_id'];
            $domainList[] = [
                'id' => (int)$row['id'],
                'entities_id' => $eid,
                'domain' => (string)$row['domain'],
                'is_primary' => (int)$row['is_primary'],
                'label' => (string)($row['label'] ?? ''),
            ];
            if (!isset($entityMap[$eid])) {
                $entityMap[$eid] = true;
            }
        }

        // Get entity names
        $entityNames = [];
        if ($entityMap) {
            $entities = $DB->request([
                'FROM' => 'glpi_entities',
                'WHERE' => ['id' => array_keys($entityMap)],
            ]);
            foreach ($entities as $row) {
                $entityNames[(int)$row['id']] = (string)$row['name'];
            }
        }

        // Get latest health report per domain
        // First get the max id per domain+entity, then fetch those rows
        $latestReports = [];
        $reportTable = 'glpi_plugin_clearsignaldiag_health_reports';
        if ($domainList && $DB->tableExists($reportTable)) {
            // Step 1: get max report ID per domain/entity pair
            $maxRows = $DB->request([
                'SELECT' => [
                    'domain',
                    'entities_id',
                    new \QueryExpression('MAX(`id`) AS `max_id`'),
                ],
                'FROM' => $reportTable,
                'GROUPBY' => ['domain', 'entities_id'],
            ]);

            $maxIds = [];
            foreach ($maxRows as $row) {
                if ((int)$row['max_id'] > 0) {
                    $maxIds[] = (int)$row['max_id'];
                }
            }

            // Step 2: fetch those reports
            if ($maxIds) {
                $reportRows = $DB->request([
                    'FROM' => $reportTable,
                    'WHERE' => ['id' => $maxIds],
                ]);
                foreach ($reportRows as $row) {
                    $key = (int)$row['entities_id'] . ':' . $row['domain'];
                    $latestReports[$key] = [
                        'id' => (int)$row['id'],
                        'status' => (string)$row['status'],
                        'checks_run' => (int)$row['checks_run'],
                        'checks_ok' => (int)$row['checks_ok'],
                        'checks_warn' => (int)$row['checks_warn'],
                        'checks_fail' => (int)$row['checks_fail'],
                        'date_creation' => (string)$row['date_creation'],
                        'users_id' => (int)$row['users_id'],
                    ];
                }
            }
        }

        // Build fleet data
        $fleet = [];
        foreach ($domainList as $d) {
            $key = $d['entities_id'] . ':' . $d['domain'];
            $report = $latestReports[$key] ?? null;

            $daysSinceCheck = null;
            if ($report) {
                $checkDate = strtotime($report['date_creation']);
                if ($checkDate) {
                    $daysSinceCheck = (int)((time() - $checkDate) / 86400);
                }
            }

            $fleet[] = [
                'domain_id' => $d['id'],
                'entities_id' => $d['entities_id'],
                'entity_name' => $entityNames[$d['entities_id']] ?? 'Unknown',
                'domain' => $d['domain'],
                'is_primary' => $d['is_primary'],
                'label' => $d['label'],
                'last_report' => $report,
                'days_since_check' => $daysSinceCheck,
                'stale' => $daysSinceCheck === null || $daysSinceCheck > 30,
                'never_checked' => $report === null,
            ];
        }

        // Summary stats
        $totalDomains = count($fleet);
        $neverChecked = count(array_filter($fleet, fn($f) => $f['never_checked']));
        $stale = count(array_filter($fleet, fn($f) => $f['stale'] && !$f['never_checked']));
        $ok = count(array_filter($fleet, fn($f) => ($f['last_report']['status'] ?? '') === 'ok'));
        $warn = count(array_filter($fleet, fn($f) => ($f['last_report']['status'] ?? '') === 'warn'));
        $fail = count(array_filter($fleet, fn($f) => ($f['last_report']['status'] ?? '') === 'fail'));

        echo json_encode([
            'success' => true,
            'summary' => [
                'total_domains' => $totalDomains,
                'total_entities' => count($entityMap),
                'never_checked' => $neverChecked,
                'stale' => $stale,
                'ok' => $ok,
                'warn' => $warn,
                'fail' => $fail,
            ],
            'fleet' => $fleet,
        ], JSON_UNESCAPED_SLASHES);

    } else {
        throw new RuntimeException('Unknown action.');
    }
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => $e->getMessage()], JSON_UNESCAPED_SLASHES);
}

exit;
