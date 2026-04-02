<?php
include('../../../inc/includes.php');

while (ob_get_level()) {
    ob_end_clean();
}
header('Content-Type: application/json; charset=UTF-8');

Session::checkLoginUser();

try {
    $action = trim((string)($_POST['action'] ?? $_GET['action'] ?? ''));
    $entityId = (int)($_POST['entities_id'] ?? $_GET['entities_id'] ?? 0);

    if ($entityId <= 0 && $action !== 'search_entities') {
        throw new RuntimeException('Invalid entity ID.');
    }

    switch ($action) {
        case 'list':
            $domains = PluginClearsignaldiagEntitydomain::getDomainsForEntity($entityId);
            echo json_encode(['success' => true, 'domains' => $domains], JSON_UNESCAPED_SLASHES);
            break;

        case 'add':
            $domain = trim((string)($_POST['domain'] ?? ''));
            $label = trim((string)($_POST['label'] ?? ''));
            $isPrimary = (bool)($_POST['is_primary'] ?? false);

            if ($domain === '') {
                throw new RuntimeException('Domain is required.');
            }

            $id = PluginClearsignaldiagEntitydomain::addDomain($entityId, $domain, $label, $isPrimary);
            echo json_encode(['success' => true, 'id' => $id], JSON_UNESCAPED_SLASHES);
            break;

        case 'remove':
            $domainId = (int)($_POST['domain_id'] ?? 0);
            if ($domainId <= 0) {
                throw new RuntimeException('Invalid domain ID.');
            }
            PluginClearsignaldiagEntitydomain::removeDomain($domainId);
            echo json_encode(['success' => true], JSON_UNESCAPED_SLASHES);
            break;

        case 'reports':
            $reports = PluginClearsignaldiagEntitydomain::getReports($entityId);
            echo json_encode(['success' => true, 'reports' => $reports], JSON_UNESCAPED_SLASHES);
            break;

        case 'view_report':
            $reportId = (int)($_GET['report_id'] ?? $_POST['report_id'] ?? 0);
            if ($reportId <= 0) {
                throw new RuntimeException('Invalid report ID.');
            }
            global $DB;
            $reportTable = 'glpi_plugin_clearsignaldiag_health_reports';
            $rows = $DB->request([
                'FROM' => $reportTable,
                'WHERE' => ['id' => $reportId],
                'LIMIT' => 1,
            ]);
            $row = $rows->current();
            if (!$row) {
                throw new RuntimeException('Report not found.');
            }
            $reportData = json_decode($row['report_json'] ?? '{}', true);
            echo json_encode([
                'success' => true,
                'report' => [
                    'id' => (int)$row['id'],
                    'domain' => (string)$row['domain'],
                    'status' => (string)$row['status'],
                    'checks_run' => (int)$row['checks_run'],
                    'checks_ok' => (int)$row['checks_ok'],
                    'checks_warn' => (int)$row['checks_warn'],
                    'checks_fail' => (int)$row['checks_fail'],
                    'date_creation' => (string)$row['date_creation'],
                    'data' => $reportData,
                ],
            ], JSON_UNESCAPED_SLASHES);
            break;

        case 'search_entities':
            $search = trim((string)($_GET['q'] ?? ''));
            if (strlen($search) < 2) {
                echo json_encode(['success' => true, 'entities' => []], JSON_UNESCAPED_SLASHES);
                break;
            }
            global $DB;
            $entities = [];
            $rows = $DB->request([
                'FROM'   => 'glpi_entities',
                'WHERE'  => ['name' => ['LIKE', '%' . $search . '%']],
                'ORDER'  => ['name ASC'],
                'LIMIT'  => 20,
            ]);
            foreach ($rows as $row) {
                $entities[] = ['id' => (int)$row['id'], 'name' => (string)$row['name']];
            }
            echo json_encode(['success' => true, 'entities' => $entities], JSON_UNESCAPED_SLASHES);
            break;

        default:
            throw new RuntimeException('Unknown action: ' . $action);
    }
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => $e->getMessage()], JSON_UNESCAPED_SLASHES);
}

exit;
