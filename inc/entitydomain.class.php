<?php

class PluginClearsignaldiagEntitydomain extends CommonDBTM {

    public static function getTable($classname = null): string {
        return 'glpi_plugin_clearsignaldiag_entity_domains';
    }

    public static function getTypeName($nb = 0): string {
        return 'Entity Domains';
    }

    /**
     * Get all domains for an entity.
     */
    public static function getDomainsForEntity(int $entityId): array {
        global $DB;

        $table = self::getTable();
        if (!$DB->tableExists($table)) {
            return [];
        }

        $results = [];
        $rows = $DB->request([
            'FROM'  => $table,
            'WHERE' => ['entities_id' => $entityId],
            'ORDER' => ['is_primary DESC', 'domain ASC'],
        ]);

        foreach ($rows as $row) {
            $results[] = [
                'id'         => (int)$row['id'],
                'entities_id'=> (int)$row['entities_id'],
                'domain'     => (string)$row['domain'],
                'is_primary' => (int)$row['is_primary'],
                'label'      => (string)($row['label'] ?? ''),
            ];
        }
        return $results;
    }

    /**
     * Add a domain to an entity.
     */
    public static function addDomain(int $entityId, string $domain, string $label = '', bool $isPrimary = false): int {
        global $DB;

        $table = self::getTable();
        $domain = strtolower(trim($domain));

        if ($domain === '') {
            throw new RuntimeException('Domain cannot be empty.');
        }

        // Check for duplicate
        $existing = $DB->request([
            'FROM'  => $table,
            'WHERE' => ['entities_id' => $entityId, 'domain' => $domain],
            'LIMIT' => 1,
        ]);
        if ($existing->count() > 0) {
            throw new RuntimeException('Domain already registered for this entity.');
        }

        // If setting as primary, clear other primaries
        if ($isPrimary) {
            $DB->update($table, ['is_primary' => 0], ['entities_id' => $entityId]);
        }

        $DB->insert($table, [
            'entities_id' => $entityId,
            'domain'      => $domain,
            'label'       => $label,
            'is_primary'  => $isPrimary ? 1 : 0,
        ]);

        return $DB->insertId();
    }

    /**
     * Remove a domain.
     */
    public static function removeDomain(int $domainId): bool {
        global $DB;
        return $DB->delete(self::getTable(), ['id' => $domainId]);
    }

    /**
     * Store a health report.
     */
    public static function storeReport(int $entityId, string $domain, array $reportData, int $userId): int {
        global $DB;

        $checks = $reportData['checks'] ?? [];
        $ok = count(array_filter($checks, fn($c) => ($c['status'] ?? '') === 'ok'));
        $warn = count(array_filter($checks, fn($c) => ($c['status'] ?? '') === 'warn'));
        $fail = count(array_filter($checks, fn($c) => ($c['status'] ?? '') === 'fail'));
        $overall = $fail > 0 ? 'fail' : ($warn > 0 ? 'warn' : 'ok');

        // Build text summary
        $summaryParts = [];
        foreach ($checks as $c) {
            $summaryParts[] = '[' . strtoupper($c['status'] ?? '?') . '] ' . ($c['name'] ?? '') . ': ' . ($c['summary'] ?? '');
        }

        $DB->insert('glpi_plugin_clearsignaldiag_health_reports', [
            'entities_id'  => $entityId,
            'domain'       => $domain,
            'status'       => $overall,
            'summary'      => implode("\n", $summaryParts),
            'report_json'  => json_encode($reportData, JSON_UNESCAPED_SLASHES),
            'checks_run'   => count($checks),
            'checks_ok'    => $ok,
            'checks_warn'  => $warn,
            'checks_fail'  => $fail,
            'users_id'     => $userId,
        ]);

        return $DB->insertId();
    }

    /**
     * Get recent reports for an entity.
     */
    public static function getReports(int $entityId, int $limit = 20): array {
        global $DB;

        $table = 'glpi_plugin_clearsignaldiag_health_reports';
        if (!$DB->tableExists($table)) {
            return [];
        }

        $results = [];
        $rows = $DB->request([
            'FROM'  => $table,
            'WHERE' => ['entities_id' => $entityId],
            'ORDER' => ['date_creation DESC'],
            'LIMIT' => $limit,
        ]);

        foreach ($rows as $row) {
            $results[] = [
                'id'            => (int)$row['id'],
                'domain'        => (string)$row['domain'],
                'status'        => (string)$row['status'],
                'summary'       => (string)($row['summary'] ?? ''),
                'checks_run'    => (int)$row['checks_run'],
                'checks_ok'     => (int)$row['checks_ok'],
                'checks_warn'   => (int)$row['checks_warn'],
                'checks_fail'   => (int)$row['checks_fail'],
                'users_id'      => (int)$row['users_id'],
                'date_creation' => (string)$row['date_creation'],
            ];
        }
        return $results;
    }
}
