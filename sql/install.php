<?php

function plugin_clearsignaldiag_install(): bool {
    global $DB;

    // ---- Config table ----
    $table = 'glpi_plugin_clearsignaldiag_configs';

    if (!$DB->tableExists($table)) {
        $query = "CREATE TABLE `$table` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `python_binary` varchar(255) NOT NULL DEFAULT '/usr/bin/python3',
            `worker_script` varchar(255) NOT NULL DEFAULT 'python/diagnostics_worker.py',
            `command_timeout` int NOT NULL DEFAULT 90,
            `default_selector` varchar(128) NOT NULL DEFAULT 'selector1',
            `allow_raw_output` tinyint NOT NULL DEFAULT 1,
            `enabled_checks` text DEFAULT NULL,
            PRIMARY KEY (`id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
        $DB->doQuery($query);
        $DB->insert($table, [
            'python_binary' => '/usr/bin/python3',
            'worker_script' => 'python/diagnostics_worker.py',
            'command_timeout' => 90,
            'default_selector' => 'selector1',
            'allow_raw_output' => 1,
            'enabled_checks' => json_encode([
                'ping', 'traceroute', 'forward_lookup', 'reverse_lookup',
                'dns_diagnostic', 'website_check', 'mx_check',
                'spf_check', 'dkim_check', 'dmarc_check'
            ]),
        ]);
    } else {
        if (!$DB->fieldExists($table, 'enabled_checks')) {
            $DB->doQuery("ALTER TABLE `$table` ADD `enabled_checks` text DEFAULT NULL");
        }
    }

    // ---- Entity domains table ----
    $domainTable = 'glpi_plugin_clearsignaldiag_entity_domains';

    if (!$DB->tableExists($domainTable)) {
        $DB->doQuery("CREATE TABLE `$domainTable` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `entities_id` int unsigned NOT NULL DEFAULT 0,
            `domain` varchar(255) NOT NULL,
            `is_primary` tinyint NOT NULL DEFAULT 0,
            `label` varchar(255) DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
            `date_mod` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (`id`),
            KEY `entities_id` (`entities_id`),
            KEY `domain` (`domain`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    }

    // ---- Health reports table ----
    $reportTable = 'glpi_plugin_clearsignaldiag_health_reports';

    if (!$DB->tableExists($reportTable)) {
        $DB->doQuery("CREATE TABLE `$reportTable` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `entities_id` int unsigned NOT NULL DEFAULT 0,
            `domain` varchar(255) NOT NULL,
            `status` varchar(10) NOT NULL DEFAULT 'ok',
            `summary` text DEFAULT NULL,
            `report_json` longtext DEFAULT NULL,
            `checks_run` int NOT NULL DEFAULT 0,
            `checks_ok` int NOT NULL DEFAULT 0,
            `checks_warn` int NOT NULL DEFAULT 0,
            `checks_fail` int NOT NULL DEFAULT 0,
            `users_id` int unsigned NOT NULL DEFAULT 0,
            `date_creation` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (`id`),
            KEY `entities_id` (`entities_id`),
            KEY `domain` (`domain`),
            KEY `date_creation` (`date_creation`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    }

    return true;
}
