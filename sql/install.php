<?php

function plugin_clearsignaldiag_install(): bool {
    global $DB;

    $table = 'glpi_plugin_clearsignaldiag_configs';

    if (!$DB->tableExists($table)) {
        $query = "CREATE TABLE `$table` (
            `id` int unsigned NOT NULL AUTO_INCREMENT,
            `python_binary` varchar(255) NOT NULL DEFAULT '/usr/bin/python3',
            `worker_script` varchar(255) NOT NULL DEFAULT 'python/diagnostics_worker.py',
            `command_timeout` int NOT NULL DEFAULT 20,
            `default_selector` varchar(128) NOT NULL DEFAULT 'selector1',
            `allow_raw_output` tinyint NOT NULL DEFAULT 1,
            `enabled_checks` text DEFAULT NULL,
            PRIMARY KEY (`id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
        $DB->doQuery($query);
        $DB->insert($table, [
            'python_binary' => '/usr/bin/python3',
            'worker_script' => 'python/diagnostics_worker.py',
            'command_timeout' => 20,
            'default_selector' => 'selector1',
            'allow_raw_output' => 1,
            'enabled_checks' => json_encode([
                'ping', 'traceroute', 'forward_lookup', 'reverse_lookup',
                'dns_diagnostic', 'website_check', 'mx_check',
                'spf_check', 'dkim_check', 'dmarc_check'
            ]),
        ]);
    } else {
        // Migration: add enabled_checks column if missing
        if (!$DB->fieldExists($table, 'enabled_checks')) {
            $DB->doQuery("ALTER TABLE `$table` ADD `enabled_checks` text DEFAULT NULL");
        }
    }

    return true;
}
