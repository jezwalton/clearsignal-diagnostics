<?php

class PluginClearsignaldiagConfig extends CommonDBTM {

    public const ALL_CHECKS = [
        'ping'           => 'Ping',
        'traceroute'     => 'Traceroute',
        'forward_lookup' => 'Forward lookup (A/AAAA)',
        'reverse_lookup' => 'Reverse lookup (PTR)',
        'dns_diagnostic' => 'Advanced DNS diagnostic',
        'website_check'  => 'Website check (HTTP/TLS)',
        'mx_check'       => 'MX record check',
        'spf_check'      => 'SPF validation',
        'dkim_check'     => 'DKIM validation',
        'dmarc_check'    => 'DMARC validation',
    ];

    private static array $defaults = [
        'python_binary'    => '/usr/bin/python3',
        'worker_script'    => 'python/diagnostics_worker.py',
        'command_timeout'  => '90',
        'default_selector' => 'selector1',
        'allow_raw_output' => '1',
        'enabled_checks'   => null, // null = all enabled
    ];

    public static function getTypeName($nb = 0): string {
        return 'ClearSignal Diagnostics';
    }

    public static function getConfig(): array {
        global $DB;

        $table = self::getTable();
        if (!$DB->tableExists($table)) {
            return self::$defaults;
        }

        $row = $DB->request([
            'FROM' => $table,
            'LIMIT' => 1
        ])->current();

        if (!$row) {
            return self::$defaults;
        }

        $enabledRaw = $row['enabled_checks'] ?? null;
        $enabledChecks = is_string($enabledRaw) ? json_decode($enabledRaw, true) : null;
        if (!is_array($enabledChecks)) {
            $enabledChecks = array_keys(self::ALL_CHECKS);
        }

        return array_merge(self::$defaults, [
            'id'               => (string)($row['id'] ?? 0),
            'python_binary'    => (string)($row['python_binary'] ?? self::$defaults['python_binary']),
            'worker_script'    => (string)($row['worker_script'] ?? self::$defaults['worker_script']),
            'command_timeout'  => (string)($row['command_timeout'] ?? self::$defaults['command_timeout']),
            'default_selector' => (string)($row['default_selector'] ?? self::$defaults['default_selector']),
            'allow_raw_output' => (string)($row['allow_raw_output'] ?? self::$defaults['allow_raw_output']),
            'enabled_checks'   => $enabledChecks,
        ]);
    }

    public function saveFromPost(array $post): void {
        global $DB;

        $table = self::getTable();
        $current = self::getConfig();

        $postedChecks = $post['enabled_checks'] ?? [];
        if (!is_array($postedChecks)) {
            $postedChecks = [];
        }
        $validChecks = array_values(array_intersect($postedChecks, array_keys(self::ALL_CHECKS)));

        $input = [
            'python_binary'    => trim((string)($post['python_binary'] ?? self::$defaults['python_binary'])),
            'worker_script'    => trim((string)($post['worker_script'] ?? self::$defaults['worker_script'])),
            'command_timeout'  => max(5, min(300, (int)($post['command_timeout'] ?? self::$defaults['command_timeout']))),
            'default_selector' => trim((string)($post['default_selector'] ?? self::$defaults['default_selector'])),
            'allow_raw_output' => isset($post['allow_raw_output']) ? 1 : 0,
            'enabled_checks'   => json_encode($validChecks),
        ];

        if (!$DB->tableExists($table)) {
            throw new RuntimeException('Plugin table missing. Reinstall the plugin.');
        }

        if (!empty($current['id'])) {
            $DB->update($table, $input, ['id' => (int)$current['id']]);
        } else {
            $DB->insert($table, $input);
        }

        Session::addMessageAfterRedirect(__('Configuration saved.'));
    }

    public function showForm($ID, array $options = []): bool {
        $config = self::getConfig();

        echo "<form method='post' action='" . htmlspecialchars($_SERVER['PHP_SELF'] ?? '', ENT_QUOTES, 'UTF-8') . "'>";
        echo "<div class='card'><div class='card-body'>";
        echo "<h2>ClearSignal Diagnostics</h2>";
        echo "<p>Configure the Python worker path and runtime behaviour.</p>";

        echo "<div class='mb-3'>";
        echo "<label><strong>Python binary</strong></label>";
        echo "<input class='form-control' type='text' name='python_binary' value='" . htmlspecialchars($config['python_binary'], ENT_QUOTES, 'UTF-8') . "'>";
        echo "</div>";

        echo "<div class='mb-3'>";
        echo "<label><strong>Worker script (relative to plugin root)</strong></label>";
        echo "<input class='form-control' type='text' name='worker_script' value='" . htmlspecialchars($config['worker_script'], ENT_QUOTES, 'UTF-8') . "'>";
        echo "</div>";

        echo "<div class='mb-3'>";
        echo "<label><strong>Command timeout (seconds)</strong></label>";
        echo "<input class='form-control' type='number' min='5' max='300' name='command_timeout' value='" . htmlspecialchars((string)$config['command_timeout'], ENT_QUOTES, 'UTF-8') . "'>";
        echo "</div>";

        echo "<div class='mb-3'>";
        echo "<label><strong>Default DKIM selector</strong></label>";
        echo "<input class='form-control' type='text' name='default_selector' value='" . htmlspecialchars($config['default_selector'], ENT_QUOTES, 'UTF-8') . "'>";
        echo "</div>";

        echo "<div class='form-check mb-3'>";
        echo "<input class='form-check-input' type='checkbox' name='allow_raw_output' value='1' " . ((int)$config['allow_raw_output'] === 1 ? "checked" : "") . ">";
        echo "<label class='form-check-label'><strong>Show raw technical output in the ticket tab</strong></label>";
        echo "</div>";

        echo "<div class='mb-3'>";
        echo "<label><strong>Enabled checks</strong></label>";
        echo "<div class='row'>";
        $enabledChecks = $config['enabled_checks'] ?? array_keys(self::ALL_CHECKS);
        foreach (self::ALL_CHECKS as $key => $label) {
            $checked = in_array($key, $enabledChecks, true) ? 'checked' : '';
            echo "<div class='col-md-4 mb-1'>";
            echo "<label style='display:block'><input type='checkbox' name='enabled_checks[]' value='" . htmlspecialchars($key, ENT_QUOTES, 'UTF-8') . "' {$checked}> " . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . "</label>";
            echo "</div>";
        }
        echo "</div></div>";

        echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
        echo Html::submit(_sx('button', 'Save'));
        echo "</div></div>";
        echo "</form>";

        return true;
    }

    public static function getTable($classname = null): string {
        return 'glpi_plugin_clearsignaldiag_configs';
    }
}
