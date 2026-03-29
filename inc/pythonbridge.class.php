<?php

class PluginClearsignaldiagPythonBridge {

    public static function run(array $payload): array {
        $config = PluginClearsignaldiagConfig::getConfig();
        $pluginDir = Plugin::getPhpDir('clearsignaldiag');

        $python = trim((string)$config['python_binary']);
        $workerRelative = trim((string)$config['worker_script']);
        $timeout = max(5, min(120, (int)$config['command_timeout']));

        // Validate python binary path - must not contain shell metacharacters
        if ($python === '' || preg_match('/[;&|`$<>]/', $python)) {
            throw new RuntimeException('Python binary path is invalid or contains disallowed characters.');
        }

        // Validate worker script path - must be relative, no directory traversal
        if ($workerRelative === '' || str_contains($workerRelative, '..') || preg_match('/[;&|`$<>]/', $workerRelative)) {
            throw new RuntimeException('Worker script path is invalid or contains disallowed characters.');
        }

        $script = realpath($pluginDir . '/' . ltrim($workerRelative, '/'));

        // Ensure script resolves to a real path within the plugin directory
        if ($script === false || !is_file($script)) {
            throw new RuntimeException(
                'Python worker script not found. Expected at: '
                . htmlspecialchars($pluginDir . '/' . $workerRelative, ENT_QUOTES, 'UTF-8')
            );
        }

        $realPluginDir = realpath($pluginDir);
        if ($realPluginDir === false || !str_starts_with($script, $realPluginDir)) {
            throw new RuntimeException('Worker script path resolves outside the plugin directory.');
        }

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $command = [
            $python,
            $script,
            '--json'
        ];

        $env = [
            'LC_ALL' => 'C',
            'LANG'   => 'C',
        ];

        // On Windows, inherit PATH so system commands (ping, tracert) are available
        if (PHP_OS_FAMILY === 'Windows') {
            $env['PATH'] = getenv('PATH') ?: '';
            $env['SystemRoot'] = getenv('SystemRoot') ?: 'C:\\Windows';
        } else {
            $env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
        }

        $process = proc_open($command, $descriptors, $pipes, $pluginDir, $env);

        if (!is_resource($process)) {
            throw new RuntimeException(
                'Could not start diagnostics worker. Verify the Python binary path in plugin configuration.'
            );
        }

        stream_set_blocking($pipes[1], true);
        stream_set_blocking($pipes[2], true);

        $jsonInput = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($jsonInput === false) {
            proc_terminate($process, 9);
            throw new RuntimeException('Failed to encode payload as JSON.');
        }

        fwrite($pipes[0], $jsonInput);
        fclose($pipes[0]);

        $start = time();
        $stdout = '';
        $stderr = '';

        do {
            $status = proc_get_status($process);
            $stdout .= stream_get_contents($pipes[1]);
            $stderr .= stream_get_contents($pipes[2]);

            if (!$status['running']) {
                break;
            }

            if ((time() - $start) > $timeout) {
                proc_terminate($process, 9);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($process);
                throw new RuntimeException(
                    'Diagnostics worker timed out after ' . $timeout . ' seconds. '
                    . 'You can increase the timeout in plugin configuration.'
                );
            }

            usleep(100000);
        } while (true);

        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = proc_close($process);

        if ($exitCode !== 0) {
            $errMsg = trim($stderr);
            if ($errMsg === '') {
                $errMsg = 'Worker exited with code ' . $exitCode . ' and no error output.';
            }
            throw new RuntimeException('Diagnostics worker failed: ' . $errMsg);
        }

        $decoded = json_decode($stdout, true);
        if (!is_array($decoded)) {
            throw new RuntimeException(
                'Diagnostics worker did not return valid JSON. '
                . 'Raw output length: ' . strlen($stdout) . ' bytes.'
            );
        }

        return $decoded;
    }
}
