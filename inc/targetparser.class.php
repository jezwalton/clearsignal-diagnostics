<?php

class PluginClearsignaldiagTargetParser {

    public static function parse(string $target): array {
        $target = trim($target);

        $result = [
            'input'  => $target,
            'valid'  => false,
            'type'   => 'unknown',
            'host'   => null,
            'domain' => null,
            'ip'     => null,
            'url'    => null,
        ];

        if ($target === '') {
            return $result;
        }

        if (filter_var($target, FILTER_VALIDATE_IP)) {
            $result['valid'] = true;
            $result['type'] = 'ip';
            $result['ip'] = $target;
            return $result;
        }

        if (filter_var($target, FILTER_VALIDATE_URL)) {
            $host = parse_url($target, PHP_URL_HOST);
            if ($host) {
                $result['valid'] = true;
                $result['type'] = 'url';
                $result['url'] = $target;
                $result['host'] = $host;
                $result['domain'] = $host;
            }
            return $result;
        }

        if (preg_match('/^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$/', $target) === 1 && str_contains($target, '.')) {
            $result['valid'] = true;
            $result['type'] = 'host';
            $result['host'] = strtolower($target);
            $result['domain'] = strtolower($target);
            return $result;
        }

        return $result;
    }
}
