<?php

class PluginClearsignaldiagDiagnosticRun {

    private const ALLOWED_CHECKS = [
        'ping',
        'traceroute',
        'forward_lookup',
        'reverse_lookup',
        'dns_diagnostic',
        'website_check',
        'mx_check',
        'spf_check',
        'dkim_check',
        'dmarc_check'
    ];

    public static function run(int $ticketId, string $target, array $checks, string $dkimSelector = ''): array {
        $ticket = new Ticket();
        if (!$ticket->getFromDB($ticketId)) {
            throw new RuntimeException('Ticket not found.');
        }

        $parsedTarget = PluginClearsignaldiagTargetParser::parse($target);
        if (!$parsedTarget['valid']) {
            throw new RuntimeException('Target is not a valid IP, hostname, domain, or URL.');
        }

        $cleanChecks = array_values(array_intersect(self::ALLOWED_CHECKS, $checks));
        if (count($cleanChecks) === 0) {
            throw new RuntimeException('No valid checks selected.');
        }

        $config = PluginClearsignaldiagConfig::getConfig();
        if ($dkimSelector === '') {
            $dkimSelector = (string)$config['default_selector'];
        }

        return PluginClearsignaldiagPythonBridge::run([
            'ticket_id'      => $ticketId,
            'target'         => $parsedTarget,
            'checks'         => $cleanChecks,
            'dkim_selector'  => $dkimSelector,
            'requested_by'   => Session::getLoginUserID(),
            'requested_at'   => date('c')
        ]);
    }
}
