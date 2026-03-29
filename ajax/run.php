<?php
include('../../../inc/includes.php');

// Ensure clean output for JSON response
while (ob_get_level()) {
    ob_end_clean();
}
header('Content-Type: application/json; charset=UTF-8');

Session::checkLoginUser();

try {
    $ticketId = (int)($_POST['tickets_id'] ?? 0);
    $target = trim((string)($_POST['target'] ?? ''));
    $checks = $_POST['checks'] ?? [];
    $dkimSelector = trim((string)($_POST['dkim_selector'] ?? ''));

    if ($ticketId <= 0) {
        throw new RuntimeException('Missing or invalid ticket ID.');
    }

    if ($target === '') {
        throw new RuntimeException('Target is required.');
    }

    if (!is_array($checks) || count($checks) === 0) {
        throw new RuntimeException('Select at least one check.');
    }

    $ticket = new Ticket();
    if (!$ticket->getFromDB($ticketId)) {
        throw new RuntimeException('Ticket not found.');
    }
    if (!$ticket->canViewItem()) {
        throw new RuntimeException('You do not have permission to view this ticket.');
    }

    $result = PluginClearsignaldiagDiagnosticRun::run($ticketId, $target, $checks, $dkimSelector);

    echo json_encode([
        'success' => true,
        'data'    => $result
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

exit;
