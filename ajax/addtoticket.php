<?php
include('../../../inc/includes.php');

Session::checkLoginUser();
header('Content-Type: application/json');

try {
    Session::checkCSRF($_POST);

    $ticketId = (int)($_POST['tickets_id'] ?? 0);
    $summary = trim((string)($_POST['summary'] ?? ''));

    if ($ticketId <= 0) {
        throw new RuntimeException('Invalid ticket ID.');
    }

    if ($summary === '') {
        throw new RuntimeException('No summary supplied.');
    }

    $ticket = new Ticket();
    if (!$ticket->getFromDB($ticketId)) {
        throw new RuntimeException('Ticket not found.');
    }

    // Check the user has follow-up rights on this ticket
    if (!$ticket->canAddFollowups()) {
        throw new RuntimeException('You do not have permission to add follow-ups to this ticket.');
    }

    // Wrap plain-text summary in <pre> for GLPI's HTML follow-up field
    $htmlContent = '<pre style="white-space:pre-wrap; font-family:monospace; font-size:0.9em;">'
        . htmlspecialchars($summary, ENT_QUOTES, 'UTF-8')
        . '</pre>';

    $followup = new ITILFollowup();
    $followupId = $followup->add([
        'items_id'   => $ticketId,
        'itemtype'   => Ticket::class,
        'content'    => $htmlContent,
        'is_private' => 1,
        'users_id'   => Session::getLoginUserID()
    ]);

    if (!$followupId) {
        throw new RuntimeException('Failed to add follow-up.');
    }

    echo json_encode([
        'success' => true,
        'followup_id' => $followupId
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}
