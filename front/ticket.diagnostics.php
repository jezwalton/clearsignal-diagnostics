<?php
include('../../../inc/includes.php');
Session::checkLoginUser();

$ticket = new Ticket();
if (!$ticket->getFromDB((int)($_GET['tickets_id'] ?? 0))) {
    Html::displayErrorAndDie(__('Ticket not found'));
}

Html::header(__('Diagnostics'), $_SERVER['PHP_SELF'], 'helpdesk', 'ticket');
PluginClearsignaldiagTickettab::renderStandalone($ticket);
Html::footer();
