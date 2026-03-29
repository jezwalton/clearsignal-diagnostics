<?php

class PluginClearsignaldiagTickettab extends CommonGLPI {

    public static function getTabNameForItem(CommonGLPI $item, $withtemplate = 0): string {
        return ($item instanceof Ticket) ? __('Diagnostics') : '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool {
        if (!$item instanceof Ticket) {
            return false;
        }
        self::renderStandalone($item);
        return true;
    }

    public static function renderStandalone(Ticket $ticket): void {
        $ticketId = (int)$ticket->fields['id'];
        $config = PluginClearsignaldiagConfig::getConfig();
        include Plugin::getPhpDir('clearsignaldiag') . '/templates/ticket_tab.php';
    }
}
