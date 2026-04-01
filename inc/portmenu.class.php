<?php

class PluginClearsignaldiagPortmenu extends CommonGLPI {

    static function getTypeName($nb = 0) {
        return __('Port Scanner');
    }

    static function getMenuName() {
        return __('Port Scanner');
    }

    static function getMenuContent() {
        return [
            'title' => self::getMenuName(),
            'page'  => Plugin::getWebDir('clearsignaldiag', true) . '/front/port_scanner.php',
            'icon'  => 'ti ti-plug',
        ];
    }

    static function canView(): bool {
        return Session::haveRight('ticket', READ);
    }
}
