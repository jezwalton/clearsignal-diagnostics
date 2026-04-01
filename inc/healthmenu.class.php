<?php

class PluginClearsignaldiagHealthmenu extends CommonGLPI {

    static function getTypeName($nb = 0) {
        return __('Health Check');
    }

    static function getMenuName() {
        return __('Health Check');
    }

    static function getMenuContent() {
        return [
            'title' => self::getMenuName(),
            'page'  => Plugin::getWebDir('clearsignaldiag', true) . '/front/health_check.php',
            'icon'  => 'ti ti-heart-rate-monitor',
        ];
    }

    static function canView(): bool {
        return Session::haveRight('ticket', READ);
    }
}
