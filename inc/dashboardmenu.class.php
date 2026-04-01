<?php

class PluginClearsignaldiagDashboardmenu extends CommonGLPI {

    static function getTypeName($nb = 0) {
        return __('Health Dashboard');
    }

    static function getMenuName() {
        return __('Health Dashboard');
    }

    static function getMenuContent() {
        return [
            'title' => self::getMenuName(),
            'page'  => Plugin::getWebDir('clearsignaldiag', true) . '/front/dashboard.php',
            'icon'  => 'ti ti-dashboard',
        ];
    }

    static function canView(): bool {
        return Session::haveRight('ticket', READ);
    }
}
