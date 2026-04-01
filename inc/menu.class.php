<?php

class PluginClearsignaldiagMenu extends CommonGLPI {

    static function getTypeName($nb = 0) {
        return __('ClearSignal Diagnostics');
    }

    static function getMenuName() {
        return __('ClearSignal Diagnostics');
    }

    static function getMenuContent() {
        $menu = [
            'title' => self::getMenuName(),
            'page'  => Plugin::getWebDir('clearsignaldiag', true) . '/front/diagnostic.php',
            'icon'  => 'ti ti-stethoscope',
        ];

        $menu['options']['dns'] = [
            'title' => __('DNS Diagnostic'),
            'page'  => Plugin::getWebDir('clearsignaldiag', true) . '/front/diagnostic.php',
            'icon'  => 'ti ti-world-search',
        ];

        $menu['options']['email'] = [
            'title' => __('Email Diagnostic'),
            'page'  => Plugin::getWebDir('clearsignaldiag', true) . '/front/email_diagnostic.php',
            'icon'  => 'ti ti-mail-check',
        ];

        return $menu;
    }

    static function canView(): bool {
        return Session::haveRight('ticket', READ);
    }
}
