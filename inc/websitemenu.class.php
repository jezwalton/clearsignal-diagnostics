<?php

class PluginClearsignaldiagWebsitemenu extends CommonGLPI {

    static function getTypeName($nb = 0) {
        return __('Website / SSL');
    }

    static function getMenuName() {
        return __('Website / SSL');
    }

    static function getMenuContent() {
        return [
            'title' => self::getMenuName(),
            'page'  => Plugin::getWebDir('clearsignaldiag', true) . '/front/website_diagnostic.php',
            'icon'  => 'ti ti-lock-check',
        ];
    }

    static function canView(): bool {
        return Session::haveRight('ticket', READ);
    }
}
