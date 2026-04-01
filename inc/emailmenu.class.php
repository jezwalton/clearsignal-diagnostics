<?php

class PluginClearsignaldiagEmailmenu extends CommonGLPI {

    static function getTypeName($nb = 0) {
        return __('Email Diagnostic');
    }

    static function getMenuName() {
        return __('Email Diagnostic');
    }

    static function getMenuContent() {
        return [
            'title' => self::getMenuName(),
            'page'  => Plugin::getWebDir('clearsignaldiag', true) . '/front/email_diagnostic.php',
            'icon'  => 'ti ti-mail-check',
        ];
    }

    static function canView(): bool {
        return Session::haveRight('ticket', READ);
    }
}
