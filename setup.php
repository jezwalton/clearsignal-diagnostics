<?php
define('PLUGIN_CLEARSIGNALDIAG_VERSION', '1.0.0');

function plugin_init_clearsignaldiag(): void {
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS['csrf_compliant']['clearsignaldiag'] = true;
    $PLUGIN_HOOKS['config_page']['clearsignaldiag'] = 'front/config.form.php';

    Plugin::registerClass(PluginClearsignaldiagConfig::class);
    Plugin::registerClass(PluginClearsignaldiagTickettab::class, [
        'addtabon' => [Ticket::class]
    ]);
    Plugin::registerClass(PluginClearsignaldiagMenu::class);
    Plugin::registerClass(PluginClearsignaldiagEmailmenu::class);
    Plugin::registerClass(PluginClearsignaldiagWebsitemenu::class);

    // Add menu entries under Tools
    if (Session::haveRight('ticket', READ)) {
        $PLUGIN_HOOKS['menu_toadd']['clearsignaldiag'] = [
            'tools' => ['PluginClearsignaldiagMenu', 'PluginClearsignaldiagEmailmenu', 'PluginClearsignaldiagWebsitemenu']
        ];
    }

    // Ensure hook functions are loadable for install/uninstall
    include_once(Plugin::getPhpDir('clearsignaldiag') . '/hook.php');
}

function plugin_version_clearsignaldiag(): array {
    return [
        'name'           => 'ClearSignal Diagnostics',
        'version'        => PLUGIN_CLEARSIGNALDIAG_VERSION,
        'author'         => 'System Force IT',
        'license'        => 'GPLv3+',
        'homepage'       => 'https://systemforce.co.uk',
        'requirements'   => [
            'glpi' => [
                'min' => '11.0.0',
                'max' => '11.9.99'
            ],
            'php' => [
                'min' => '8.1'
            ]
        ]
    ];
}

function plugin_clearsignaldiag_check_prerequisites(): bool {
    return version_compare(PHP_VERSION, '8.1.0', '>=');
}

function plugin_clearsignaldiag_check_config(bool $verbose = false): bool {
    return true;
}
