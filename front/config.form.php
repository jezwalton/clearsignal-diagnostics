<?php
include('../../../inc/includes.php');

Session::checkRight('config', READ);

$config = new PluginClearsignaldiagConfig();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    Session::checkRight('config', UPDATE);
    Html::header(__('ClearSignal Diagnostics Configuration'), $_SERVER['PHP_SELF'], 'config', 'plugins');
    $config->saveFromPost($_POST);
    Html::back();
    Html::footer();
    exit;
}

Html::header(__('ClearSignal Diagnostics Configuration'), $_SERVER['PHP_SELF'], 'config', 'plugins');
$config->showForm(1);
Html::footer();
