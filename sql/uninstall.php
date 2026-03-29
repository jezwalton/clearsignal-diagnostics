<?php

function plugin_clearsignaldiag_uninstall(): bool {
    global $DB;
    $table = 'glpi_plugin_clearsignaldiag_configs';
    if ($DB->tableExists($table)) {
        $DB->doQuery("DROP TABLE `$table`");
    }
    return true;
}
