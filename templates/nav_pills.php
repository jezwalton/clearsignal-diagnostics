<?php
/**
 * Shared nav pills — included by all diagnostic front pages.
 * Expects $pluginRoot to be set and $currentPage to identify the active pill.
 */
$currentPage = $currentPage ?? basename($_SERVER['SCRIPT_NAME'] ?? '');
$navItems = [
    ['page' => 'diagnostic.php',         'icon' => 'ti ti-world-search',       'label' => 'DNS'],
    ['page' => 'email_diagnostic.php',   'icon' => 'ti ti-mail-check',         'label' => 'Email'],
    ['page' => 'header_analyser.php',    'icon' => 'ti ti-mail-code',          'label' => 'Analyser'],
    ['page' => 'website_diagnostic.php', 'icon' => 'ti ti-lock-check',         'label' => 'Website'],
    ['page' => 'port_scanner.php',       'icon' => 'ti ti-plug',               'label' => 'Ports'],
    ['page' => 'health_check.php',       'icon' => 'ti ti-heart-rate-monitor', 'label' => 'Health Check'],
    ['page' => 'dashboard.php',          'icon' => 'ti ti-dashboard',          'label' => 'Dashboard'],
];
?>
<ul class="nav nav-pills mb-3">
<?php foreach ($navItems as $item): ?>
  <li class="nav-item"><a class="nav-link<?php echo $currentPage === $item['page'] ? ' active' : ''; ?>" href="<?php echo htmlspecialchars($pluginRoot . '/front/' . $item['page'], ENT_QUOTES, 'UTF-8'); ?>"><i class="<?php echo $item['icon']; ?> me-1"></i><?php echo $item['label']; ?></a></li>
<?php endforeach; ?>
</ul>
