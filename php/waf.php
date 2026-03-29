<?php

/**
 * fireWTwall — PHP Web Application Firewall
 *
 * This file is meant to be loaded via php.ini's auto_prepend_file directive,
 * or via .htaccess:
 *
 *   php_value auto_prepend_file "/absolute/path/to/waf.php"
 *
 * It will then execute before EVERY PHP script in the directory.
 */

declare(strict_types=1);

// ------------------------------------------------------------------ //
// Autoload all classes (no Composer required)
// ------------------------------------------------------------------ //
spl_autoload_register(function (string $class): void {
    // Map  FireWTWall\Foo\Bar  →  src/Foo/Bar.php
    $prefix = 'FireWTWall\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) return;

    $relative = str_replace('\\', DIRECTORY_SEPARATOR, substr($class, strlen($prefix)));
    $file     = __DIR__ . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . $relative . '.php';

    if (file_exists($file)) {
        require_once $file;
    }
});

// ------------------------------------------------------------------ //
// Load config & run
// ------------------------------------------------------------------ //
$wafConfig = require __DIR__ . '/config/waf.config.php';

$waf = new \FireWTWall\WAF($wafConfig);
$waf->run();

// If we reach here, the request passed all WAF checks.
// PHP continues executing the originally requested script.
