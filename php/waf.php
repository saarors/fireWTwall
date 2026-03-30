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
// Autoload — Composer if available, otherwise built-in PSR-4 loader
// ------------------------------------------------------------------ //
// Composer autoloader may be at repo root (installed via `composer require`)
// or inside php/ (local `composer install` in php/ directory)
$_waf_composer = file_exists(__DIR__ . '/../vendor/autoload.php')
    ? __DIR__ . '/../vendor/autoload.php'
    : __DIR__ . '/vendor/autoload.php';

if (file_exists($_waf_composer)) {
    require_once $_waf_composer;
} else {
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
}
unset($_waf_composer);

// ------------------------------------------------------------------ //
// Load config & run
// ------------------------------------------------------------------ //
$wafConfig = require __DIR__ . '/config/waf.config.php';

$waf = new \FireWTWall\WAF($wafConfig);
$waf->run();

// If we reach here, the request passed all WAF checks.
// PHP continues executing the originally requested script.
