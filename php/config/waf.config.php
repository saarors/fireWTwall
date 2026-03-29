<?php

return [
    // Permitted HTTP methods — anything else → 405
    'allowed_methods' => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],

    // Maximum Content-Length in bytes (default: 10 MB)
    'max_body_size' => 10 * 1024 * 1024,

    // Rate limiting
    'rate_limit' => [
        'window_sec'       => 60,    // sliding window in seconds
        'max_requests'     => 100,   // requests allowed per window
        'block_duration_sec' => 600, // block duration in seconds (10 min)
    ],

    // IPs / CIDR ranges that bypass all checks (never blocked)
    'whitelist' => [],

    // IPs / CIDR ranges that are always blocked
    'blacklist' => [],

    // URL paths that skip all WAF checks (exact prefix match)
    'bypass_paths' => ['/health', '/ping'],

    // Trusted reverse-proxy IPs — enables X-Forwarded-For parsing
    'trusted_proxies' => [],

    // 'reject'   → send 403 and exit
    // 'log-only' → log but let request through
    'mode' => 'reject',

    // Log file path (must be writable by web server; should NOT be web-accessible)
    'log_path' => __DIR__ . '/../logs/waf.log',

    // Block response format: 'json' or 'html'
    'response_type' => 'json',
];
