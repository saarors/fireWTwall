<?php

return [
    // DDoS protection
    'ddos' => [
        'max_url_length'    => 2048,
        'max_header_count'  => 100,
        'max_header_size'   => 8192,
        'burst' => [
            'window_sec'         => 1,
            'max_requests'       => 20,
            'block_duration_sec' => 60,
        ],
        'global' => [
            'window_sec'   => 1,
            'max_requests' => 500,
        ],
        'fingerprint' => [
            'window_sec'         => 10,
            'max_requests'       => 50,
            'block_duration_sec' => 60,
        ],
        'path_flood' => [
            'window_sec'   => 5,
            'max_requests' => 200,
        ],
        'tarpit' => [
            'enabled'  => false,
            'delay_ms' => 2000,
        ],
    ],

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

    // Debug mode: log every request (pass + block) and add X-WAF-* response headers.
    // Never enable in production — exposes internal rule names in headers.
    'debug' => false,
];
