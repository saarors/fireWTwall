<?php

namespace FireWTWall;

/**
 * Renders block responses and terminates the request.
 */
class Response
{
    /** Security headers added to every block response */
    private static array $securityHeaders = [
        'X-Content-Type-Options'       => 'nosniff',
        'X-Frame-Options'              => 'SAMEORIGIN',
        'X-XSS-Protection'             => '1; mode=block',
        'Referrer-Policy'              => 'strict-origin-when-cross-origin',
        'Cross-Origin-Opener-Policy'   => 'same-origin',
        'Cross-Origin-Resource-Policy' => 'same-origin',
        'Cache-Control'                => 'no-store',
    ];

    /**
     * Send a block response and exit.
     *
     * @param string $rule        Rule that triggered the block
     * @param int    $statusCode  HTTP status code (default 403)
     * @param string $type        'json' or 'html'
     */
    public static function block(string $rule, int $statusCode = 403, string $type = 'json'): void
    {
        if (headers_sent()) {
            exit;
        }

        http_response_code($statusCode);
        self::sendSecurityHeaders();

        if ($type === 'json') {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'blocked' => true,
                'rule'    => $rule,
                'message' => 'Request blocked by WAF',
            ]);
        } else {
            header('Content-Type: text/html; charset=utf-8');
            $safeRule = htmlspecialchars($rule, ENT_QUOTES, 'UTF-8');
            echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>403 Blocked</title>
<style>
body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;
     height:100vh;margin:0;background:#f4f4f4}
.box{text-align:center;padding:2rem;background:#fff;border-radius:8px;
     box-shadow:0 2px 8px rgba(0,0,0,.1)}
h1{color:#c0392b}code{background:#eee;padding:2px 6px;border-radius:3px}
</style></head>
<body><div class="box">
<h1>&#x1F6AB; Access Blocked</h1>
<p>Your request was blocked by the web application firewall.</p>
<p>Rule: <code>{$safeRule}</code></p>
</div></body></html>
HTML;
        }

        exit;
    }

    /** Send a Method Not Allowed response. */
    public static function methodNotAllowed(array $allowedMethods): void
    {
        if (!headers_sent()) {
            header('Allow: ' . implode(', ', $allowedMethods));
        }
        self::block('method-not-allowed', 405);
    }

    /** Send a Rate Limit Exceeded response. */
    public static function tooManyRequests(int $retryAfter, string $type = 'json'): void
    {
        if (!headers_sent()) {
            header('Retry-After: ' . $retryAfter);
        }
        http_response_code(429);
        self::sendSecurityHeaders();

        if ($type === 'json') {
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode([
                'blocked'    => true,
                'rule'       => 'rate-limit',
                'message'    => 'Too many requests',
                'retryAfter' => $retryAfter,
            ]);
        } else {
            echo '<h1>429 Too Many Requests</h1><p>Retry after ' . $retryAfter . ' seconds.</p>';
        }
        exit;
    }

    /**
     * Append security headers to all responses (called once per request
     * from WAF::run() for clean/passing requests).
     */
    public static function sendSecurityHeaders(): void
    {
        if (headers_sent()) return;
        foreach (self::$securityHeaders as $name => $value) {
            header($name . ': ' . $value);
        }
    }
}
