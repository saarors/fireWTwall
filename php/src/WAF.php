<?php

namespace FireWTWall;

use FireWTWall\Detectors\SqlInjectionDetector;
use FireWTWall\Detectors\XssDetector;
use FireWTWall\Detectors\PathTraversalDetector;
use FireWTWall\Detectors\BotDetector;
use FireWTWall\Detectors\CommandInjectionDetector;
use FireWTWall\Detectors\HeaderInjectionDetector;
use FireWTWall\Detectors\SsrfDetector;
use FireWTWall\Detectors\XxeDetector;
use FireWTWall\Detectors\OpenRedirectDetector;
use FireWTWall\Detectors\MassAssignmentDetector;

/**
 * Core WAF orchestrator.
 *
 * Runs the check pipeline in order and either blocks or passes each request.
 * Requires PHP >= 8.0
 */
class WAF
{
    private array       $config;
    private Request     $request;
    private Logger      $logger;
    private IpFilter    $ipFilter;
    private RateLimiter $rateLimiter;
    private BotDetector $botDetector;

    private string  $requestId;
    private float   $startTime;

    public function __construct(array $config)
    {
        $this->config      = $config;
        $this->requestId   = bin2hex(random_bytes(8));
        $this->startTime   = microtime(true);
        $this->ipFilter    = new IpFilter($config['whitelist'] ?? [], $config['blacklist'] ?? []);
        $this->request     = new Request($config['trusted_proxies'] ?? []);
        $this->logger      = new Logger($config['log_path']);
        $this->rateLimiter = new RateLimiter($config['rate_limit']);
        $this->botDetector = new BotDetector(require __DIR__ . '/../config/bad-bots.php');
    }

    /**
     * Execute the WAF pipeline.
     * Returns without doing anything if the request is clean (security headers
     * are still added on clean pass).
     * Calls Response::block() (which exits) if the request must be blocked.
     */
    public function run(): void
    {
        $ip   = $this->request->getIp();
        $path = $this->request->getPath();

        // --- Bypass paths ---
        foreach ($this->config['bypass_paths'] as $bypassPath) {
            if (str_starts_with($path, $bypassPath)) {
                Response::sendSecurityHeaders();
                return;
            }
        }

        // --- 1. Request size ---
        $cl = $this->request->getContentLength();
        if ($cl > 0 && $cl > $this->config['max_body_size']) {
            $this->block('request-size', $ip, 'header', '', 'medium', 413);
        }

        // --- 2. HTTP method ---
        $method = $this->request->getMethod();
        if (!in_array($method, $this->config['allowed_methods'], true)) {
            $this->logger->logBlock($ip, $method, $path, 'method-not-allowed', '', '', 'medium',
                $this->request->getUserAgent());
            if ($this->config['mode'] !== 'log-only') {
                Response::methodNotAllowed($this->config['allowed_methods']);
            }
        }

        // --- 3. IP filter ---
        $ipResult = $this->ipFilter->check($ip);
        if ($ipResult === 'blacklist') {
            $this->block('ip-blacklist', $ip, '', '', 'high');
        }
        $trusted = ($ipResult === 'whitelist');

        if ($trusted) {
            Response::sendSecurityHeaders();
            return;
        }

        // --- 4. Rate limit ---
        $rl = $this->rateLimiter->check($ip);
        if (!$rl['allowed']) {
            $this->logger->logBlock($ip, $method, $path, 'rate-limit', '', '', 'medium',
                $this->request->getUserAgent());
            if ($this->config['mode'] !== 'log-only') {
                Response::tooManyRequests($rl['retryAfter'], $this->config['response_type']);
            }
        } else {
            @header('X-RateLimit-Limit: '     . $this->config['rate_limit']['max_requests']);
            @header('X-RateLimit-Remaining: ' . $rl['remaining']);
        }

        // --- 5. Bot detection ---
        $botHit = $this->botDetector->check($this->request->getUserAgent());
        if ($botHit !== null) {
            $this->block('bad-bot', $ip, 'user-agent', $botHit['matched'], 'high');
        }

        // --- 5a. SSRF ---
        $hit = SsrfDetector::scan($this->request, $this->config);
        if ($hit !== null) {
            $this->block($hit['rule'], $ip, $hit['source'], $hit['matched'], $hit['severity']);
        }

        // --- 5b. XXE ---
        $hit = XxeDetector::scan($this->request, $this->config);
        if ($hit !== null) {
            $this->block($hit['rule'], $ip, $hit['source'], $hit['matched'], $hit['severity']);
        }

        // --- 5c. Open redirect ---
        $hit = OpenRedirectDetector::scan($this->request, $this->config);
        if ($hit !== null) {
            $this->block($hit['rule'], $ip, $hit['source'], $hit['matched'], $hit['severity']);
        }

        // --- 5d. Mass assignment ---
        $hit = MassAssignmentDetector::scan($this->request, $this->config);
        if ($hit !== null) {
            $this->block($hit['rule'], $ip, $hit['source'], $hit['matched'], $hit['severity']);
        }

        // --- 6. Header injection (CRLF + host injection) ---
        $headerHit = HeaderInjectionDetector::scan(
            $this->request->getHeaders(),
            $this->request->getHeaders()['host'] ?? ''
        );
        if ($headerHit !== null) {
            $this->block($headerHit['rule'], $ip, $headerHit['source'], $headerHit['matched'],
                $headerHit['severity']);
        }

        // Collect decoded sources for pattern detectors
        $sources = [
            'query'   => $this->request->getQuery(),
            'body'    => $this->request->getBody(),
            'path'    => $path,
            'cookies' => $this->request->getCookies(),
        ];

        // --- 7. Path traversal ---
        $hit = PathTraversalDetector::scan($sources);
        if ($hit !== null) {
            $this->block($hit['rule'], $ip, $hit['source'], $hit['matched'], $hit['severity']);
        }

        // --- 8. Command injection ---
        $hit = CommandInjectionDetector::scan($sources);
        if ($hit !== null) {
            $this->block($hit['rule'], $ip, $hit['source'], $hit['matched'], $hit['severity']);
        }

        // --- 9. SQL injection ---
        $hit = SqlInjectionDetector::scan($sources);
        if ($hit !== null) {
            $this->block($hit['rule'], $ip, $hit['source'], $hit['matched'], $hit['severity']);
        }

        // --- 10. XSS ---
        $hit = XssDetector::scan($sources);
        if ($hit !== null) {
            $this->block($hit['rule'], $ip, $hit['source'], $hit['matched'], $hit['severity']);
        }

        // All checks passed
        Response::sendSecurityHeaders();

        if ($this->config['debug'] ?? false) {
            $durationMs = round((microtime(true) - $this->startTime) * 1000, 3);
            @header('X-WAF-RequestId: ' . $this->requestId);
            @header('X-WAF-Result: passed');
            @header('X-WAF-Time: '      . $durationMs . 'ms');

            $this->logger->logPass(
                $ip,
                $method,
                $path,
                $this->request->getUserAgent(),
                $this->requestId,
                $durationMs
            );
        }
    }

    // ------------------------------------------------------------------ //
    // Internal helpers
    // ------------------------------------------------------------------ //

    private function block(
        string $rule,
        string $ip,
        string $source   = '',
        string $matched  = '',
        string $severity = 'medium',
        int    $status   = 403
    ): void {
        $this->logger->logBlock(
            $ip,
            $this->request->getMethod(),
            $this->request->getPath(),
            $rule,
            $matched,
            $source,
            $severity,
            $this->request->getUserAgent()
        );

        if ($this->config['debug'] ?? false) {
            $durationMs = round((microtime(true) - $this->startTime) * 1000, 3);
            @header('X-WAF-RequestId: ' . $this->requestId);
            @header('X-WAF-Result: blocked');
            @header('X-WAF-Rule: '      . $rule);
            @header('X-WAF-Time: '      . $durationMs . 'ms');
        }

        if ($this->config['mode'] === 'log-only') return;

        Response::block($rule, $status, $this->config['response_type']);
        // Response::block() calls exit — execution stops here in reject mode.
    }
}
