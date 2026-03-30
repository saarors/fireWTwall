<?php

namespace FireWTWall;

/**
 * Layer-7 DDoS protection.
 *
 * Equivalent to nodejs/middleware/ddos.js.
 *
 * Storage strategy:
 *  - APCu is used when available (shared across FPM workers, TTL-based expiry).
 *  - If APCu is absent, static class properties are used as a per-process
 *    in-memory fallback (resets per request in standard FPM — still useful
 *    as a basic guard for single-process setups such as PHP built-in server).
 *
 * Requires PHP >= 8.0
 */
class DdosProtection
{
    // -----------------------------------------------------------------------
    // Static fallback stores (used only when APCu is unavailable)
    // -----------------------------------------------------------------------

    /** @var array<string, array{count:int, windowStart:float, blockedUntil:float|null, blockCount:int}> */
    private static array $burstStore = [];

    /** @var array<string, array{count:int, windowStart:float, blockedUntil:float|null}> */
    private static array $fpStore = [];

    /** @var array<string, array{count:int, windowStart:float}> */
    private static array $pathStore = [];

    /** @var array{count:int, windowStart:float} */
    private static array $globalCounter = ['count' => 0, 'windowStart' => 0.0];

    // -----------------------------------------------------------------------
    // Entry point
    // -----------------------------------------------------------------------

    /**
     * Run all DDoS protection layers.
     * Calls Response::block() and exits if a layer fires in reject mode.
     *
     * @param Request $request
     * @param array   $config   Merged WAF config
     */
    public static function run(Request $request, array $config): void
    {
        $ddos = $config['ddos'] ?? [];

        $maxUrlLength   = (int)($ddos['max_url_length']   ?? 2048);
        $maxHeaderCount = (int)($ddos['max_header_count'] ?? 100);
        $maxHeaderSize  = (int)($ddos['max_header_size']  ?? 8192);

        $burstWindowSec    = (int)($ddos['burst']['window_sec']          ?? 1);
        $burstMaxRequests  = (int)($ddos['burst']['max_requests']        ?? 20);
        $burstBlockSec     = (int)($ddos['burst']['block_duration_sec']  ?? 60);

        $globalWindowSec   = (int)($ddos['global']['window_sec']   ?? 1);
        $globalMaxRequests = (int)($ddos['global']['max_requests'] ?? 500);

        $fpWindowSec   = (int)($ddos['fingerprint']['window_sec']         ?? 10);
        $fpMaxRequests = (int)($ddos['fingerprint']['max_requests']       ?? 50);
        $fpBlockSec    = (int)($ddos['fingerprint']['block_duration_sec'] ?? 60);

        $pathWindowSec   = (int)($ddos['path_flood']['window_sec']   ?? 5);
        $pathMaxRequests = (int)($ddos['path_flood']['max_requests'] ?? 200);

        $tarpitEnabled = (bool)($ddos['tarpit']['enabled'] ?? false);
        $tarpitDelayMs = (int)($ddos['tarpit']['delay_ms'] ?? 2000);

        $useApcu = function_exists('apcu_fetch');
        $ip      = $request->getIp();
        $path    = $request->getPath();
        $ua      = $request->getUserAgent();
        $now     = microtime(true);

        // ------------------------------------------------------------------
        // Layer 1 — URL length guard
        // ------------------------------------------------------------------
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        if (strlen($uri) > $maxUrlLength) {
            self::block($request, $config, 'ddos-url-length', 414, 'URI Too Long');
        }

        // ------------------------------------------------------------------
        // Layer 2 — Header count guard
        // ------------------------------------------------------------------
        $headerCount = count(array_filter(
            array_keys($_SERVER),
            static fn(string $k): bool => str_starts_with($k, 'HTTP_')
        ));
        if ($headerCount > $maxHeaderCount) {
            self::block($request, $config, 'ddos-header-count', 431, 'Too many request headers');
        }

        // ------------------------------------------------------------------
        // Layer 3 — Header size guard
        // ------------------------------------------------------------------
        foreach ($_SERVER as $key => $value) {
            if (
                str_starts_with((string)$key, 'HTTP_') &&
                strlen((string)$value) > $maxHeaderSize
            ) {
                self::block($request, $config, 'ddos-header-size', 431, 'Request header field too large');
            }
        }

        // ------------------------------------------------------------------
        // Layer 4 — Burst rate limiter (per-IP, short window)
        // ------------------------------------------------------------------
        if ($useApcu) {
            $burstKey = 'waf_burst_' . md5($ip);
            $blockKey = 'waf_burst_block_' . md5($ip);
            $bcKey    = 'waf_burst_bc_' . md5($ip);   // block-count key

            try {
                // Check if IP is currently blocked
                if (apcu_exists($blockKey)) {
                    $blockCount = (int)(apcu_fetch($bcKey) ?: 0);
                    // Tarpitting: delay repeat offenders
                    if ($tarpitEnabled && $blockCount > 3) {
                        usleep($tarpitDelayMs * 1000);
                    }
                    self::block($request, $config, 'ddos-burst', 429, 'Burst rate limit exceeded');
                }

                // Increment or create burst counter
                $count = apcu_inc($burstKey, 1, $success);
                if (!$success) {
                    apcu_store($burstKey, 1, $burstWindowSec);
                    $count = 1;
                }

                if ($count > $burstMaxRequests) {
                    apcu_store($blockKey, 1, $burstBlockSec);
                    $newBc = (int)(apcu_fetch($bcKey) ?: 0) + 1;
                    apcu_store($bcKey, $newBc, $burstBlockSec + 60);
                    self::block($request, $config, 'ddos-burst', 429, 'Burst rate limit exceeded');
                }
            } catch (\Throwable) {
                // APCu error — skip layer gracefully
            }
        } else {
            // Static fallback
            $bEntry = self::$burstStore[$ip] ?? null;

            if ($bEntry !== null && $bEntry['blockedUntil'] !== null && $now < $bEntry['blockedUntil']) {
                if ($tarpitEnabled && ($bEntry['blockCount'] ?? 0) > 3) {
                    usleep($tarpitDelayMs * 1000);
                }
                self::block($request, $config, 'ddos-burst', 429, 'Burst rate limit exceeded');
            }

            if ($bEntry === null || ($now - $bEntry['windowStart']) >= $burstWindowSec) {
                self::$burstStore[$ip] = [
                    'count'       => 1,
                    'windowStart' => $now,
                    'blockedUntil' => null,
                    'blockCount'  => $bEntry['blockCount'] ?? 0,
                ];
            } else {
                self::$burstStore[$ip]['count']++;
            }

            $bEntry = self::$burstStore[$ip];
            if ($bEntry['count'] > $burstMaxRequests) {
                self::$burstStore[$ip]['blockedUntil'] = $now + $burstBlockSec;
                self::$burstStore[$ip]['blockCount']   = ($bEntry['blockCount'] ?? 0) + 1;
                self::block($request, $config, 'ddos-burst', 429, 'Burst rate limit exceeded');
            }
        }

        // ------------------------------------------------------------------
        // Layer 5 — Global rate limiter (all IPs combined)
        // ------------------------------------------------------------------
        if ($useApcu) {
            try {
                $gCount = apcu_inc('waf_global_count', 1, $success);
                if (!$success) {
                    apcu_store('waf_global_count', 1, $globalWindowSec);
                    $gCount = 1;
                }
                if ($gCount > $globalMaxRequests) {
                    self::block($request, $config, 'ddos-global-flood', 503, 'Service temporarily unavailable');
                }
            } catch (\Throwable) {
                // Skip gracefully
            }
        } else {
            if (self::$globalCounter['windowStart'] === 0.0 ||
                ($now - self::$globalCounter['windowStart']) >= $globalWindowSec) {
                self::$globalCounter = ['count' => 1, 'windowStart' => $now];
            } else {
                self::$globalCounter['count']++;
            }
            if (self::$globalCounter['count'] > $globalMaxRequests) {
                self::block($request, $config, 'ddos-global-flood', 503, 'Service temporarily unavailable');
            }
        }

        // ------------------------------------------------------------------
        // Layer 6 — Request fingerprint flood detection
        // ------------------------------------------------------------------
        $fpRaw = $ip . "\x00" . $ua . "\x00" . $path;
        $fpHash = md5($fpRaw);

        if ($useApcu) {
            $fpKey      = 'waf_fp_' . $fpHash;
            $fpBlockKey = 'waf_fp_block_' . $fpHash;

            try {
                if (apcu_exists($fpBlockKey)) {
                    self::block($request, $config, 'ddos-fingerprint-flood', 429, 'Request fingerprint flood detected');
                }

                $fpCount = apcu_inc($fpKey, 1, $success);
                if (!$success) {
                    apcu_store($fpKey, 1, $fpWindowSec);
                    $fpCount = 1;
                }

                if ($fpCount > $fpMaxRequests) {
                    apcu_store($fpBlockKey, 1, $fpBlockSec);
                    self::block($request, $config, 'ddos-fingerprint-flood', 429, 'Request fingerprint flood detected');
                }
            } catch (\Throwable) {
                // Skip gracefully
            }
        } else {
            $fpEntry = self::$fpStore[$fpHash] ?? null;

            if ($fpEntry !== null && $fpEntry['blockedUntil'] !== null && $now < $fpEntry['blockedUntil']) {
                self::block($request, $config, 'ddos-fingerprint-flood', 429, 'Request fingerprint flood detected');
            }

            if ($fpEntry === null || ($now - $fpEntry['windowStart']) >= $fpWindowSec) {
                self::$fpStore[$fpHash] = ['count' => 1, 'windowStart' => $now, 'blockedUntil' => null];
            } else {
                self::$fpStore[$fpHash]['count']++;
            }

            $fpEntry = self::$fpStore[$fpHash];
            if ($fpEntry['count'] > $fpMaxRequests) {
                self::$fpStore[$fpHash]['blockedUntil'] = $now + $fpBlockSec;
                self::block($request, $config, 'ddos-fingerprint-flood', 429, 'Request fingerprint flood detected');
            }
        }

        // ------------------------------------------------------------------
        // Layer 7 — Repeated path flood (cross-IP, same endpoint)
        // ------------------------------------------------------------------
        $pathHash = md5($path);

        if ($useApcu) {
            $pathKey = 'waf_path_' . $pathHash;

            try {
                $pCount = apcu_inc($pathKey, 1, $success);
                if (!$success) {
                    apcu_store($pathKey, 1, $pathWindowSec);
                    $pCount = 1;
                }
                if ($pCount > $pathMaxRequests) {
                    self::block($request, $config, 'ddos-path-flood', 503, 'Service temporarily unavailable');
                }
            } catch (\Throwable) {
                // Skip gracefully
            }
        } else {
            $pEntry = self::$pathStore[$pathHash] ?? null;

            if ($pEntry === null || ($now - $pEntry['windowStart']) >= $pathWindowSec) {
                self::$pathStore[$pathHash] = ['count' => 1, 'windowStart' => $now];
            } else {
                self::$pathStore[$pathHash]['count']++;
            }

            $pEntry = self::$pathStore[$pathHash];
            if ($pEntry['count'] > $pathMaxRequests) {
                self::block($request, $config, 'ddos-path-flood', 503, 'Service temporarily unavailable');
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /**
     * Log the block event, then either exit (reject mode) or return (log-only).
     */
    private static function block(
        Request $request,
        array   $config,
        string  $rule,
        int     $httpCode,
        string  $msg
    ): void {
        $severity = (str_starts_with($rule, 'ddos-global') || str_starts_with($rule, 'ddos-path'))
            ? 'critical'
            : 'high';

        $logger = new Logger($config['log_path']);
        $logger->logBlock(
            $request->getIp(),
            $request->getMethod(),
            $request->getPath(),
            $rule,
            '',
            'ddos',
            $severity,
            $request->getUserAgent()
        );

        if (($config['mode'] ?? 'reject') === 'log-only') {
            return;
        }

        if (!headers_sent()) {
            if ($httpCode === 429) header('Retry-After: 60');
            if ($httpCode === 503) header('Retry-After: 5');
        }

        Response::block($rule, $httpCode, $config['response_type'] ?? 'json');
        exit;
    }
}
