<?php

namespace FireWTWall;

/**
 * Sliding-window rate limiter.
 *
 * Uses APCu when available (fast, atomic, shared across PHP-FPM workers).
 * Falls back to a file-based lock store for shared hosting environments.
 */
class RateLimiter
{
    private int    $windowSec;
    private int    $maxRequests;
    private int    $blockDurationSec;
    private bool   $useApcu;
    private string $storePath;

    public function __construct(array $config)
    {
        $this->windowSec        = (int) ($config['window_sec']        ?? 60);
        $this->maxRequests      = (int) ($config['max_requests']       ?? 100);
        $this->blockDurationSec = (int) ($config['block_duration_sec'] ?? 600);
        $this->useApcu          = function_exists('apcu_fetch') && ini_get('apc.enabled');
        $this->storePath        = sys_get_temp_dir() . '/waf_ratelimit';
    }

    /**
     * @return array{allowed: bool, remaining: int, retryAfter: int}
     */
    public function check(string $ip): array
    {
        return $this->useApcu ? $this->checkApcu($ip) : $this->checkFile($ip);
    }

    // ------------------------------------------------------------------ //
    // APCu backend
    // ------------------------------------------------------------------ //

    private function checkApcu(string $ip): array
    {
        $now    = time();
        $key    = 'waf_rl_' . md5($ip);
        $bKey   = 'waf_bl_' . md5($ip);

        // Is this IP currently blocked?
        $blockedUntil = apcu_fetch($bKey);
        if ($blockedUntil !== false && $now < (int) $blockedUntil) {
            return ['allowed' => false, 'remaining' => 0, 'retryAfter' => (int) $blockedUntil - $now];
        }

        // Fetch or create counter entry
        $entry = apcu_fetch($key);
        if ($entry === false || $now - $entry['start'] >= $this->windowSec) {
            $entry = ['start' => $now, 'count' => 0];
        }

        $entry['count']++;
        apcu_store($key, $entry, $this->windowSec * 2);

        if ($entry['count'] > $this->maxRequests) {
            apcu_store($bKey, $now + $this->blockDurationSec, $this->blockDurationSec);
            return ['allowed' => false, 'remaining' => 0, 'retryAfter' => $this->blockDurationSec];
        }

        $remaining = max(0, $this->maxRequests - $entry['count']);
        return ['allowed' => true, 'remaining' => $remaining, 'retryAfter' => 0];
    }

    // ------------------------------------------------------------------ //
    // File-based fallback
    // ------------------------------------------------------------------ //

    private function checkFile(string $ip): array
    {
        $now      = time();
        $file     = $this->storePath . '_' . md5($ip) . '.json';
        $lockFile = $file . '.lock';

        $lock = fopen($lockFile, 'c');
        if (!$lock) {
            return ['allowed' => true, 'remaining' => $this->maxRequests, 'retryAfter' => 0];
        }

        flock($lock, LOCK_EX);

        $entry = [];
        if (file_exists($file)) {
            $entry = json_decode(file_get_contents($file), true) ?? [];
        }

        // Check block
        if (!empty($entry['blocked_until']) && $now < $entry['blocked_until']) {
            $retry = $entry['blocked_until'] - $now;
            flock($lock, LOCK_UN);
            fclose($lock);
            return ['allowed' => false, 'remaining' => 0, 'retryAfter' => $retry];
        }

        // Slide window
        if (empty($entry['start']) || $now - $entry['start'] >= $this->windowSec) {
            $entry = ['start' => $now, 'count' => 0, 'blocked_until' => null];
        }

        $entry['count']++;

        if ($entry['count'] > $this->maxRequests) {
            $entry['blocked_until'] = $now + $this->blockDurationSec;
            file_put_contents($file, json_encode($entry));
            flock($lock, LOCK_UN);
            fclose($lock);
            return ['allowed' => false, 'remaining' => 0, 'retryAfter' => $this->blockDurationSec];
        }

        file_put_contents($file, json_encode($entry));
        flock($lock, LOCK_UN);
        fclose($lock);

        $remaining = max(0, $this->maxRequests - $entry['count']);
        return ['allowed' => true, 'remaining' => $remaining, 'retryAfter' => 0];
    }
}
