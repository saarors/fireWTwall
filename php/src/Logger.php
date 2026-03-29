<?php

namespace FireWTWall;

/**
 * Appends structured NDJSON entries to the WAF log file.
 */
class Logger
{
    private string $logPath;

    public function __construct(string $logPath)
    {
        $this->logPath = $logPath;
        $dir = dirname($logPath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
    }

    public function logPass(
        string  $ip,
        string  $method,
        string  $path,
        string  $userAgent  = '',
        ?string $requestId  = null,
        ?float  $durationMs = null
    ): void {
        $entry = json_encode(array_filter([
            'timestamp'  => gmdate('Y-m-d\TH:i:s\Z'),
            'requestId'  => $requestId ?? bin2hex(random_bytes(8)),
            'result'     => 'passed',
            'ip'         => $ip,
            'method'     => $method,
            'path'       => $path,
            'userAgent'  => $userAgent,
            'durationMs' => $durationMs,
        ], fn($v) => $v !== null)) . "\n";

        $fp = @fopen($this->logPath, 'a');
        if ($fp) {
            flock($fp, LOCK_EX);
            fwrite($fp, $entry);
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }

    public function logBlock(
        string  $ip,
        string  $method,
        string  $path,
        string  $rule,
        string  $matched    = '',
        string  $source     = '',
        string  $severity   = 'medium',
        string  $userAgent  = '',
        ?string $requestId  = null,
        ?float  $durationMs = null
    ): void {
        $entry = json_encode(array_filter([
            'timestamp'  => gmdate('Y-m-d\TH:i:s\Z'),
            'requestId'  => $requestId ?? bin2hex(random_bytes(8)),
            'result'     => 'blocked',
            'ip'         => $ip,
            'method'     => $method,
            'path'       => $path,
            'rule'       => $rule,
            'matched'    => substr($matched, 0, 120),
            'source'     => $source,
            'severity'   => $severity,
            'userAgent'  => $userAgent,
            'durationMs' => $durationMs,
        ], fn($v) => $v !== null)) . "\n";

        $fp = @fopen($this->logPath, 'a');
        if ($fp) {
            flock($fp, LOCK_EX);
            fwrite($fp, $entry);
            flock($fp, LOCK_UN);
            fclose($fp);
        }
    }
}
