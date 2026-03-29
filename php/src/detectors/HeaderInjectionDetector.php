<?php

namespace FireWTWall\Detectors;

class HeaderInjectionDetector
{
    /** CRLF characters used for HTTP response splitting */
    private const CRLF_PATTERN = '/[\r\n]|%0[aAdD]|\\\\r|\\\\n/i';

    /**
     * Scan request headers for CRLF injection and host-header injection.
     *
     * @param  array  $headers  Normalised header array (lowercase keys)
     * @param  string $host     Value of the Host header
     * @return array{rule:string,severity:string,matched:string,source:string}|null
     */
    public static function scan(array $headers, string $host): ?array
    {
        // 1. CRLF injection in any header
        foreach ($headers as $name => $value) {
            if (preg_match(self::CRLF_PATTERN, $value, $m)) {
                return [
                    'rule'     => 'crlf-injection',
                    'severity' => 'critical',
                    'matched'  => substr($m[0], 0, 120),
                    'source'   => 'header:' . $name,
                ];
            }
        }

        // 2. Host header injection
        if ($host !== '' && preg_match('/[\/?\r\n@#]/', $host, $m)) {
            return [
                'rule'     => 'host-header-injection',
                'severity' => 'high',
                'matched'  => substr($m[0], 0, 120),
                'source'   => 'header:host',
            ];
        }

        return null;
    }
}
