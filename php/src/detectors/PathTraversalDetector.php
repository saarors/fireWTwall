<?php

namespace FireWTWall\Detectors;

class PathTraversalDetector
{
    private static array $rules = [
        ['name' => 'path-traversal-dotdot',  'severity' => 'critical', 'pattern' => '/(?:\.\.[\\/]|[\\/]\.\.)/'],
        ['name' => 'path-traversal-encoded', 'severity' => 'critical', 'pattern' => '/%2e%2e[%2f5c]/i'],
        ['name' => 'path-traversal-unicode', 'severity' => 'critical', 'pattern' => '/(?:%c0%ae|%c1%9c)/i'],
        ['name' => 'path-null-byte',         'severity' => 'critical', 'pattern' => '/%00|\x00/'],
        ['name' => 'path-etc-passwd',        'severity' => 'critical', 'pattern' => '/\/etc\/(?:passwd|shadow|hosts|group)\b/'],
        ['name' => 'path-win-system',        'severity' => 'critical', 'pattern' => '/(?:c:|%systemroot%)[\/\\\\]/i'],
        ['name' => 'path-env-file',          'severity' => 'high',     'pattern' => '/(?:^|\/)\.env(?:\.|$)/'],
        ['name' => 'path-wp-config',         'severity' => 'high',     'pattern' => '/wp-config\.php/i'],
        ['name' => 'path-htaccess',          'severity' => 'high',     'pattern' => '/\.htaccess\b/i'],
        ['name' => 'path-git-config',        'severity' => 'high',     'pattern' => '/\.git[\\/]/i'],
        ['name' => 'path-ssh-keys',          'severity' => 'high',     'pattern' => '/\.ssh[\\/]/i'],
        ['name' => 'path-proc-self',         'severity' => 'critical', 'pattern' => '/\/proc\/self\//i'],
        ['name' => 'path-php-wrappers',      'severity' => 'high',     'pattern' => '/(?:php|zip|phar|data|expect|glob|file):\/\//i'],
        ['name' => 'path-php-filter',        'severity' => 'high',     'pattern' => '/php:\/\/(?:filter|input|stdin)/i'],
    ];

    public static function scan(array $sources): ?array
    {
        foreach ($sources as $label => $values) {
            $result = self::scanValues($values, $label);
            if ($result !== null) return $result;
        }
        return null;
    }

    private static function scanValues($data, string $label): ?array
    {
        if (is_string($data)) {
            return self::matchString($data, $label);
        }
        if (is_array($data)) {
            foreach ($data as $value) {
                $r = self::scanValues($value, $label);
                if ($r !== null) return $r;
            }
        }
        return null;
    }

    private static function matchString(string $value, string $label): ?array
    {
        foreach (self::$rules as $rule) {
            if (preg_match($rule['pattern'], $value, $m)) {
                return [
                    'rule'     => $rule['name'],
                    'severity' => $rule['severity'],
                    'matched'  => substr($m[0], 0, 120),
                    'source'   => $label,
                ];
            }
        }
        return null;
    }
}
