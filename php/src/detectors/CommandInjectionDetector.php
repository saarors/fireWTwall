<?php

namespace FireWTWall\Detectors;

class CommandInjectionDetector
{
    private static array $rules = [
        ['name' => 'cmd-pipe',           'severity' => 'critical', 'pattern' => '/[|;`]\s*(?:ls|cat|whoami|id|uname|wget|curl|bash|sh|python|perl|ruby|nc|netcat|ncat)\b/i'],
        ['name' => 'cmd-subshell',       'severity' => 'critical', 'pattern' => '/\$\([^)]*\)|`[^`]*`/'],
        ['name' => 'cmd-path-exec',      'severity' => 'critical', 'pattern' => '/\/(?:bin|usr\/bin|usr\/local\/bin)\/\w+/'],
        ['name' => 'cmd-win-shell',      'severity' => 'critical', 'pattern' => '/(?:cmd\.exe|powershell(?:\.exe)?|wscript|cscript)\b/i'],
        ['name' => 'cmd-win-net',        'severity' => 'high',     'pattern' => '/\bnet\s+(?:user|group|localgroup|share)\b/i'],
        ['name' => 'cmd-win-reg',        'severity' => 'high',     'pattern' => '/\breg(?:\.exe)?\s+(?:add|delete|query|export)/i'],
        ['name' => 'cmd-wget-curl',      'severity' => 'critical', 'pattern' => '/\b(?:wget|curl)\s+(?:https?|ftp):\/\//i'],
        ['name' => 'cmd-base64-decode',  'severity' => 'high',     'pattern' => '/base64\s*(?:--decode|-d)\b/i'],
        ['name' => 'cmd-redirection',    'severity' => 'high',     'pattern' => '/(?:^|[^<])>{1,2}\s*\/(?:etc|tmp|var|dev)/'],
        // Extended coverage
        ['name' => 'cmd-python-exec',    'severity' => 'critical', 'pattern' => '/python[23]?\s+-[cC]\s+["\']?.*import|python[23]?\s+-[cC]\s+["\']?.*exec/i'],
        ['name' => 'cmd-ruby-exec',      'severity' => 'critical', 'pattern' => '/ruby\s+-e\s+["\']?/i'],
        ['name' => 'cmd-perl-exec',      'severity' => 'critical', 'pattern' => '/perl\s+-e\s+["\']?/i'],
        ['name' => 'cmd-php-exec',       'severity' => 'critical', 'pattern' => '/php\s+-r\s+["\']?/i'],
        ['name' => 'cmd-netcat',         'severity' => 'critical', 'pattern' => '/\bnc\s+-[enlvz]|\bnetcat\b/i'],
        ['name' => 'cmd-whoami',         'severity' => 'high',     'pattern' => '/\bwhoami\b|\bid\b|\bpasswd\b/i'],
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
        if (is_string($data)) return self::matchString($data, $label);
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
