<?php

namespace FireWTWall\Detectors;

class SqlInjectionDetector
{
    private static array $rules = [
        // Critical
        ['name' => 'sql-union-select',      'severity' => 'critical', 'pattern' => '/\bunion\s+(?:all\s+)?select\b/i'],
        ['name' => 'sql-drop-table',        'severity' => 'critical', 'pattern' => '/;\s*drop\s+table\b/i'],
        ['name' => 'sql-xp-cmdshell',       'severity' => 'critical', 'pattern' => '/\bxp_cmdshell\b/i'],
        ['name' => 'sql-exec',              'severity' => 'critical', 'pattern' => '/\bexec(?:ute)?\s*\(/i'],
        ['name' => 'sql-information-schema','severity' => 'critical', 'pattern' => '/\binformation_schema\b/i'],
        ['name' => 'sql-sleep',             'severity' => 'critical', 'pattern' => '/\bsleep\s*\(\s*\d/i'],
        ['name' => 'sql-benchmark',         'severity' => 'critical', 'pattern' => '/\bbenchmark\s*\(/i'],
        ['name' => 'sql-load-file',         'severity' => 'critical', 'pattern' => '/\bload_file\s*\(/i'],
        ['name' => 'sql-into-outfile',      'severity' => 'critical', 'pattern' => '/\binto\s+(?:out|dump)file\b/i'],
        ['name' => 'sql-sys-tables',        'severity' => 'critical', 'pattern' => '/\bsysobjects\b|\bsyscolumns\b/i'],
        // High
        ['name' => 'sql-comment',           'severity' => 'high',     'pattern' => '/(?:--|\/\*|\*\/|#\s*$)/m'],
        ['name' => 'sql-stacked-query',     'severity' => 'high',     'pattern' => '/;\s*(?:select|insert|update|delete|drop|alter|create|exec)\b/i'],
        ['name' => 'sql-cast-convert',      'severity' => 'high',     'pattern' => '/\b(?:cast|convert)\s*\(/i'],
        ['name' => 'sql-char-concat',       'severity' => 'high',     'pattern' => '/\bchar\s*\(\s*\d/i'],
        // Medium
        ['name' => 'sql-boolean-true',      'severity' => 'medium',   'pattern' => "/\\bor\\s+['\"\d]+\\s*=\\s*['\"\d]+/i"],
        ['name' => 'sql-boolean-and',       'severity' => 'medium',   'pattern' => "/\\band\\s+['\"\d]+\\s*=\\s*['\"\d]+/i"],
        ['name' => 'sql-order-by-num',      'severity' => 'medium',   'pattern' => '/\border\s+by\s+\d+\b/i'],
        ['name' => 'sql-tautology',         'severity' => 'medium',   'pattern' => "/'\\s*or\\s*'[^']*'\\s*=\\s*'/i"],
        // Additional coverage
        ['name' => 'sql-waitfor-delay',     'severity' => 'critical', 'pattern' => '/\bwaitfor\s+delay\b/i'],
        ['name' => 'sql-pg-sleep',          'severity' => 'critical', 'pattern' => '/\bpg_sleep\s*\(/i'],
        ['name' => 'sql-hex-values',        'severity' => 'medium',   'pattern' => '/0x[0-9a-f]{4,}/i'],
        ['name' => 'sql-group-by-having',   'severity' => 'medium',   'pattern' => '/\bhaving\s+\d+\s*=\s*\d+/i'],
        ['name' => 'sql-dbms-fingerprint',  'severity' => 'medium',   'pattern' => '/\b(?:@@version|version\s*\(\s*\)|user\s*\(\s*\)|database\s*\(\s*\))\b/i'],
        ['name' => 'sql-declare-set',       'severity' => 'high',     'pattern' => '/\bdeclare\s+@\w+\b/i'],
        ['name' => 'sql-bulk-insert',       'severity' => 'critical', 'pattern' => '/\bbulk\s+insert\b/i'],
        ['name' => 'sql-openrowset',        'severity' => 'critical', 'pattern' => '/\bopenrowset\s*\(/i'],
        // Extended coverage
        ['name' => 'sql-case-when',         'severity' => 'high',     'pattern' => '/CASE\s+WHEN\s+.*\s+THEN/i'],
        ['name' => 'sql-extractvalue',      'severity' => 'critical', 'pattern' => '/EXTRACTVALUE\s*\(/i'],
        ['name' => 'sql-updatexml',         'severity' => 'critical', 'pattern' => '/UPDATEXML\s*\(/i'],
        ['name' => 'sql-sys-tables',        'severity' => 'critical', 'pattern' => '/sys\.(user_summary|processlist|statements_with_errors)/i'],
        ['name' => 'sql-gtid',              'severity' => 'critical', 'pattern' => '/GTID_SUBSET\s*\(/i'],
        ['name' => 'sql-exp-tilde',         'severity' => 'critical', 'pattern' => '/exp\(~\(/i'],
        ['name' => 'sql-polygon',           'severity' => 'high',     'pattern' => '/(polygon|geometrycollection|linestring|multipoint)\s*\(/i'],
        ['name' => 'sql-procedure-analyse', 'severity' => 'high',     'pattern' => '/procedure\s+analyse\s*\(/i'],
        ['name' => 'sql-having',            'severity' => 'high',     'pattern' => '/\bHAVING\s+\d+\s*=\s*\d+/i'],
        ['name' => 'sql-dbms-version',      'severity' => 'critical', 'pattern' => '/@@version|@@global|@@session/i'],
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
