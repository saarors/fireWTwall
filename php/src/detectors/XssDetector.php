<?php

namespace FireWTWall\Detectors;

class XssDetector
{
    private static array $rules = [
        ['name' => 'xss-script-tag',       'severity' => 'critical', 'pattern' => '/<\s*script[\s>\/]/i'],
        ['name' => 'xss-javascript-proto', 'severity' => 'critical', 'pattern' => '/javascript\s*:/i'],
        ['name' => 'xss-vbscript-proto',   'severity' => 'critical', 'pattern' => '/vbscript\s*:/i'],
        ['name' => 'xss-data-uri',         'severity' => 'critical', 'pattern' => '/data\s*:\s*text\/html/i'],
        ['name' => 'xss-event-handler',    'severity' => 'high',     'pattern' => '/\bon\w+\s*=/i'],
        ['name' => 'xss-iframe',           'severity' => 'high',     'pattern' => '/<\s*iframe[\s>\/]/i'],
        ['name' => 'xss-object-embed',     'severity' => 'high',     'pattern' => '/<\s*(?:object|embed)[\s>\/]/i'],
        ['name' => 'xss-svg',             'severity' => 'high',     'pattern' => '/<\s*svg[\s>\/]/i'],
        ['name' => 'xss-link-meta',        'severity' => 'medium',   'pattern' => '/<\s*(?:link|meta)[\s>\/]/i'],
        ['name' => 'xss-expression',       'severity' => 'high',     'pattern' => '/expression\s*\(/i'],
        ['name' => 'xss-img-src',          'severity' => 'medium',   'pattern' => '/<\s*img[^>]+src\s*=/i'],
        ['name' => 'xss-srcdoc',           'severity' => 'high',     'pattern' => '/srcdoc\s*=/i'],
        ['name' => 'xss-base-href',        'severity' => 'medium',   'pattern' => '/<\s*base[\s>]/i'],
        ['name' => 'xss-form-action',      'severity' => 'high',     'pattern' => '/<\s*form[^>]+action\s*=\s*[\'"]?javascript/i'],
        ['name' => 'xss-dom-write',        'severity' => 'high',     'pattern' => '/document\s*\.\s*(?:write|writeln)\s*\(/i'],
        ['name' => 'xss-inner-html',       'severity' => 'high',     'pattern' => '/\.innerHTML\s*=/i'],
        ['name' => 'xss-angularjs-bind',   'severity' => 'high',     'pattern' => '/\{\{.*\}\}/'],
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
