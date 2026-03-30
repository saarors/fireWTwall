<?php

namespace FireWTWall\Detectors;

use FireWTWall\Request;

/**
 * Detects Server-Side Template Injection (SSTI) attempts.
 *
 * Scans query parameters, request body, URL path, and cookies for template
 * expression syntax targeting Jinja2/Python, Twig, FreeMarker, Velocity,
 * Smarty, ERB, Java EL, and OGNL engines.
 *
 * Requires PHP >= 8.0
 */
class SstiDetector
{
	private static array $rules = [
		['id' => 'ssti-python-class',       'pattern' => '/\{\{.*__class__.*\}\}/i',                        'severity' => 'critical'],
		['id' => 'ssti-python-mro',         'pattern' => '/\{\{.*__mro__.*\}\}/i',                          'severity' => 'critical'],
		['id' => 'ssti-python-subclasses',  'pattern' => '/\{\{.*__subclasses__\s*\(\)/i',                  'severity' => 'critical'],
		['id' => 'ssti-python-popen',       'pattern' => '/\{\{.*popen\s*\(|subprocess\s*\./i',             'severity' => 'critical'],
		['id' => 'ssti-python-globals',     'pattern' => '/\{\{.*__globals__.*\}\}/i',                      'severity' => 'critical'],
		['id' => 'ssti-python-builtins',    'pattern' => '/\{\{.*__builtins__.*\}\}/i',                     'severity' => 'critical'],
		['id' => 'ssti-twig-self',          'pattern' => '/\{\{_self\.env\./i',                             'severity' => 'critical'],
		['id' => 'ssti-twig-filter',        'pattern' => '/registerUndefinedFilterCallback/i',               'severity' => 'critical'],
		['id' => 'ssti-freemarker',         'pattern' => '/<#assign[^>]*Execute|freemarker\.template\.utility\.Execute/i', 'severity' => 'critical'],
		['id' => 'ssti-velocity',           'pattern' => '/#set\s*\(\s*\$[a-z]+\s*=\s*["\']?\s*\$class|#set.*Runtime/i', 'severity' => 'critical'],
		['id' => 'ssti-smarty-php',         'pattern' => '/\{php\}|\{\/php\}/i',                            'severity' => 'critical'],
		['id' => 'ssti-smarty-system',      'pattern' => '/\{system\s*\(|\{passthru\s*\(/i',                'severity' => 'critical'],
		['id' => 'ssti-erb',                'pattern' => '/<%=\s*(system|`|%x|IO\.popen|exec)/i',           'severity' => 'critical'],
		['id' => 'ssti-java-runtime',       'pattern' => '/\$\{.*Runtime.*exec|\$\{.*ProcessBuilder/i',     'severity' => 'critical'],
		['id' => 'ssti-ognl-expression',    'pattern' => '/%\{#[a-zA-Z_]|%25\{#|\$\{#context\[/i',         'severity' => 'critical'],
		['id' => 'ssti-ognl-member',        'pattern' => '/#_memberAccess|@java\.lang\.Runtime|new java\.lang\.ProcessBuilder/i', 'severity' => 'critical'],
		['id' => 'ssti-spring-classloader', 'pattern' => '/class\.module\.classLoader|class\.classLoader\.urls/i', 'severity' => 'critical'],
		['id' => 'ssti-tornado-import',     'pattern' => '/\{%\s*import\s+os\s*%\}/i',                      'severity' => 'critical'],
	];

	/**
	 * Scan the request for SSTI payloads.
	 *
	 * @param  Request $request  Normalised request object
	 * @param  array   $config   WAF configuration (reserved for future use)
	 * @return array{rule:string,matched:string,source:string,severity:string}|null
	 */
	public static function scan(Request $request, array $config): ?array
	{
		$sources = [
			'query'   => $request->getQuery(),
			'body'    => $request->getBody(),
			'path'    => $request->getPath(),
			'cookies' => $request->getCookies(),
		];

		foreach ($sources as $label => $values) {
			$result = self::scanValues($values, $label);
			if ($result !== null) {
				return $result;
			}
		}

		return null;
	}

	// ------------------------------------------------------------------ //
	// Private helpers
	// ------------------------------------------------------------------ //

	private static function scanValues(mixed $data, string $label): ?array
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
					'rule'     => $rule['id'],
					'severity' => $rule['severity'],
					'matched'  => substr($m[0], 0, 120),
					'source'   => $label,
				];
			}
		}
		return null;
	}
}
