<?php

namespace FireWTWall\Detectors;

use FireWTWall\Request;

/**
 * Detects Log4Shell (CVE-2021-44228) and related Log4j JNDI injection attempts.
 *
 * Scans ALL HTTP request headers (from $_SERVER keys starting with HTTP_),
 * query parameters, request body, and cookies.  Covers plain payloads as well
 * as common obfuscation techniques such as nested lookups and case-mangling.
 *
 * Requires PHP >= 8.0
 */
class Log4ShellDetector
{
	private static array $rules = [
		['id' => 'log4shell-jndi',          'pattern' => '/\$\{jndi\s*:/i',                                           'severity' => 'critical'],
		['id' => 'log4shell-jndi-protocol', 'pattern' => '/\$\{jndi\s*:\s*(ldap|ldaps|rmi|dns|iiop|corba|nds|http)s?:\/\//i', 'severity' => 'critical'],
		['id' => 'log4shell-obfusc-lower',  'pattern' => '/\$\{.*lower.*j.*ndi|j\$\{.*\}ndi/i',                      'severity' => 'critical'],
		['id' => 'log4shell-obfusc-upper',  'pattern' => '/\$\{.*upper.*j.*ndi/i',                                    'severity' => 'critical'],
		['id' => 'log4shell-double-colon',  'pattern' => '/\$\{\s*::-[jJ]\s*\}/i',                                    'severity' => 'critical'],
		['id' => 'log4shell-nested',        'pattern' => '/\$\{[^}]*\$\{[^}]*\}[^}]*jndi/i',                         'severity' => 'critical'],
	];

	/**
	 * Scan the request for Log4Shell payloads.
	 *
	 * @param  Request $request  Normalised request object
	 * @param  array   $config   WAF configuration (reserved for future use)
	 * @return array{rule:string,matched:string,source:string,severity:string}|null
	 */
	public static function scan(Request $request, array $config): ?array
	{
		// Scan all HTTP headers directly from $_SERVER
		foreach ($_SERVER as $key => $value) {
			if (!str_starts_with($key, 'HTTP_')) {
				continue;
			}
			if (!is_string($value)) {
				continue;
			}
			$result = self::matchString($value, 'header');
			if ($result !== null) {
				return $result;
			}
		}

		// Scan query params, body, and cookies
		$sources = [
			'query'   => $request->getQuery(),
			'body'    => $request->getBody(),
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
