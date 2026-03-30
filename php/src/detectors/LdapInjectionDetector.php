<?php

namespace FireWTWall\Detectors;

use FireWTWall\Request;

/**
 * Detects LDAP Injection attempts.
 *
 * Scans query parameters, request body, and cookies for patterns that
 * suggest manipulation of LDAP filter expressions, including wildcard
 * bypasses, parenthesis injection, null-byte injection, and hex-encoded
 * special characters.
 *
 * Requires PHP >= 8.0
 */
class LdapInjectionDetector
{
	private static array $rules = [
		['id' => 'ldap-wildcard-bypass', 'pattern' => '/\*\)\s*\(\s*[a-z]+=\*|^\*$/i',                  'severity' => 'high'],
		['id' => 'ldap-injection-paren', 'pattern' => '/\*\)\s*\(\||\*\)\s*\(&/i',                       'severity' => 'critical'],
		['id' => 'ldap-injection-null',  'pattern' => '/\x00|%00.*uid|uid.*%00/i',                       'severity' => 'high'],
		['id' => 'ldap-injection-uid',   'pattern' => '/\*\s*\)\s*\(\s*uid\s*=\s*\*/i',                  'severity' => 'critical'],
		['id' => 'ldap-injection-admin', 'pattern' => '/\*\)\s*\(\s*cn\s*=\s*admin|\)\s*\(&\s*\(password/i', 'severity' => 'critical'],
		['id' => 'ldap-injection-encode','pattern' => '/\*28|\*29|\*00|\*2a/i',                           'severity' => 'high'],
	];

	/**
	 * Scan the request for LDAP injection payloads.
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
