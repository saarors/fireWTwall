<?php

namespace FireWTWall\Detectors;

use FireWTWall\Request;

/**
 * Detects Shellshock (CVE-2014-6271 / CVE-2014-7169) exploitation attempts.
 *
 * Shellshock payloads are delivered via HTTP headers, so this detector scans
 * ALL HTTP headers by iterating $_SERVER keys that begin with HTTP_.
 *
 * Requires PHP >= 8.0
 */
class ShellshockDetector
{
	private static array $rules = [
		['id' => 'shellshock-func',    'pattern' => '/\(\s*\)\s*\{\s*[^}]*\}\s*;/',    'severity' => 'critical'],
		['id' => 'shellshock-env-cmd', 'pattern' => '/\(\s*\)\s*\{\s*:;\s*\}\s*;/',    'severity' => 'critical'],
	];

	/**
	 * Scan all HTTP request headers for Shellshock payloads.
	 *
	 * @param  Request $request  Normalised request object
	 * @param  array   $config   WAF configuration (reserved for future use)
	 * @return array{rule:string,matched:string,source:string,severity:string}|null
	 */
	public static function scan(Request $request, array $config): ?array
	{
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

		return null;
	}

	// ------------------------------------------------------------------ //
	// Private helpers
	// ------------------------------------------------------------------ //

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
