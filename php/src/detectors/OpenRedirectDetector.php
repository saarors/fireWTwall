<?php

namespace FireWTWall\Detectors;

use FireWTWall\Request;

/**
 * Detects Open Redirect attempts.
 *
 * Scans query parameters and body fields whose names are commonly used to
 * carry redirect targets.  Blocks any value that starts with an absolute
 * URL prefix (http://, https://, //, \\), which would allow an attacker to
 * redirect users to an external domain.
 *
 * Requires PHP >= 8.0
 */
class OpenRedirectDetector
{
	/** Parameter names that commonly carry a redirect destination */
	private const REDIRECT_PARAMS = [
		'redirect', 'return', 'returnUrl', 'next', 'url', 'dest', 'destination',
		'go', 'goto', 'target', 'redir', 'r', 'u', 'link', 'forward',
		'location', 'continue', 'ref',
	];

	/**
	 * Scan the request for open-redirect indicators.
	 *
	 * @param  Request $request  Normalised request object
	 * @param  array   $config   WAF configuration (reserved for future use)
	 * @return array{rule:string,matched:string,source:string,severity:string}|null
	 */
	public static function scan(Request $request, array $config): ?array
	{
		$allSources = [
			'query' => $request->getQuery(),
			'body'  => $request->getBody(),
		];

		foreach ($allSources as $sourceLabel => $data) {
			$result = self::scanFlat($data, $sourceLabel);
			if ($result !== null) {
				return $result;
			}
		}

		return null;
	}

	// ------------------------------------------------------------------ //
	// Private helpers
	// ------------------------------------------------------------------ //

	/**
	 * Walk a (possibly nested) array and check every key that is a redirect
	 * param name for suspicious absolute-URL values.
	 */
	private static function scanFlat(array $data, string $sourceLabel, string $prefix = ''): ?array
	{
		foreach ($data as $key => $value) {
			$paramName = $prefix !== '' ? $prefix . '[' . $key . ']' : (string) $key;

			if (is_array($value)) {
				$result = self::scanFlat($value, $sourceLabel, $paramName);
				if ($result !== null) {
					return $result;
				}
				continue;
			}

			if (!is_string($value)) {
				continue;
			}

			// Only inspect parameters whose name suggests a redirect target
			if (!in_array(strtolower((string) $key), array_map('strtolower', self::REDIRECT_PARAMS), true)) {
				continue;
			}

			if (self::isAbsoluteRedirect($value)) {
				return [
					'rule'     => 'open-redirect',
					'matched'  => $value,
					'source'   => $sourceLabel,
					'severity' => 'high',
				];
			}
		}

		return null;
	}

	/**
	 * Return true when $value starts with an absolute URL indicator that
	 * could redirect the user off-site.
	 */
	private static function isAbsoluteRedirect(string $value): bool
	{
		$v = ltrim($value);

		return str_starts_with($v, 'http://')
			|| str_starts_with($v, 'https://')
			|| str_starts_with($v, '//')
			|| str_starts_with($v, '\\');
	}
}
