<?php

namespace FireWTWall\Detectors;

use FireWTWall\Request;

/**
 * Detects NoSQL Injection attempts (primarily MongoDB operator injection).
 *
 * Scans query parameters, request body, and cookies for MongoDB query
 * operators embedded as JSON keys or PHP array notation.  Also checks the
 * raw query string for bracket-encoded operators such as [$ne]=.
 *
 * Requires PHP >= 8.0
 */
class NoSqlInjectionDetector
{
	private static array $rules = [
		['id' => 'nosql-operator-ne',    'pattern' => '/\[\s*\$ne\s*\]|"\s*\$ne\s*"\s*:/i',    'severity' => 'high'],
		['id' => 'nosql-operator-gt',    'pattern' => '/\[\s*\$gt\s*\]|"\s*\$gt\s*"\s*:/i',    'severity' => 'high'],
		['id' => 'nosql-operator-lt',    'pattern' => '/\[\s*\$lt\s*\]|"\s*\$lt\s*"\s*:/i',    'severity' => 'high'],
		['id' => 'nosql-operator-where', 'pattern' => '/"\s*\$where\s*"\s*:/i',                 'severity' => 'critical'],
		['id' => 'nosql-operator-regex', 'pattern' => '/\[\s*\$regex\s*\]|"\s*\$regex\s*"\s*:/i', 'severity' => 'high'],
		['id' => 'nosql-operator-or',    'pattern' => '/"\s*\$or\s*"\s*:\s*\[/i',               'severity' => 'medium'],
		['id' => 'nosql-operator-expr',  'pattern' => '/"\s*\$expr\s*"\s*:/i',                  'severity' => 'high'],
		['id' => 'nosql-func-sleep',     'pattern' => '/"\s*\$where\s*".*sleep\s*\(/i',         'severity' => 'critical'],
	];

	/** Raw query string patterns for bracket-encoded MongoDB operators */
	private const RAW_QS_PATTERN = '/\[\s*\$(ne|gt|lt|gte|lte|in|nin|regex|where|exists)\s*\]/i';

	/**
	 * Scan the request for NoSQL injection payloads.
	 *
	 * @param  Request $request  Normalised request object
	 * @param  array   $config   WAF configuration (reserved for future use)
	 * @return array{rule:string,matched:string,source:string,severity:string}|null
	 */
	public static function scan(Request $request, array $config): ?array
	{
		// Check raw query string for bracket-notation operators ([$ne]=, [$gt]=, etc.)
		$rawQs = $_SERVER['QUERY_STRING'] ?? '';
		if ($rawQs !== '' && preg_match(self::RAW_QS_PATTERN, $rawQs, $m)) {
			return [
				'rule'     => 'nosql-operator-raw-qs',
				'severity' => 'high',
				'matched'  => substr($m[0], 0, 120),
				'source'   => 'query',
			];
		}

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
