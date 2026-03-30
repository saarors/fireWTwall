<?php

namespace FireWTWall\Detectors;

use FireWTWall\Request;

/**
 * Detects insecure deserialization payloads.
 *
 * Scans the raw request body, query parameters, and cookies for serialized
 * object signatures from PHP, Java (both base64 and hex-encoded), and
 * Node.js (node-serialize).
 *
 * Requires PHP >= 8.0
 */
class DeserializationDetector
{
	private static array $rules = [
		['id' => 'deser-php-object',  'pattern' => '/O:\d+:"[a-zA-Z_\\\\]+":\d+:\{/',          'severity' => 'critical'],
		['id' => 'deser-php-array',   'pattern' => '/a:\d+:\{(?:i:\d+;|s:\d+:")/',              'severity' => 'high'],
		['id' => 'deser-java-b64',    'pattern' => '/rO0AB[XY]/',                                'severity' => 'critical'],
		['id' => 'deser-java-hex',    'pattern' => '/aced0005/i',                                'severity' => 'critical'],
		['id' => 'deser-node-serial', 'pattern' => '/\{"rce"\s*:\s*"_\$\$ND_FUNC\$\$_function/i', 'severity' => 'critical'],
	];

	/**
	 * Scan the request for deserialization payloads.
	 *
	 * @param  Request $request  Normalised request object
	 * @param  array   $config   WAF configuration (reserved for future use)
	 * @return array{rule:string,matched:string,source:string,severity:string}|null
	 */
	public static function scan(Request $request, array $config): ?array
	{
		// Check raw body first (catches binary/base64 payloads before decoding)
		$rawBody = $request->getRawBody();
		if ($rawBody !== '') {
			$result = self::matchString($rawBody, 'body');
			if ($result !== null) {
				return $result;
			}
		}

		$sources = [
			'query'   => $request->getQuery(),
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
