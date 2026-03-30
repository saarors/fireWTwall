<?php

namespace FireWTWall\Detectors;

use FireWTWall\Request;

/**
 * Detects Mass Assignment / Object-Injection attempts.
 *
 * Looks for input keys that map to special PHP / framework internals
 * (__proto__, constructor, prototype, magic methods, etc.).  Also decodes
 * a JSON body and recursively checks all keys at every nesting level.
 *
 * Requires PHP >= 8.0
 */
class MassAssignmentDetector
{
	/** Input key names that should never appear in user-supplied data */
	private const DANGEROUS_KEYS = [
		'__proto__',
		'constructor',
		'prototype',
		'__class__',
		'__type__',
		'_method',
		'_METHOD',
		'__destruct',
		'__wakeup',
		'__construct',
	];

	/**
	 * Scan the request for mass-assignment / object-injection indicators.
	 *
	 * @param  Request $request  Normalised request object
	 * @param  array   $config   WAF configuration (reserved for future use)
	 * @return array{rule:string,matched:string,source:string,severity:string}|null
	 */
	public static function scan(Request $request, array $config): ?array
	{
		// 1. Flat query + body key scan
		$flatSources = [
			'query' => $request->getQuery(),
			'body'  => $request->getBody(),
		];

		foreach ($flatSources as $sourceLabel => $data) {
			$result = self::scanKeys($data, $sourceLabel);
			if ($result !== null) {
				return $result;
			}
		}

		// 2. JSON body — recursive key scan
		$raw = $request->getRawBody();
		if ($raw !== '') {
			$decoded = @json_decode($raw, true);
			if (is_array($decoded)) {
				$result = self::scanKeys($decoded, 'body');
				if ($result !== null) {
					return $result;
				}
			}
		}

		return null;
	}

	// ------------------------------------------------------------------ //
	// Private helpers
	// ------------------------------------------------------------------ //

	/**
	 * Recursively walk $data and check every key against the dangerous list.
	 */
	private static function scanKeys(array $data, string $sourceLabel): ?array
	{
		foreach ($data as $key => $value) {
			if (in_array((string) $key, self::DANGEROUS_KEYS, true)) {
				return [
					'rule'     => 'mass-assignment',
					'matched'  => (string) $key,
					'source'   => $sourceLabel,
					'severity' => 'critical',
				];
			}

			if (is_array($value)) {
				$result = self::scanKeys($value, $sourceLabel);
				if ($result !== null) {
					return $result;
				}
			}
		}

		return null;
	}
}
