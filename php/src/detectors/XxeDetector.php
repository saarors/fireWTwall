<?php

namespace FireWTWall\Detectors;

use FireWTWall\Request;

/**
 * Detects XML External Entity (XXE) injection attempts.
 *
 * Only activates when the request body looks like XML (Content-Type header
 * or body prefix).  Looks for DOCTYPE / ENTITY declarations that reference
 * external resources.
 *
 * Requires PHP >= 8.0
 */
class XxeDetector
{
	/** Patterns indicating an XXE payload */
	private const PATTERNS = [
		'/<!DOCTYPE[^>]*\[/i',
		'/<!ENTITY[^>]*SYSTEM/i',
		'/<!ENTITY\s+%/i',
		'/SYSTEM\s+["\']/',
		'/PUBLIC\s+["\']/',
		'/<xi:include/i',
	];

	/**
	 * Scan the request body for XXE payloads.
	 *
	 * @param  Request $request  Normalised request object
	 * @param  array   $config   WAF configuration (reserved for future use)
	 * @return array{rule:string,matched:string,source:string,severity:string}|null
	 */
	public static function scan(Request $request, array $config): ?array
	{
		$body        = $request->getRawBody();
		$contentType = $request->getHeaders()['content-type'] ?? '';

		// Only process if this looks like XML content
		if (!self::isXmlContent($contentType, $body)) {
			return null;
		}

		foreach (self::PATTERNS as $pattern) {
			if (preg_match($pattern, $body)) {
				return [
					'rule'     => 'xxe-external-entity',
					'matched'  => substr($body, 0, 100),
					'source'   => 'body',
					'severity' => 'critical',
				];
			}
		}

		return null;
	}

	// ------------------------------------------------------------------ //
	// Private helpers
	// ------------------------------------------------------------------ //

	/** Return true when the request body is (or appears to be) XML. */
	private static function isXmlContent(string $contentType, string $body): bool
	{
		if (str_contains(strtolower($contentType), 'xml')) {
			return true;
		}

		$prefix = ltrim(substr($body, 0, 20));
		return str_starts_with($prefix, '<?xml') || str_starts_with($prefix, '<!DOCTYPE');
	}
}
