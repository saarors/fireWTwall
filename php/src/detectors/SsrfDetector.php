<?php

namespace FireWTWall\Detectors;

use FireWTWall\Request;

/**
 * Detects Server-Side Request Forgery (SSRF) attempts.
 *
 * Scans query parameters and body fields whose names are commonly used to
 * pass URLs or redirect targets, looking for private IP ranges, cloud metadata
 * endpoints, and dangerous URI schemes.
 *
 * Requires PHP >= 8.0
 */
class SsrfDetector
{
	/** Parameter names that commonly carry a URL or redirect target */
	private const URL_PARAMS = [
		'url', 'redirect', 'return', 'callback', 'next', 'dest', 'destination',
		'src', 'source', 'uri', 'link', 'href', 'proxy', 'forward', 'returnUrl',
		'goto', 'target', 'redir', 'r', 'u',
	];

	/** Patterns that identify private / loopback IP addresses */
	private const PRIVATE_IP_PATTERNS = [
		'/^127\./i',
		'/^10\./i',
		'/^172\.(1[6-9]|2[0-9]|3[01])\./i',
		'/^192\.168\./i',
		'/^0\.0\.0\.0/i',
		'/^::1$/i',
	];

	/** Cloud instance metadata endpoints */
	private const METADATA_PATTERNS = [
		'/169\.254\.169\.254/i',
		'/metadata\.google\.internal/i',
		'/metadata\.azure\.com/i',
		'/100\.100\.100\.200/i',
	];

	/** Dangerous URI schemes (excluding http/https/ftp used legitimately) */
	private const SCHEME_PATTERNS = [
		'/^file:\/\//i',
		'/^gopher:\/\//i',
		'/^dict:\/\//i',
		'/^ldap:\/\//i',
		'/^tftp:\/\//i',
		'/^ftp:\/\//i',
	];

	/**
	 * Scan the request for SSRF indicators.
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
	 * Walk a (possibly nested) array and check every key that is a URL param
	 * name for suspicious values.
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

			// Only inspect parameters whose name suggests a URL or redirect
			if (!in_array(strtolower((string) $key), array_map('strtolower', self::URL_PARAMS), true)) {
				continue;
			}

			if (self::isSuspiciousValue($value)) {
				return [
					'rule'     => 'ssrf-private-ip',
					'matched'  => $value,
					'source'   => $sourceLabel,
					'severity' => 'critical',
				];
			}
		}

		return null;
	}

	/** Return true if $value matches any SSRF indicator. */
	private static function isSuspiciousValue(string $value): bool
	{
		// Extract host portion for IP checks
		$host = self::extractHost($value);

		foreach (self::PRIVATE_IP_PATTERNS as $pattern) {
			if ($host !== '' && preg_match($pattern, $host)) {
				return true;
			}
		}

		foreach (self::METADATA_PATTERNS as $pattern) {
			if (preg_match($pattern, $value)) {
				return true;
			}
		}

		foreach (self::SCHEME_PATTERNS as $pattern) {
			if (preg_match($pattern, ltrim($value))) {
				return true;
			}
		}

		return false;
	}

	/** Extract the host (or bare value) from a URL-like string. */
	private static function extractHost(string $value): string
	{
		$parsed = @parse_url($value);
		if ($parsed !== false && isset($parsed['host'])) {
			return $parsed['host'];
		}
		// Bare IP/hostname without scheme
		return strtok($value, "/?#:") ?: $value;
	}
}
