<?php

namespace FireWTWall\Detectors;

use FireWTWall\Request;

/**
 * Detects Remote File Inclusion (RFI) attempts.
 *
 * Only activates when the parameter name is one of a known set of file/path
 * carrying names.  Checks each value for remote URL schemes and dangerous
 * pseudo-protocols that could cause the server to include a remote resource.
 *
 * Requires PHP >= 8.0
 */
class RfiDetector
{
	/** Parameter names commonly used to pass file or include paths */
	private const FILE_PARAMS = [
		'page', 'file', 'include', 'require', 'template', 'view', 'document',
		'folder', 'root', 'path', 'pg', 'style', 'pdf', 'layout', 'conf',
		'config', 'inc', 'mod', 'module', 'load', 'show',
	];

	private static array $rules = [
		['id' => 'rfi-http',       'pattern' => '/^https?:\/\//i',                 'severity' => 'critical'],
		['id' => 'rfi-ftp',        'pattern' => '/^ftp:\/\//i',                    'severity' => 'critical'],
		['id' => 'rfi-smb',        'pattern' => '/^\\\\\\\\/i',                    'severity' => 'critical'],
		['id' => 'rfi-expect',     'pattern' => '/^expect:\/\//i',                  'severity' => 'critical'],
		['id' => 'rfi-data',       'pattern' => '/^data:text\/plain;base64,/i',    'severity' => 'critical'],
		['id' => 'rfi-log-poison', 'pattern' => '/\/var\/log\/(apache|nginx|httpd|auth|syslog|mail)|\/proc\/self\/environ/i', 'severity' => 'critical'],
	];

	/**
	 * Scan the request for RFI payloads.
	 *
	 * @param  Request $request  Normalised request object
	 * @param  array   $config   WAF configuration (reserved for future use)
	 * @return array{rule:string,matched:string,source:string,severity:string}|null
	 */
	public static function scan(Request $request, array $config): ?array
	{
		$allSources = [
			'query'   => $request->getQuery(),
			'body'    => $request->getBody(),
			'cookies' => $request->getCookies(),
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
	 * Walk a (possibly nested) array and check values whose key is a known
	 * file/include parameter name.
	 */
	private static function scanFlat(array $data, string $sourceLabel, string $prefix = ''): ?array
	{
		foreach ($data as $key => $value) {
			if (is_array($value)) {
				$paramName = $prefix !== '' ? $prefix . '[' . $key . ']' : (string) $key;
				$result    = self::scanFlat($value, $sourceLabel, $paramName);
				if ($result !== null) {
					return $result;
				}
				continue;
			}

			if (!is_string($value)) {
				continue;
			}

			// Only inspect parameters whose name suggests a file/include path
			if (!in_array(strtolower((string) $key), self::FILE_PARAMS, true)) {
				continue;
			}

			foreach (self::$rules as $rule) {
				if (preg_match($rule['pattern'], $value, $m)) {
					return [
						'rule'     => $rule['id'],
						'severity' => $rule['severity'],
						'matched'  => substr($m[0], 0, 120),
						'source'   => $sourceLabel,
					];
				}
			}
		}

		return null;
	}
}
