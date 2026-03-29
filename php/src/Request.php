<?php

namespace FireWTWall;

/**
 * Normalises and wraps the current HTTP request.
 * All string values are URL-decoded (up to 3 passes) and null-byte stripped.
 *
 * Requires PHP >= 8.0
 */
class Request
{
    private string $method;
    private string $path;
    private string $ip;
    private string $userAgent;
    private array  $query;
    private array  $body;
    private array  $cookies;
    private array  $headers;
    private string $rawBody;
    private int    $contentLength;

    public function __construct(array $trustedProxies = [])
    {
        $this->method        = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $this->path          = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?? '/';
        $this->userAgent     = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $this->contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        $this->ip            = $this->resolveIp($trustedProxies);
        $this->headers       = $this->collectHeaders();

        $this->query   = $this->decodeArray($_GET);
        $this->body    = $this->decodeArray($_POST);
        $this->cookies = $this->decodeArray($_COOKIE);
        $this->rawBody = $this->readRawBody();
    }

    // ------------------------------------------------------------------ //
    // Accessors
    // ------------------------------------------------------------------ //

    public function getMethod(): string       { return $this->method; }
    public function getPath(): string         { return $this->path; }
    public function getIp(): string           { return $this->ip; }
    public function getUserAgent(): string    { return $this->userAgent; }
    public function getQuery(): array         { return $this->query; }
    public function getBody(): array          { return $this->body; }
    public function getCookies(): array       { return $this->cookies; }
    public function getHeaders(): array       { return $this->headers; }
    public function getRawBody(): string      { return $this->rawBody; }
    public function getContentLength(): int   { return $this->contentLength; }

    // ------------------------------------------------------------------ //
    // Helpers
    // ------------------------------------------------------------------ //

    private function resolveIp(array $trustedProxies): string
    {
        $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        if (empty($trustedProxies)) {
            return $remote;
        }

        // IpFilter is guaranteed to be loaded by WAF.php before Request is instantiated
        if (!IpFilter::ipInList($remote, $trustedProxies)) {
            return $remote;
        }

        $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($xff === '') {
            return $remote;
        }

        // Walk from right; the first non-trusted IP is the real client
        $candidates = array_reverse(array_map('trim', explode(',', $xff)));
        foreach ($candidates as $candidate) {
            if (filter_var($candidate, FILTER_VALIDATE_IP)
                && !IpFilter::ipInList($candidate, $trustedProxies)) {
                return $candidate;
            }
        }

        return $remote;
    }

    /**
     * Collect HTTP request headers into a normalised array.
     * Keys are lowercased header names (e.g. 'content-type', 'x-forwarded-for').
     */
    private function collectHeaders(): array
    {
        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $name = strtolower(str_replace('_', '-', substr($key, 5)));
                $headers[$name] = $value;
            }
        }
        if (isset($_SERVER['CONTENT_TYPE'])) {
            $headers['content-type'] = $_SERVER['CONTENT_TYPE'];
        }
        if (isset($_SERVER['CONTENT_LENGTH'])) {
            $headers['content-length'] = $_SERVER['CONTENT_LENGTH'];
        }
        return $headers;
    }

    /**
     * Recursively URL-decode all string values in an array (up to 3 passes)
     * and strip null bytes.
     */
    private function decodeArray(array $data): array
    {
        array_walk_recursive($data, function (&$val): void {
            if (is_string($val)) {
                $val = $this->deepDecode($val);
            }
        });
        return $data;
    }

    public function deepDecode(string $value, int $maxPasses = 3): string
    {
        $prev = null;
        for ($i = 0; $i < $maxPasses; $i++) {
            $value   = str_replace("\x00", '', $value);
            $decoded = rawurldecode($value);
            if ($decoded === $prev) break;
            $prev  = $value;
            $value = $decoded;
        }
        return html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    private function readRawBody(): string
    {
        static $body = null;
        if ($body === null) {
            $body = (string) @file_get_contents('php://input');
        }
        return $body;
    }
}
