<?php

namespace FireWTWall;

/**
 * IP blacklist / whitelist filter with CIDR support (IPv4 and IPv6).
 */
class IpFilter
{
    private array $whitelist;
    private array $blacklist;

    public function __construct(array $whitelist = [], array $blacklist = [])
    {
        $this->whitelist = $whitelist;
        $this->blacklist = $blacklist;
    }

    /** Returns 'whitelist', 'blacklist', or null */
    public function check(string $ip): ?string
    {
        if (!empty($this->whitelist) && self::ipInList($ip, $this->whitelist)) {
            return 'whitelist';
        }
        if (!empty($this->blacklist) && self::ipInList($ip, $this->blacklist)) {
            return 'blacklist';
        }
        return null;
    }

    // ------------------------------------------------------------------ //
    // Static helpers (used by Request::resolveIp as well)
    // ------------------------------------------------------------------ //

    public static function ipInList(string $ip, array $list): bool
    {
        foreach ($list as $entry) {
            if (self::ipMatchesEntry($ip, $entry)) return true;
        }
        return false;
    }

    public static function ipMatchesEntry(string $ip, string $entry): bool
    {
        if (strpos($entry, '/') === false) {
            return $ip === $entry;
        }
        return self::ipInCidr($ip, $entry);
    }

    public static function ipInCidr(string $ip, string $cidr): bool
    {
        [$range, $prefix] = explode('/', $cidr, 2);
        $prefix = (int) $prefix;

        // IPv6
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::ipv6InCidr($ip, $range, $prefix);
        }
        // IPv4
        return self::ipv4InCidr($ip, $range, $prefix);
    }

    private static function ipv4InCidr(string $ip, string $range, int $prefix): bool
    {
        $ipLong    = ip2long($ip);
        $rangeLong = ip2long($range);
        if ($ipLong === false || $rangeLong === false) return false;
        $mask = $prefix === 0 ? 0 : (~0 << (32 - $prefix));
        return ($ipLong & $mask) === ($rangeLong & $mask);
    }

    private static function ipv6InCidr(string $ip, string $range, int $prefix): bool
    {
        $ipBin    = inet_pton($ip);
        $rangeBin = inet_pton($range);
        if ($ipBin === false || $rangeBin === false) return false;

        $byteCount  = (int) ceil($prefix / 8);
        $remaining  = $prefix % 8;

        for ($i = 0; $i < $byteCount - 1; $i++) {
            if ($ipBin[$i] !== $rangeBin[$i]) return false;
        }
        if ($byteCount > 0 && $remaining > 0) {
            $mask = 0xFF & (0xFF << (8 - $remaining));
            if ((ord($ipBin[$byteCount - 1]) & $mask) !== (ord($rangeBin[$byteCount - 1]) & $mask)) {
                return false;
            }
        }
        return true;
    }
}
