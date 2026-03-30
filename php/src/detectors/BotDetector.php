<?php

namespace FireWTWall\Detectors;

class BotDetector
{
    private array $blockedPatterns;
    private array $allowedPatterns;
    private bool  $blockEmptyUA;
    private array $suspiciousPatterns = [
        '/^(curl|wget|python|perl|ruby|php|java|go|node)[\s\/\-]/i',
        '/^libcurl/i',
        '/^HTTPClient/i',
        '/^Apache-HttpClient/i',
        '/^OkHttpClient/i',
        '/^java\.net\.URLConnection/i',
        '/^scrapy/i',
        '/^mechanize/i',
        '/^urllib/i',
    ];

    public function __construct(array $botsConfig)
    {
        $this->blockedPatterns = array_map(
            fn($s) => '/' . preg_quote($s, '/') . '/i',
            $botsConfig['blocked'] ?? []
        );
        $this->allowedPatterns = array_map(
            fn($s) => '/' . preg_quote($s, '/') . '/i',
            $botsConfig['allowed'] ?? []
        );
        // Default true — no legitimate browser or API client omits User-Agent
        $this->blockEmptyUA = $botsConfig['block_empty_user_agent'] ?? true;
    }

    /**
     * @return array{rule: string, matched: string}|null
     */
    public function check(string $userAgent): ?array
    {
        // Block missing / empty User-Agent
        if ($userAgent === '') {
            if ($this->blockEmptyUA) {
                return ['rule' => 'missing-user-agent', 'matched' => ''];
            }
            return null;
        }

        // Allowed bots always pass
        foreach ($this->allowedPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) return null;
        }

        // Check blocklist
        foreach ($this->blockedPatterns as $pattern) {
            if (preg_match($pattern, $userAgent, $m)) {
                return ['rule' => 'bad-bot', 'matched' => substr($m[0], 0, 120)];
            }
        }

        // Check for suspicious programmatic patterns (curl, python, etc.)
        foreach ($this->suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent, $m)) {
                return ['rule' => 'suspicious-automation', 'matched' => substr($m[0] ?? $userAgent, 0, 120)];
            }
        }

        return null;
    }
}
