using System;
using System.Runtime.Caching;
using System.Security.Cryptography;
using System.Text;

namespace FireWTWall
{
    /// <summary>
    /// Sliding-window rate limiter backed by MemoryCache.
    /// Thread-safe; shared across all IIS worker threads in the AppDomain.
    /// </summary>
    public sealed class RateLimiter
    {
        private readonly int          _windowSec;
        private readonly int          _maxRequests;
        private readonly int          _blockDurationSec;
        private static readonly MemoryCache _cache = new MemoryCache("waf_ratelimit");
        private static readonly object      _sync  = new object();

        public RateLimiter(RateLimitConfig config)
        {
            _windowSec        = config.WindowSec;
            _maxRequests      = config.MaxRequests;
            _blockDurationSec = config.BlockDurationSec;
        }

        public struct Result
        {
            public bool Allowed;
            public int  Remaining;
            public int  RetryAfter;
        }

        public Result Check(string ip)
        {
            string key   = "rl_" + Md5(ip);
            string bKey  = "bl_" + Md5(ip);
            long   now   = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            lock (_sync)
            {
                // Is this IP currently blocked?
                object blocked = _cache.Get(bKey);
                if (blocked != null)
                {
                    long until = (long)blocked;
                    int  retry = (int)Math.Max(0, until - now);
                    return new Result { Allowed = false, Remaining = 0, RetryAfter = retry };
                }

                // Fetch or create sliding window entry
                var entry = (long[])_cache.Get(key); // [start, count]
                if (entry == null || now - entry[0] >= _windowSec)
                {
                    entry = new long[] { now, 0 };
                }

                entry[1]++;

                // Store with double-window TTL
                var policy = new CacheItemPolicy
                {
                    AbsoluteExpiration = DateTimeOffset.UtcNow.AddSeconds(_windowSec * 2)
                };
                _cache.Set(key, entry, policy);

                if (entry[1] > _maxRequests)
                {
                    long until = now + _blockDurationSec;
                    _cache.Set(bKey, until, new CacheItemPolicy
                    {
                        AbsoluteExpiration = DateTimeOffset.UtcNow.AddSeconds(_blockDurationSec)
                    });
                    return new Result { Allowed = false, Remaining = 0, RetryAfter = _blockDurationSec };
                }

                int remaining = Math.Max(0, _maxRequests - (int)entry[1]);
                return new Result { Allowed = true, Remaining = remaining, RetryAfter = 0 };
            }
        }

        private static string Md5(string input)
        {
            using (var md5 = MD5.Create())
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }
    }
}
