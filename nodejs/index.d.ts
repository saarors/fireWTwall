import { RequestHandler } from 'express';

/** Options for the built-in sliding-window rate limiter. */
export interface RateLimitOptions {
  /** Time window in milliseconds (default: 60000). */
  windowMs?: number;
  /** Maximum number of requests allowed within the window (default: 100). */
  maxRequests?: number;
  /** How long (ms) an IP stays blocked after exceeding the limit (default: 60000). */
  blockDurationMs?: number;
}

/** Top-level WAF configuration object. */
export interface WAFOptions {
  /**
   * `'reject'`    — actively block and return 403 responses (default).
   * `'log-only'`  — log but do not block; useful for testing.
   */
  mode?: 'reject' | 'log-only';

  /** HTTP methods to allow. Any other method is rejected with 405. */
  allowedMethods?: string[];

  /** Maximum request body size in bytes before the request is rejected. */
  maxBodySize?: number;

  /** Rate-limiter configuration. */
  rateLimit?: RateLimitOptions;

  /** IP addresses or CIDR ranges that bypass all WAF checks. */
  whitelist?: string[];

  /** IP addresses or CIDR ranges that are always blocked. */
  blacklist?: string[];

  /** URL path prefixes that skip all WAF checks (e.g. ['/healthz']). */
  bypassPaths?: string[];

  /**
   * IP addresses or CIDR ranges of trusted reverse proxies.
   * Used to determine the real client IP from X-Forwarded-For.
   */
  trustedProxies?: string[];

  /** Absolute or relative path to the WAF NDJSON log file. */
  logPath?: string;

  /** Response format for block responses. */
  responseType?: 'json' | 'html';

  /** Enable verbose per-request debug logging. */
  debug?: boolean;
}

/**
 * Interface for a pluggable key/value store used by the rate limiter.
 * Implement this to use Redis, Memcached, or any other backend.
 */
export interface StoreAdapter {
  get(key: string): Promise<any>;
  set(key: string, value: any): Promise<void>;
  del(key: string): Promise<void>;
}

/**
 * Creates a WAF middleware stack for Express.
 *
 * @example
 * import express from 'express';
 * import { createWAF } from 'firewtwall';
 *
 * const app = express();
 * app.use(...createWAF({ mode: 'reject', rateLimit: { maxRequests: 200 } }));
 */
export function createWAF(options?: WAFOptions): RequestHandler[];

/**
 * Swap the in-process rate-limit store for an external adapter (e.g. Redis).
 *
 * @example
 * import { setStore } from 'firewtwall';
 * setStore(myRedisAdapter);
 */
export function setStore(adapter: StoreAdapter): void;
