'use strict';

/**
 * Parse a cookie header string into a plain object.
 * e.g. "a=b; c=d" → { a: 'b', c: 'd' }
 *
 * @param {string} cookieStr
 * @returns {Record<string, string>}
 */
function parseCookies(cookieStr) {
  const out = {};
  if (!cookieStr) return out;
  for (const pair of cookieStr.split(';')) {
    const idx = pair.indexOf('=');
    if (idx < 0) continue;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) out[key] = val;
  }
  return out;
}

/**
 * Decode a string up to `maxPasses` times to catch multi-encoded payloads.
 * Strips null bytes before each decode pass.
 *
 * Handles:
 *   - Standard URL encoding (%xx)
 *   - Double URL encoding (%2500 → %00, %2520 → space)
 *   - Unicode escapes (\u003c → <)
 *   - Hex escapes (\x3c → <)
 *   - HTML5 numeric entities (&#60; &#62; &#x3c; &#x3e;)
 *   - Basic named HTML entities (&amp; &lt; &gt; &quot; &#39;)
 */
function deepDecode(value, maxPasses = 3) {
  if (typeof value !== 'string') return String(value);

  let decoded = value;
  for (let i = 0; i < maxPasses; i++) {
    // Strip null bytes
    decoded = decoded.replace(/\x00/g, '');
    try {
      const next = decodeURIComponent(decoded.replace(/\+/g, ' '));
      if (next === decoded) break; // No more decoding possible
      decoded = next;
    } catch {
      break;
    }
  }

  // Double URL encoding: %2500 is a literal %00 after one pass; handle here
  // so patterns that fire on %00 also catch %2500 input.
  decoded = decoded.replace(/%25([0-9a-f]{2})/gi, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );

  // Unicode escape sequences (\u003c, \u003C, etc.)
  decoded = decoded.replace(/\\u([0-9a-f]{4})/gi, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );

  // Hex escape sequences (\x3c, \x3C, etc.)
  decoded = decoded.replace(/\\x([0-9a-f]{2})/gi, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );

  // HTML entity decode — numeric decimal, hex, and common named entities
  decoded = decoded
    .replace(/&#(\d+);/g,       (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&amp;/gi,  '&')
    .replace(/&lt;/gi,   '<')
    .replace(/&gt;/gi,   '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi,  "'");

  return decoded;
}

/**
 * Test a single value against an array of { name, pattern } rules.
 *
 * @param {string} value          - Raw string to test
 * @param {{ name: string, pattern: RegExp }[]} rules
 * @returns {{ rule: string, matched: string } | null}
 */
function matchValue(value, rules) {
  if (typeof value !== 'string' || value.length === 0) return null;

  const decoded = deepDecode(value);

  for (const { name, pattern } of rules) {
    const m = pattern.exec(decoded);
    if (m) {
      return { rule: name, matched: m[0].slice(0, 120) };
    }
  }
  return null;
}

/**
 * Recursively collect all string leaf values from an object/array.
 *
 * @param {*} input
 * @returns {string[]}
 */
function flattenValues(input) {
  if (typeof input === 'string') return [input];
  if (Array.isArray(input)) return input.flatMap(flattenValues);
  if (input && typeof input === 'object') {
    return Object.values(input).flatMap(flattenValues);
  }
  return [];
}

/**
 * Scan all string values in `sources` against the provided rules.
 * Cookie values are sourced from req.cookies (if provided in the source list)
 * or parsed from the raw cookie header string via parseCookies().
 *
 * Each source entry may be:
 *   { label: string, data: * }
 *
 * For cookie sources the label should be 'cookies' and data should be the
 * parsed cookies object (keyed by name).  The returned hit.source will be
 * 'cookie:<name>' when the match originates from a cookie value.
 *
 * @param {Array<{ label: string, data: * }>} sources
 * @param {{ name: string, pattern: RegExp }[]} rules
 * @returns {{ rule: string, source: string, matched: string } | null}
 */
function scanSources(sources, rules) {
  for (const { label, data } of sources) {
    // Special handling for cookies: emit granular source labels per cookie name
    if (label === 'cookies' && data && typeof data === 'object' && !Array.isArray(data)) {
      for (const [cookieName, cookieVal] of Object.entries(data)) {
        if (typeof cookieVal !== 'string') continue;
        const hit = matchValue(cookieVal, rules);
        if (hit) return { ...hit, source: `cookie:${cookieName}` };
      }
      continue;
    }

    const values = flattenValues(data);
    for (const val of values) {
      const hit = matchValue(val, rules);
      if (hit) return { ...hit, source: label };
    }
  }
  return null;
}

/**
 * Convenience wrapper: build a cookies source object from the raw cookie
 * header string.  Use this when req.cookies is not populated by a cookie-
 * parser middleware.
 *
 * @param {string} cookieHeader  - Value of the 'cookie' HTTP header
 * @returns {{ label: string, data: object }}
 */
function cookieSource(cookieHeader) {
  return { label: 'cookies', data: parseCookies(cookieHeader || '') };
}

module.exports = { deepDecode, matchValue, flattenValues, scanSources, parseCookies, cookieSource };
