'use strict';

/**
 * Decode a string up to `maxPasses` times to catch multi-encoded payloads.
 * Strips null bytes before each decode pass.
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

  // HTML entity decode (basic — covers numeric and named entities)
  decoded = decoded
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'");

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
 *
 * @param {Array<{ label: string, data: * }>} sources
 * @param {{ name: string, pattern: RegExp }[]} rules
 * @returns {{ rule: string, source: string, matched: string } | null}
 */
function scanSources(sources, rules) {
  for (const { label, data } of sources) {
    const values = flattenValues(data);
    for (const val of values) {
      const hit = matchValue(val, rules);
      if (hit) return { ...hit, source: label };
    }
  }
  return null;
}

module.exports = { deepDecode, matchValue, flattenValues, scanSources };
