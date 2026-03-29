'use strict';

const net = require('net');

/**
 * Convert an IPv4 address string to a 32-bit integer.
 */
function ipv4ToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

/**
 * Check whether an IPv4 address is within a CIDR range.
 * @param {string} ip   - e.g. "192.168.1.50"
 * @param {string} cidr - e.g. "192.168.1.0/24"
 */
function ipv4InCidr(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const mask = bits === undefined ? 32 : parseInt(bits, 10);
  const maskInt = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
  return (ipv4ToInt(ip) & maskInt) === (ipv4ToInt(range) & maskInt);
}

/**
 * Expand an IPv6 address to its full 128-bit representation.
 */
function expandIPv6(ip) {
  // Remove zone ID
  ip = ip.split('%')[0];
  // Handle :: expansion
  if (ip.includes('::')) {
    const [left, right] = ip.split('::');
    const leftGroups = left ? left.split(':') : [];
    const rightGroups = right ? right.split(':') : [];
    const missing = 8 - leftGroups.length - rightGroups.length;
    const middle = Array(missing).fill('0000');
    return [...leftGroups, ...middle, ...rightGroups]
      .map((g) => g.padStart(4, '0'))
      .join(':');
  }
  return ip.split(':').map((g) => g.padStart(4, '0')).join(':');
}

/**
 * Convert an expanded IPv6 address to a BigInt.
 */
function ipv6ToBigInt(ip) {
  return BigInt('0x' + expandIPv6(ip).replace(/:/g, ''));
}

/**
 * Check whether an IPv6 address is within a CIDR range.
 */
function ipv6InCidr(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const prefix = bits === undefined ? 128 : parseInt(bits, 10);
  const shift = BigInt(128 - prefix);
  const ipInt = ipv6ToBigInt(ip) >> shift;
  const rangeInt = ipv6ToBigInt(range) >> shift;
  return ipInt === rangeInt;
}

/**
 * Determine whether `ip` matches `entry`, where entry can be:
 *   - An exact IP address
 *   - An IPv4 CIDR (e.g. "10.0.0.0/8")
 *   - An IPv6 CIDR
 *
 * @param {string} ip
 * @param {string} entry
 * @returns {boolean}
 */
function ipMatchesEntry(ip, entry) {
  if (!ip || !entry) return false;

  // Strip IPv6 zone ID from the incoming IP
  const cleanIp = ip.split('%')[0];

  const hasCidr = entry.includes('/');

  if (!hasCidr) {
    return cleanIp === entry;
  }

  const isIPv6 = entry.includes(':') || cleanIp.includes(':');

  try {
    return isIPv6 ? ipv6InCidr(cleanIp, entry) : ipv4InCidr(cleanIp, entry);
  } catch {
    return false;
  }
}

/**
 * Returns true if `ip` matches any entry in the list.
 * @param {string} ip
 * @param {string[]} list
 */
function ipInList(ip, list) {
  return list.some((entry) => ipMatchesEntry(ip, entry));
}

/**
 * Extract the real client IP from a request, respecting trusted proxies.
 * @param {import('http').IncomingMessage} req
 * @param {string[]} trustedProxies
 */
function extractIp(req, trustedProxies = []) {
  const remoteIp = req.socket?.remoteAddress || '0.0.0.0';

  if (trustedProxies.length === 0) return remoteIp;
  if (!ipInList(remoteIp, trustedProxies)) return remoteIp;

  const xff = req.headers['x-forwarded-for'];
  if (!xff) return remoteIp;

  // X-Forwarded-For: client, proxy1, proxy2
  // The leftmost non-trusted IP is the real client.
  const candidates = xff.split(',').map((s) => s.trim()).reverse();
  for (const candidate of candidates) {
    if (net.isIP(candidate) && !ipInList(candidate, trustedProxies)) {
      return candidate;
    }
  }
  return remoteIp;
}

module.exports = { ipMatchesEntry, ipInList, extractIp };
