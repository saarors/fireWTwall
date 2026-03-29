'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

let _stream = null;
let _logPath = null;

function getStream(logPath) {
  if (_stream && _logPath === logPath) return _stream;

  const dir = path.dirname(logPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  _logPath = logPath;
  _stream = fs.createWriteStream(logPath, { flags: 'a', highWaterMark: 64 * 1024 });

  // Flush buffer on process exit
  process.on('exit', () => {
    try { _stream.end(); } catch {}
  });

  return _stream;
}

/**
 * Write a structured NDJSON log entry for a blocked (or flagged) request.
 *
 * @param {object} opts
 * @param {string}  opts.logPath
 * @param {string}  opts.ip
 * @param {string}  opts.method
 * @param {string}  opts.path
 * @param {string}  opts.rule
 * @param {string}  [opts.matched]
 * @param {string}  [opts.source]
 * @param {string}  [opts.severity]
 * @param {string}  [opts.userAgent]
 */
function logBlock(opts) {
  const entry = {
    timestamp: new Date().toISOString(),
    requestId: crypto.randomBytes(8).toString('hex'),
    ip: opts.ip,
    method: opts.method,
    path: opts.path,
    rule: opts.rule,
    matched: opts.matched || '',
    source: opts.source || '',
    severity: opts.severity || 'medium',
    userAgent: opts.userAgent || '',
  };

  try {
    getStream(opts.logPath).write(JSON.stringify(entry) + '\n');
  } catch (err) {
    // Don't let logging errors crash the app
    console.error('[WAF] Log write error:', err.message);
  }
}

module.exports = { logBlock };
