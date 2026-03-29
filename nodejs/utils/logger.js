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

  process.on('exit', () => {
    try { _stream.end(); } catch {}
  });

  return _stream;
}

function write(logPath, entry) {
  try {
    getStream(logPath).write(JSON.stringify(entry) + '\n');
  } catch (err) {
    console.error('[WAF] Log write error:', err.message);
  }
}

/**
 * Log a blocked / flagged request.
 */
function logBlock(opts) {
  write(opts.logPath, {
    timestamp:  new Date().toISOString(),
    requestId:  opts.requestId || crypto.randomBytes(8).toString('hex'),
    result:     'blocked',
    ip:         opts.ip,
    method:     opts.method,
    path:       opts.path,
    rule:       opts.rule,
    matched:    opts.matched    || '',
    source:     opts.source     || '',
    severity:   opts.severity   || 'medium',
    userAgent:  opts.userAgent  || '',
    durationMs: opts.durationMs ?? null,
  });
}

/**
 * Log a request that passed all WAF checks (debug mode only).
 */
function logPass(opts) {
  write(opts.logPath, {
    timestamp:  new Date().toISOString(),
    requestId:  opts.requestId || crypto.randomBytes(8).toString('hex'),
    result:     'passed',
    ip:         opts.ip,
    method:     opts.method,
    path:       opts.path,
    userAgent:  opts.userAgent  || '',
    durationMs: opts.durationMs ?? null,
  });
}

module.exports = { logBlock, logPass };
