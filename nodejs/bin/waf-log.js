#!/usr/bin/env node
'use strict';

/**
 * fireWTwall log viewer
 *
 * Usage:
 *   node bin/waf-log.js [options] [logfile]
 *
 * Options:
 *   --tail   N     Show last N entries (default 50)
 *   --stats        Show summary statistics instead of entries
 *   --blocked      Show only blocked entries
 *   --passed       Show only passed entries (debug mode logs)
 *   --ip    ADDR   Filter by IP address
 *   --rule  NAME   Filter by rule name (partial match)
 *   --since DATE   Show entries after this ISO date (e.g. 2026-03-29T12:00:00Z)
 *   --json         Raw NDJSON output (no colour / formatting)
 *   --help         Show this help
 */

const fs   = require('fs');
const path = require('path');
const readline = require('readline');

// ------------------------------------------------------------------ //
// Colour helpers (gracefully degrade if NO_COLOR is set)
// ------------------------------------------------------------------ //
const NO_COLOR = process.env.NO_COLOR || !process.stdout.isTTY;
const c = {
  red:     (s) => NO_COLOR ? s : `\x1b[31m${s}\x1b[0m`,
  yellow:  (s) => NO_COLOR ? s : `\x1b[33m${s}\x1b[0m`,
  cyan:    (s) => NO_COLOR ? s : `\x1b[36m${s}\x1b[0m`,
  green:   (s) => NO_COLOR ? s : `\x1b[32m${s}\x1b[0m`,
  grey:    (s) => NO_COLOR ? s : `\x1b[90m${s}\x1b[0m`,
  bold:    (s) => NO_COLOR ? s : `\x1b[1m${s}\x1b[0m`,
  magenta: (s) => NO_COLOR ? s : `\x1b[35m${s}\x1b[0m`,
};

// ------------------------------------------------------------------ //
// Argument parsing
// ------------------------------------------------------------------ //
const args = process.argv.slice(2);

function flag(name)       { return args.includes(name); }
function opt(name, def)   { const i = args.indexOf(name); return i !== -1 ? args[i + 1] : def; }

if (flag('--help') || flag('-h')) {
  console.log(fs.readFileSync(__filename, 'utf8').match(/\/\*\*([\s\S]*?)\*\//)[0]
    .replace(/\/\*\*|\*\//g, '').replace(/^\s*\* ?/gm, '').trim());
  process.exit(0);
}

const tailN    = parseInt(opt('--tail', '50'), 10);
const showStats = flag('--stats');
const onlyBlocked = flag('--blocked');
const onlyPassed  = flag('--passed');
const filterIp   = opt('--ip', null);
const filterRule = opt('--rule', null);
const sinceDate  = opt('--since', null) ? new Date(opt('--since', null)) : null;
const rawJson    = flag('--json');

// Positional arg = log file path
const logFile = args.find((a) => !a.startsWith('--') && args[args.indexOf(a) - 1] !== '--tail'
  && args[args.indexOf(a) - 1] !== '--ip' && args[args.indexOf(a) - 1] !== '--rule'
  && args[args.indexOf(a) - 1] !== '--since')
  || path.resolve(process.cwd(), 'logs/waf.log');

if (!fs.existsSync(logFile)) {
  console.error(c.red(`Log file not found: ${logFile}`));
  process.exit(1);
}

// ------------------------------------------------------------------ //
// Read and parse NDJSON
// ------------------------------------------------------------------ //
async function readEntries() {
  const entries = [];
  const rl = readline.createInterface({ input: fs.createReadStream(logFile), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    try { entries.push(JSON.parse(line)); } catch { /* skip malformed */ }
  }
  return entries;
}

// ------------------------------------------------------------------ //
// Filters
// ------------------------------------------------------------------ //
function applyFilters(entries) {
  return entries.filter((e) => {
    if (onlyBlocked && e.result !== 'blocked') return false;
    if (onlyPassed  && e.result !== 'passed')  return false;
    if (filterIp   && e.ip !== filterIp)        return false;
    if (filterRule && !e.rule?.includes(filterRule)) return false;
    if (sinceDate  && new Date(e.timestamp) < sinceDate) return false;
    return true;
  });
}

// ------------------------------------------------------------------ //
// Formatters
// ------------------------------------------------------------------ //
function severityColor(sev) {
  if (sev === 'critical') return c.red(sev);
  if (sev === 'high')     return c.yellow(sev);
  return c.cyan(sev);
}

function resultColor(r) {
  return r === 'blocked' ? c.red(r) : c.green(r);
}

function formatEntry(e) {
  const ts      = c.grey(e.timestamp);
  const id      = c.grey(e.requestId?.slice(0, 8) || '--------');
  const result  = resultColor(e.result || 'blocked');
  const method  = c.bold(e.method?.padEnd(6) || '?     ');
  const ip      = c.magenta((e.ip || '?').padEnd(15));
  const reqPath = e.path || '/';

  if (e.result === 'passed') {
    const dur = e.durationMs != null ? c.grey(` ${e.durationMs}ms`) : '';
    return `${ts} ${id} ${result} ${method} ${ip} ${reqPath}${dur}`;
  }

  const rule    = c.yellow(e.rule || '?');
  const matched = e.matched ? c.grey(` matched:"${e.matched.slice(0, 60)}"`) : '';
  const source  = e.source  ? c.grey(` [${e.source}]`) : '';
  const sev     = e.severity ? ` ${severityColor(e.severity)}` : '';
  const dur     = e.durationMs != null ? c.grey(` ${e.durationMs}ms`) : '';

  return `${ts} ${id} ${result} ${method} ${ip} ${reqPath} → ${rule}${source}${matched}${sev}${dur}`;
}

// ------------------------------------------------------------------ //
// Stats
// ------------------------------------------------------------------ //
function showStatsReport(entries) {
  const blocked = entries.filter((e) => e.result === 'blocked' || !e.result);
  const passed  = entries.filter((e) => e.result === 'passed');

  console.log(c.bold('\n── fireWTwall log stats ──────────────────────────────'));
  console.log(`  Total entries : ${c.bold(String(entries.length))}`);
  console.log(`  Blocked       : ${c.red(String(blocked.length))}`);
  console.log(`  Passed        : ${c.green(String(passed.length))}`);
  if (entries.length) {
    console.log(`  From          : ${c.grey(entries[0].timestamp)}`);
    console.log(`  To            : ${c.grey(entries[entries.length - 1].timestamp)}`);
  }

  // Top rules
  const ruleCounts = {};
  for (const e of blocked) ruleCounts[e.rule] = (ruleCounts[e.rule] || 0) + 1;
  const topRules = Object.entries(ruleCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (topRules.length) {
    console.log(c.bold('\n  Top rules:'));
    for (const [rule, count] of topRules) {
      console.log(`    ${String(count).padStart(5)}  ${c.yellow(rule)}`);
    }
  }

  // Top IPs
  const ipCounts = {};
  for (const e of blocked) ipCounts[e.ip] = (ipCounts[e.ip] || 0) + 1;
  const topIps = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (topIps.length) {
    console.log(c.bold('\n  Top offending IPs:'));
    for (const [ip, count] of topIps) {
      console.log(`    ${String(count).padStart(5)}  ${c.magenta(ip)}`);
    }
  }

  // Severity breakdown
  const sevCounts = { critical: 0, high: 0, medium: 0 };
  for (const e of blocked) if (e.severity in sevCounts) sevCounts[e.severity]++;
  console.log(c.bold('\n  Severity breakdown:'));
  console.log(`    ${c.red('critical')} : ${sevCounts.critical}`);
  console.log(`    ${c.yellow('high')}     : ${sevCounts.high}`);
  console.log(`    ${c.cyan('medium')}   : ${sevCounts.medium}`);
  console.log();
}

// ------------------------------------------------------------------ //
// Main
// ------------------------------------------------------------------ //
(async () => {
  const all      = await readEntries();
  const filtered = applyFilters(all);
  const slice    = showStats ? filtered : filtered.slice(-tailN);

  if (rawJson) {
    for (const e of slice) console.log(JSON.stringify(e));
    return;
  }

  if (showStats) {
    showStatsReport(filtered);
    return;
  }

  if (slice.length === 0) {
    console.log(c.grey('No matching log entries found.'));
    return;
  }

  console.log(c.bold(`\n── fireWTwall log (last ${slice.length} of ${filtered.length} filtered) ──`));
  for (const e of slice) console.log(formatEntry(e));
  console.log();
})();
