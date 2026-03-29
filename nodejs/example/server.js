'use strict';

const express = require('express');
const { createWAF } = require('../waf');

const app = express();

// --- Parse body BEFORE WAF so body inspection works ---
app.use(express.json({ limit: '11mb' }));     // limit slightly above WAF default — WAF wins via Content-Length check
app.use(express.urlencoded({ extended: true }));
app.use(express.text());

// --- Mount the WAF ---
app.use(...createWAF({
  mode: 'reject',
  rateLimit: {
    windowMs: 60 * 1000,
    maxRequests: 60,
    blockDurationMs: 5 * 60 * 1000,
  },
  logPath: './logs/waf.log',
}));

// --- Application routes ---
app.get('/', (req, res) => {
  res.json({ message: 'Hello! This route is protected by fireWTwall.' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/search', (req, res) => {
  const { q } = req.body;
  res.json({ query: q, results: [] });
});

// --- Start ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[fireWTwall] Example server listening on http://localhost:${PORT}`);
  console.log('Try attacking it:');
  console.log(`  curl "http://localhost:${PORT}/search?q=1+UNION+SELECT+*+FROM+users"`);
  console.log(`  curl "http://localhost:${PORT}/?q=<script>alert(1)</script>"`);
  console.log(`  curl "http://localhost:${PORT}/../../../etc/passwd"`);
});
