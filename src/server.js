const fs = require('fs');
const path = require('path');
const express = require('express');
const { loadAll } = require('./store');
const { scanLog, scanLogWithContext } = require('./scan');
const watchlist = require('./watchlist');
const { DATA_DIR } = require('./paths');
const { FEEDS } = require('./fetch');

const VALID_TYPES = new Set(Object.keys(FEEDS));

const HISTORY_FILE = path.join(DATA_DIR, 'history.jsonl');

const app = express();
let store = loadAll();

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now() - start}ms`);
  });
  next();
});

const CORS_ORIGIN = process.env.CORS_ORIGIN;
if (CORS_ORIGIN) {
  app.use((req, res, next) => {
    res.set('Access-Control-Allow-Origin', CORS_ORIGIN);
    res.set('Access-Control-Allow-Methods', 'GET, POST, DELETE');
    res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
  });
}

const RATE_LIMIT = Number(process.env.RATE_LIMIT) || 60; // requests per minute per IP
const hits = new Map();
app.use((req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  const entry = hits.get(ip) || { count: 0, reset: now + 60_000 };
  if (now > entry.reset) {
    entry.count = 0;
    entry.reset = now + 60_000;
  }
  entry.count += 1;
  hits.set(ip, entry);
  if (entry.count > RATE_LIMIT) return res.status(429).json({ error: 'rate limit exceeded' });
  next();
});

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of hits) {
    if (now > entry.reset) hits.delete(ip);
  }
}, 5 * 60_000).unref();

app.use(express.static(path.join(__dirname, '..', 'public')));

const { parseTokens, makeRequireAdmin } = require('./auth');
const adminTokens = parseTokens(process.env);
if (Object.keys(adminTokens).length === 0) {
  console.warn('no ADMIN_TOKEN/ADMIN_TOKENS set — /watch and /reload are unauthenticated; do not expose this publicly as-is');
}
const requireAdmin = makeRequireAdmin(adminTokens);

function expiresAt(generatedAt, validDays) {
  if (!generatedAt || !validDays) return null;
  const d = new Date(generatedAt);
  d.setDate(d.getDate() + validDays);
  return d.toISOString().slice(0, 10);
}

app.get('/stats', (req, res) => {
  const stats = {};
  for (const [type, d] of Object.entries(store)) {
    if (!d) { stats[type] = null; continue; }
    const m = d.meta;
    stats[type] = {
      total: m.total,
      generated_at: m.generated_at,
      valid_for_days: m.valid_for_days ?? null,
      expires_at: expiresAt(m.generated_at, m.valid_for_days),
      tlp: m.tlp?.[0] ?? null,
      sha256: m.file?.sha256 ?? null,
      feed: m.feed ?? null,
    };
  }
  res.json(stats);
});

app.get('/info', (req, res) => {
  const info = {};
  for (const [type, d] of Object.entries(store)) {
    if (!d) { info[type] = null; continue; }
    const m = d.meta;
    info[type] = {
      feed: m.feed,
      description: m.description,
      publisher: m.publisher,
      country: m.country,
      license: m.license,
      contact: m.contact,
      homepage: m.homepage,
      tlp: m.tlp,
      source: m.source,
      generated_at: m.generated_at,
      valid_for_days: m.valid_for_days,
      expires_at: expiresAt(m.generated_at, m.valid_for_days),
      total: m.total,
      sha256: m.file?.sha256,
    };
  }
  res.json(info);
});

app.get('/check/auto/:value', (req, res) => {
  const { value } = req.params;
  const type = /^[0-9a-f]{64}$/i.test(value) ? 'hash'
    : /^\d{1,3}(\.\d{1,3}){3}$/.test(value) ? 'ip'
    : 'domain';
  const d = store[type];
  if (!d) return res.status(503).json({ error: `${type} data not loaded` });
  res.json({ type, value, blacklisted: d.set.has(value) });
});

app.get('/check/:type/:value', (req, res) => {
  const { type, value } = req.params;
  const d = store[type];
  if (!d) return res.status(404).json({ error: `unknown type: ${type}` });
  res.json({ type, value, blacklisted: d.set.has(value) });
});

app.post('/scan', express.text({ limit: '2mb' }), (req, res) => {
  const d = store.ip;
  if (!d) return res.status(503).json({ error: 'ip data not loaded' });
  res.json(scanLogWithContext(req.body || '', d.set));
});

app.post('/check/bulk', express.json({ limit: '1mb' }), (req, res) => {
  const { type, values } = req.body || {};
  if (!type || !Array.isArray(values)) return res.status(400).json({ error: 'type and values[] required' });
  if (!VALID_TYPES.has(type)) return res.status(400).json({ error: `type must be one of: ${[...VALID_TYPES].join(', ')}` });
  if (values.length > 10000) return res.status(400).json({ error: 'max 10000 values per request' });
  const d = store[type];
  if (!d) return res.status(503).json({ error: `${type} data not loaded` });
  res.json({ type, results: values.map((v) => ({ value: String(v), blacklisted: d.set.has(String(v)) })) });
});

app.get('/search', (req, res) => {
  const { type, q } = req.query;
  if (!type || !q) return res.status(400).json({ error: 'type and q required' });
  if (!VALID_TYPES.has(type)) return res.status(400).json({ error: `type must be one of: ${[...VALID_TYPES].join(', ')}` });
  if (q.length < 3) return res.status(400).json({ error: 'q must be at least 3 characters' });
  const d = store[type];
  if (!d) return res.status(503).json({ error: `${type} data not loaded` });
  const results = [];
  for (const v of d.set) {
    if (v.includes(q)) { results.push(v); if (results.length >= 100) break; }
  }
  res.json({ type, q, count: results.length, capped: results.length === 100, results });
});

app.post('/reload', requireAdmin, (req, res) => {
  store = loadAll();
  console.log(`reload by admin "${req.adminName || 'default'}"`);
  res.json({ reloaded: true });
});

app.get('/history', (req, res) => {
  const { type } = req.query;
  if (!fs.existsSync(HISTORY_FILE)) return res.json([]);
  const lines = fs.readFileSync(HISTORY_FILE, 'utf8').trim().split('\n').filter(Boolean);
  const entries = lines.map((l) => JSON.parse(l)).filter((e) => !type || e.type === type);
  res.json(entries.slice(-30));
});

app.get('/export/iptables', (req, res) => {
  const d = store.ip;
  if (!d) return res.status(503).send('# ip data not loaded — run fetch first\n');
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="ncsa-iptables.sh"');
  const lines = ['#!/bin/sh', `# generated from NCSA ip blocklist — ${d.meta.generated_at}`,
    'ipset create ncsa-blacklist hash:ip -exist'];
  for (const ip of d.set) lines.push(`ipset add ncsa-blacklist ${ip} -exist`);
  lines.push('iptables -I INPUT -m set --match-set ncsa-blacklist src -j DROP');
  res.send(lines.join('\n') + '\n');
});

app.get('/export/dnsmasq', (req, res) => {
  const d = store.domain;
  if (!d) return res.status(503).send('# domain data not loaded — run fetch first\n');
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="ncsa-dnsmasq.conf"');
  const lines = [`# generated from NCSA domain blocklist — ${d.meta.generated_at}`];
  for (const domain of d.set) lines.push(`address=/${domain}/0.0.0.0`);
  res.send(lines.join('\n') + '\n');
});

app.get('/export/wazuh', (req, res) => {
  const d = store.hash;
  if (!d) return res.status(503).send('# hash data not loaded — run fetch first\n');
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="ncsa-wazuh.cdb"');
  const lines = [];
  for (const hash of d.set) lines.push(`${hash.toLowerCase()}:ncsa-blacklist`);
  res.send(lines.join('\n') + '\n');
});

app.get('/watch', (req, res) => {
  res.json(watchlist.load());
});

app.post('/watch', requireAdmin, express.json(), (req, res) => {
  const { type, value } = req.body || {};
  if (!type || !value) return res.status(400).json({ error: 'type and value required' });
  if (!VALID_TYPES.has(type)) return res.status(400).json({ error: `type must be one of: ${[...VALID_TYPES].join(', ')}` });
  console.log(`watch add by admin "${req.adminName || 'default'}": ${type}:${value}`);
  res.json(watchlist.add(type, value));
});

app.delete('/watch', requireAdmin, express.json(), (req, res) => {
  const { type, value } = req.body || {};
  if (!type || !value) return res.status(400).json({ error: 'type and value required' });
  console.log(`watch remove by admin "${req.adminName || 'default'}": ${type}:${value}`);
  res.json(watchlist.remove(type, value));
});

const PORT = process.env.PORT || 3939;
app.listen(PORT, () => console.log(`ncsa-blacklist API on :${PORT}`));
