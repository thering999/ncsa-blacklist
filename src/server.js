const fs = require('fs');
const path = require('path');
const express = require('express');
const { loadAll } = require('./store');
const { scanLog } = require('./scan');
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

app.get('/stats', (req, res) => {
  const stats = {};
  for (const [type, d] of Object.entries(store)) {
    stats[type] = d ? { total: d.meta.total, generated_at: d.meta.generated_at } : null;
  }
  res.json(stats);
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
  res.json(scanLog(req.body || '', d.set));
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
