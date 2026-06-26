const fs = require('fs');
const path = require('path');
const express = require('express');
const { loadAll } = require('./store');
const { scanLog, scanLogWithContext } = require('./scan');
const watchlist = require('./watchlist');
const { DATA_DIR } = require('./paths');
const { FEEDS, RECENT_FILE } = require('./fetch');

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

const { fetchLatestNews } = require('./news');
const { lookup: geoLookup } = require('./geoip');
const { parseTokens, makeRequireAdmin } = require('./auth');

// --- CIDR helpers ---
function ipToInt(ip) {
  return ip.split('.').reduce((a, b) => ((a << 8) | parseInt(b)) >>> 0, 0);
}
function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}
function parseCIDR(cidr) {
  const m = cidr.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) return null;
  const prefix = parseInt(m[2]);
  if (prefix < 0 || prefix > 32) return null;
  const base = ipToInt(m[1]);
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  const start = (base & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return { start, end, count: end - start + 1, prefix };
}
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
      file_entries: m.file?.entries ?? null,
      integrity_ok: m.file?.entries != null ? m.total === m.file.entries : null,
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

// Check domain + all parent domains; returns first match
function domainCheck(domainSet, value) {
  if (domainSet.has(value)) return { blacklisted: true, matched: value, matchType: 'exact' };
  const parts = value.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join('.');
    if (domainSet.has(parent)) return { blacklisted: true, matched: parent, matchType: 'parent' };
  }
  return { blacklisted: false, matched: value, matchType: 'exact' };
}

app.get('/check/auto/:value', (req, res) => {
  const { value } = req.params;
  const type = /^[0-9a-f]{64}$/i.test(value) ? 'hash'
    : /^\d{1,3}(\.\d{1,3}){3}$/.test(value) ? 'ip'
    : 'domain';
  const d = store[type];
  if (!d) return res.status(503).json({ error: `${type} data not loaded` });
  if (type === 'domain') return res.json({ type, value, ...domainCheck(d.set, value) });
  const blacklisted = d.set.has(value);
  const geo = type === 'ip' ? geoLookup(value) : null;
  res.json({ type, value, blacklisted, matched: value, matchType: 'exact', geo });
});

app.get('/check/:type/:value', (req, res) => {
  const { type, value } = req.params;
  const d = store[type];
  if (!d) return res.status(404).json({ error: `unknown type: ${type}` });
  if (type === 'domain') return res.json({ type, value, ...domainCheck(d.set, value) });
  const blacklisted = d.set.has(value);
  const geo = type === 'ip' ? geoLookup(value) : null;
  res.json({ type, value, blacklisted, matched: value, matchType: 'exact', geo });
});

app.post('/check/cidr', express.json({ limit: '1kb' }), (req, res) => {
  const { cidr } = req.body || {};
  if (!cidr) return res.status(400).json({ error: 'cidr required' });
  const range = parseCIDR(cidr.trim());
  if (!range) return res.status(400).json({ error: 'invalid CIDR (IPv4 only, /0-/32)' });
  if (range.count > 65536) return res.status(400).json({ error: 'CIDR too large (max /16 = 65536 IPs)' });
  const d = store.ip;
  if (!d) return res.status(503).json({ error: 'ip data not loaded' });
  const hits = [];
  for (const ip of d.set) {
    const n = ipToInt(ip);
    if (n >= range.start && n <= range.end) {
      hits.push({ ip, geo: geoLookup(ip) });
    }
  }
  hits.sort((a, b) => ipToInt(a.ip) - ipToInt(b.ip));
  res.json({ cidr, range_start: intToIp(range.start), range_end: intToIp(range.end), total_in_range: range.count, hits_count: hits.length, hits: hits.slice(0, 1000) });
});

app.get('/analyze/networks', (req, res) => {
  const d = store.ip;
  if (!d) return res.status(503).json({ error: 'ip data not loaded' });
  const counts = new Map();
  for (const ip of d.set) {
    const net = ip.split('.').slice(0, 3).join('.') + '.0/24';
    counts.set(net, (counts.get(net) || 0) + 1);
  }
  const top = [...counts.entries()]
    .map(([network, count]) => {
      const repIp = network.replace('.0/24', '.1');
      const g = geoLookup(repIp);
      return { network, count, country: g?.country || null, as: g?.as?.split(' ')[0] || null };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 25);
  res.json({ total_ips: d.set.size, total_networks: counts.size, top });
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
  res.json({
    type, results: values.map((v) => {
      const s = String(v);
      if (type === 'domain') return { value: s, ...domainCheck(d.set, s) };
      return { value: s, blacklisted: d.set.has(s), matched: s, matchType: 'exact' };
    }),
  });
});

app.get('/recent', (req, res) => {
  const { type, limit = 15 } = req.query;
  const lim = Math.min(parseInt(limit) || 15, 50);
  if (!fs.existsSync(RECENT_FILE)) return res.json({ count: 0, entries: [] });
  let entries = fs.readFileSync(RECENT_FILE, 'utf8').trim().split('\n').filter(Boolean)
    .map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean)
    .reverse();
  if (type && VALID_TYPES.has(type)) entries = entries.filter(e => e.type === type);
  entries = entries.slice(0, lim).map(e => ({
    date: e.date,
    type: e.type,
    total: e.total,
    added_count: e.added.length,
    removed_count: e.removed.length,
    // Enrich first 20 added IPs with GeoIP
    added_sample: e.type === 'ip'
      ? e.added.slice(0, 20).map(ip => ({ ip, geo: geoLookup(ip) }))
      : e.added.slice(0, 20).map(v => ({ value: v })),
    removed_sample: e.removed.slice(0, 10).map(v => ({ value: v })),
  }));
  res.json({ count: entries.length, entries });
});

app.get('/news', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 25, 200);
  const { items, source, fetchedAt } = await fetchLatestNews();
  res.json({ source, fetchedAt: fetchedAt ? new Date(fetchedAt).toISOString() : null, count: items.length, items: items.slice(0, limit) });
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
