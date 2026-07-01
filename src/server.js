const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns');
const express = require('express');
const { loadAll } = require('./store');
const { scanLog, scanLogWithContext } = require('./scan');
const watchlist = require('./watchlist');
const allowlist = require('./allowlist');
const alertRules = require('./alert_rules');
const reputation = require('./reputation');
const wazuh = require('./wazuh');
const { DATA_DIR } = require('./paths');
const { FEEDS, RECENT_FILE } = require('./fetch');

// Merge extra_feeds.json into FEEDS at startup
const EXTRA_FEEDS_FILE = path.join(DATA_DIR, 'extra_feeds.json');
(function mergeExtraFeeds() {
  try {
    const extra = JSON.parse(fs.readFileSync(EXTRA_FEEDS_FILE, 'utf8'));
    if (Array.isArray(extra)) {
      for (const { name, url } of extra) {
        if (name && url && !FEEDS[name]) FEEDS[name] = url;
      }
    }
  } catch {}
})();

const VALID_TYPES = new Set(Object.keys(FEEDS));

const HISTORY_FILE = path.join(DATA_DIR, 'history.jsonl');
const TREND_FILE = path.join(DATA_DIR, 'trend.json');

const helmet = require('helmet');
const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", 'https://ipinfo.io', 'https://crt.sh', 'https://dns.google', 'https://services.nvd.nist.gov', 'https://notify-api.line.me'],
    },
  },
}));

// Request ID — must be first so all routes including /healthz get it
app.use((req, res, next) => {
  res.set('X-Request-Id', req.get('X-Request-Id') || crypto.randomUUID());
  next();
});

// --- Rate limiter (in-memory per IP) ---
const _rateMap = new Map();
function rateLimit(maxReq, windowMs) {
  return (req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const key = ip + req.path;
    const now = Date.now();
    const e = _rateMap.get(key) || { n: 0, reset: now + windowMs };
    if (now > e.reset) { e.n = 0; e.reset = now + windowMs; }
    e.n++;
    _rateMap.set(key, e);
    res.set('X-RateLimit-Limit', maxReq);
    res.set('X-RateLimit-Remaining', Math.max(0, maxReq - e.n));
    res.set('X-RateLimit-Reset', new Date(e.reset).toISOString());
    if (e.n > maxReq) return res.status(429).json({ error: 'rate limit exceeded', reset: new Date(e.reset).toISOString() });
    next();
  };
}

// --- Reverse DNS (2s timeout) ---
function reverseDns(ip) {
  return new Promise((resolve) => {
    const resolver = new dns.Resolver();
    const tid = setTimeout(() => { resolver.cancel(); resolve(null); }, 2000);
    if (tid.unref) tid.unref();
    resolver.reverse(ip, (err, names) => {
      clearTimeout(tid);
      resolve(Array.isArray(names) && names.length ? names[0] : null);
    });
  });
}

// --- Risk score 0-100 ---
const HIGH_RISK_CC = new Set(['CN','RU','KP','IR','BY','CU','SY','VE','NI']);
function riskScore(ip, blacklisted, geo) {
  let score = 0;
  if (blacklisted) score += 50;
  if (geo?.country && HIGH_RISK_CC.has(geo.country)) score += 15;
  if (IPV4_RE && IPV4_RE.test(ip) && store.ip) {
    const prefix = ip.split('.').slice(0, 3).join('.');
    let density = 0;
    for (const e of store.ip.set) { if (e.startsWith(prefix + '.')) density++; }
    if (density > 50) score += 20;
    else if (density > 10) score += 12;
    else if (density > 2) score += 5;
  }
  return Math.min(100, score);
}
// Prune stale rate entries every 5 min
setInterval(() => { const now = Date.now(); for (const [k, v] of _rateMap) if (now > v.reset) _rateMap.delete(k); }, 5 * 60_000).unref();
let store = loadAll();

app.get('/healthz', (req, res) => {
  let sync_last_run = null, sync_next_run = null;
  try {
    const lines = fs.readFileSync(path.join(DATA_DIR, 'history.jsonl'), 'utf8').trim().split('\n').filter(Boolean);
    if (lines.length) {
      const last = JSON.parse(lines[lines.length - 1]);
      sync_last_run = last.date || null;
      if (sync_last_run) sync_next_run = new Date(new Date(sync_last_run).getTime() + 24 * 3600_000).toISOString();
    }
  } catch {}
  res.json({ ok: true, sync_last_run, sync_next_run });
});

const LOG_JSON = process.env.LOG_FORMAT === 'json';
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const rid = res.get('X-Request-Id') || '-';
    const ms = Date.now() - start;
    if (LOG_JSON) {
      console.log(JSON.stringify({ ts: new Date().toISOString(), method: req.method, path: req.originalUrl, status: res.statusCode, ms, rid }));
    } else {
      console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl} ${res.statusCode} ${ms}ms rid=${rid}`);
    }
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
app.use(rateLimit(RATE_LIMIT, 60_000));

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

function ipv6ToBigInt(ip) {
  // Expand :: shorthand
  let full = ip;
  if (ip.includes('::')) {
    const [left, right] = ip.split('::');
    const lp = left ? left.split(':') : [];
    const rp = right ? right.split(':') : [];
    const fill = Array(8 - lp.length - rp.length).fill('0');
    full = [...lp, ...fill, ...rp].join(':');
  }
  return full.split(':').reduce((acc, h) => (acc << 16n) | BigInt(parseInt(h || '0', 16)), 0n);
}

function parseCIDR(cidr) {
  // IPv4
  const v4 = cidr.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (v4) {
    const prefix = parseInt(v4[2]);
    if (prefix > 32) return null;
    const base = ipToInt(v4[1]);
    const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    const start = (base & mask) >>> 0;
    const end = (start | (~mask >>> 0)) >>> 0;
    return { start, end, count: end - start + 1, prefix, isV6: false };
  }
  // IPv6
  const v6 = cidr.match(/^(.+)\/(\d{1,3})$/);
  if (v6 && v6[1].includes(':')) {
    const prefix = parseInt(v6[2]);
    if (prefix > 128) return null;
    try {
      const base = ipv6ToBigInt(v6[1]);
      const bits = BigInt(128 - prefix);
      const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << bits) - 1n);
      const start = base & mask;
      const end = start | ((1n << bits) - 1n);
      return { start, end, count: end - start + 1n, prefix, isV6: true };
    } catch { return null; }
  }
  return null;
}
const adminTokens = parseTokens(process.env);
if (Object.keys(adminTokens).length === 0) {
  console.warn('no ADMIN_TOKEN/ADMIN_TOKENS set — /watch and /reload are unauthenticated; do not expose this publicly as-is');
}

// ADMIN_ALLOWED_IPS=10.0.0.0/8,192.168.0.0/16 — restricts /admin/* to specific IP ranges
const _adminAllowedRanges = (process.env.ADMIN_ALLOWED_IPS || '').split(',').map(s => s.trim()).filter(Boolean).map(parseCIDR).filter(Boolean);
function requireAdminIp(req, res, next) {
  if (!_adminAllowedRanges.length) return next();
  const clientIp = req.ip || '';
  if (clientIp.includes(':')) return res.status(403).json({ error: 'forbidden: IPv6 not supported in ADMIN_ALLOWED_IPS' });
  const n = ipToInt(clientIp);
  if (_adminAllowedRanges.some(r => !r.isV6 && n >= r.start && n <= r.end)) return next();
  return res.status(403).json({ error: 'forbidden: IP not in ADMIN_ALLOWED_IPS' });
}

// Startup env validation
(function validateEnv() {
  const w = (msg) => console.warn(`[config] ${msg}`);
  if (process.env.SMTP_HOST && !process.env.SMTP_TO) w('SMTP_HOST set but SMTP_TO missing — email notifications will not send');
  if (process.env.SMTP_HOST && process.env.SMTP_SECURE === 'true' && !process.env.SMTP_USER) w('SMTP_SECURE=true but no SMTP_USER — auth may be required');
  if (process.env.WEBHOOK_URL && !process.env.WEBHOOK_URL.startsWith('http')) w('WEBHOOK_URL does not look like a URL');
  if (process.env.RATE_LIMIT && isNaN(Number(process.env.RATE_LIMIT))) w('RATE_LIMIT must be a number');
  if (process.env.PORT && isNaN(Number(process.env.PORT))) w('PORT must be a number');
})();
const requireAdmin = makeRequireAdmin(adminTokens);

// Optional auth — only enforces token if adminTokens are configured
function requireAdminIfConfigured(req, res, next) {
  if (Object.keys(adminTokens).length === 0) return next();
  return requireAdmin(req, res, next);
}

// Trend helpers
function readTrend() {
  try { return JSON.parse(fs.readFileSync(TREND_FILE, 'utf8')); } catch { return []; }
}
function recordTrendEntry() {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const entries = readTrend().filter(e => e.date !== today);
    const ipCount = store.ip ? store.ip.set.size : 0;
    const domainCount = store.domain ? store.domain.set.size : 0;
    const hashCount = store.hash ? store.hash.set.size : 0;
    entries.push({ date: today, ip: ipCount, domain: domainCount, hash: hashCount, total: ipCount + domainCount + hashCount });
    fs.writeFileSync(TREND_FILE, JSON.stringify(entries.slice(-90)));
  } catch (e) { console.error('trend record error:', e.message); }
}

// Seed today's trend entry on startup if missing
(async () => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const trend = readTrend();
    if (!trend.find(e => e.date === today)) recordTrendEntry();
  } catch {}
})();

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

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6_RE = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^::(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$/;

function autoDetectType(value) {
  if (/^[0-9a-f]{64}$/i.test(value)) return 'hash';
  if (IPV4_RE.test(value) || IPV6_RE.test(value)) return 'ip';
  return 'domain';
}

app.get('/check/auto/:value', async (req, res) => {
  const { value } = req.params;
  const type = autoDetectType(value);
  const d = store[type];
  if (!d) return res.status(503).json({ error: `${type} data not loaded` });

  if (allowlist.check(type, value)) {
    return res.json({ type, value, blacklisted: false, allowlisted: true, matched: value, matchType: 'exact' });
  }

  // Multi-feed: check all feeds for this value
  const feeds = [];
  for (const [t, fd] of Object.entries(store)) { if (fd && fd.set.has(value)) feeds.push(t); }

  if (type === 'domain') return res.json({ type, value, ...domainCheck(d.set, value), feeds });
  const blacklisted = d.set.has(value);
  const geo = type === 'ip' ? geoLookup(value) : null;
  const rdns = type === 'ip' ? await reverseDns(value) : null;
  const risk = type === 'ip' ? riskScore(value, blacklisted, geo) : null;
  res.json({ type, value, blacklisted, matched: value, matchType: 'exact', geo, rdns, risk, feeds });
});

app.get('/check/:type/:value', (req, res) => {
  const { type, value } = req.params;
  const d = store[type];
  if (!d) return res.status(404).json({ error: `unknown type: ${type}` });
  if (allowlist.check(type, value)) {
    return res.json({ type, value, blacklisted: false, allowlisted: true, matched: value, matchType: 'exact' });
  }
  if (type === 'domain') return res.json({ type, value, ...domainCheck(d.set, value) });
  const blacklisted = d.set.has(value);
  const geo = type === 'ip' ? geoLookup(value) : null;
  res.json({ type, value, blacklisted, matched: value, matchType: 'exact', geo });
});

app.post('/check/cidr', rateLimit(60, 60_000), express.json({ limit: '1kb' }), (req, res) => {
  const { cidr } = req.body || {};
  if (!cidr) return res.status(400).json({ error: 'cidr required' });
  const range = parseCIDR(cidr.trim());
  if (!range) return res.status(400).json({ error: 'invalid CIDR' });
  const MAX_IPS = range.isV6 ? 65536n : 65536;
  if (range.count > MAX_IPS) {
    return res.status(400).json({ error: range.isV6 ? 'CIDR too large (max /112 for IPv6)' : 'CIDR too large (max /16 for IPv4)' });
  }
  const d = store.ip;
  if (!d) return res.status(503).json({ error: 'ip data not loaded' });
  const allowed = new Set(allowlist.load().filter(e => e.type === 'ip').map(e => e.value));
  const hits = [];
  for (const ip of d.set) {
    if (allowed.has(ip)) continue;
    if (range.isV6) {
      if (!ip.includes(':')) continue;
      const n = ipv6ToBigInt(ip);
      if (n >= range.start && n <= range.end) hits.push({ ip, geo: geoLookup(ip) });
    } else {
      if (ip.includes(':')) continue;
      const n = ipToInt(ip);
      if (n >= range.start && n <= range.end) hits.push({ ip, geo: geoLookup(ip) });
    }
  }
  hits.sort((a, b) => {
    if (range.isV6) { const an = ipv6ToBigInt(a.ip), bn = ipv6ToBigInt(b.ip); return an < bn ? -1 : an > bn ? 1 : 0; }
    return ipToInt(a.ip) - ipToInt(b.ip);
  });
  const base = { cidr, total_in_range: Number(range.count), hits_count: hits.length, hits: hits.slice(0, 1000) };
  if (!range.isV6) Object.assign(base, { range_start: intToIp(range.start), range_end: intToIp(range.end) });
  res.json(base);
});

app.get('/analyze/networks', (req, res) => {
  const d = store.ip;
  if (!d) return res.status(503).json({ error: 'ip data not loaded' });
  const { country } = req.query;
  const counts = new Map();
  for (const ip of d.set) {
    if (!IPV4_RE.test(ip)) continue;
    const net = ip.split('.').slice(0, 3).join('.') + '.0/24';
    counts.set(net, (counts.get(net) || 0) + 1);
  }
  let top = [...counts.entries()]
    .map(([network, count]) => {
      const repIp = network.replace('.0/24', '.1');
      const g = geoLookup(repIp);
      return { network, count, country: g?.country || null, as: g?.as?.split(' ')[0] || null };
    })
    .sort((a, b) => b.count - a.count);
  if (country) top = top.filter(n => (n.country || '').toUpperCase() === country.toUpperCase());
  top = top.slice(0, 50);
  res.json({ total_ips: d.set.size, total_networks: counts.size, top, filter_country: country || null });
});

app.get('/analyze/countries', requireAdminIfConfigured, (req, res) => {
  const d = store.ip;
  if (!d) return res.status(503).json({ error: 'ip data not loaded' });
  const counts = new Map();
  for (const ip of d.set) {
    const g = geoLookup(ip);
    const cc = g?.country || 'Unknown';
    counts.set(cc, (counts.get(cc) || 0) + 1);
  }
  const top = [...counts.entries()]
    .map(([country, count]) => ({ country, count, pct: Math.round(count / d.set.size * 1000) / 10 }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 25);
  res.json({ total_ips: d.set.size, total_countries: counts.size, top });
});

app.post('/scan', rateLimit(30, 60_000), express.text({ limit: '2mb' }), (req, res) => {
  const d = store.ip;
  if (!d) return res.status(503).json({ error: 'ip data not loaded' });
  const result = scanLogWithContext(req.body || '', d.set);
  const allowed = new Set(allowlist.load().filter(e => e.type === 'ip').map(e => e.value));
  if (allowed.size) {
    result.hits = result.hits.filter(ip => !allowed.has(ip));
    for (const l of result.lines) l.ips = l.ips.filter(ip => !allowed.has(ip));
    result.lines = result.lines.filter(l => l.ips.length > 0);
  }
  res.json(result);
});

app.post('/check/bulk', rateLimit(120, 60_000), express.json({ limit: '1mb' }), (req, res) => {
  const { type, values } = req.body || {};
  if (!Array.isArray(values)) return res.status(400).json({ error: 'values[] required' });
  if (type && type !== 'auto' && !VALID_TYPES.has(type)) return res.status(400).json({ error: `type must be auto or one of: ${[...VALID_TYPES].join(', ')}` });
  if (values.length > 10000) return res.status(400).json({ error: 'max 10000 values per request' });

  const results = values.map((v) => {
    const s = String(v).trim();
    const t = (type === 'auto' || !type) ? autoDetectType(s) : type;
    const d = store[t];
    if (!d) return { value: s, type: t, error: 'data not loaded' };
    if (allowlist.check(t, s)) return { value: s, type: t, blacklisted: false, allowlisted: true, matched: s, matchType: 'exact' };
    if (t === 'domain') return { value: s, type: t, ...domainCheck(d.set, s) };
    const blacklisted = d.set.has(s);
    const geo = t === 'ip' ? geoLookup(s) : null;
    return { value: s, type: t, blacklisted, matched: s, matchType: 'exact', ...(geo ? { geo } : {}) };
  });
  res.json({ type: type || 'auto', results });
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

const ORG_CONFIG_FILE = path.join(DATA_DIR, 'org_config.json');

app.get('/config', requireAdminIfConfigured, (req, res) => {
  try {
    const cfg = fs.existsSync(ORG_CONFIG_FILE) ? JSON.parse(fs.readFileSync(ORG_CONFIG_FILE, 'utf8')) : {};
    res.json(cfg);
  } catch { res.json({}); }
});

app.post('/config', requireAdminIfConfigured, express.json({ limit: '256kb' }), (req, res) => {
  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) return res.status(400).json({ error: 'body must be a JSON object' });
  try {
    fs.writeFileSync(ORG_CONFIG_FILE, JSON.stringify(body));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/news', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 25, 200);
  const { items, source, fetchedAt } = await fetchLatestNews();
  res.json({ source, fetchedAt: fetchedAt ? new Date(fetchedAt).toISOString() : null, count: items.length, items: items.slice(0, limit) });
});

app.get('/reputation/ip/:value', async (req, res) => {
  const ip = req.params.value;
  if (!IPV4_RE.test(ip) && !IPV6_RE.test(ip)) return res.status(400).json({ error: 'invalid IP' });
  const sources = await reputation.lookup(ip);
  res.json({ ip, sources });
});

app.get('/search', (req, res) => {
  const { type, q, page = '1', limit = '100' } = req.query;
  if (!type || !q) return res.status(400).json({ error: 'type and q required' });
  if (!VALID_TYPES.has(type)) return res.status(400).json({ error: `type must be one of: ${[...VALID_TYPES].join(', ')}` });
  if (q.length < 3) return res.status(400).json({ error: 'q must be at least 3 characters' });
  const d = store[type];
  if (!d) return res.status(503).json({ error: `${type} data not loaded` });
  const pageNum = Math.max(1, parseInt(page) || 1);
  const lim = Math.min(500, Math.max(10, parseInt(limit) || 100));
  const all = [];
  for (const v of d.set) { if (v.includes(q)) all.push(v); }
  const total = all.length;
  const start = (pageNum - 1) * lim;
  const results = all.slice(start, start + lim);
  res.json({ type, q, total, page: pageNum, limit: lim, pages: Math.ceil(total / lim), results });
});

app.post('/reload', requireAdmin, (req, res) => {
  store = loadAll();
  console.log(`reload by admin "${req.adminName || 'default'}"`);
  res.json({ reloaded: true });
});

// IP restriction for all /admin/* routes (no-op if ADMIN_ALLOWED_IPS unset)
app.use('/admin', requireAdminIp);

app.get('/admin/health', requireAdmin, (req, res) => {
  const mem = process.memoryUsage();
  const toMB = n => Math.round(n / 1024 / 1024 * 10) / 10;
  const uptime = process.uptime();
  const storeSizes = {};
  for (const [t, d] of Object.entries(store)) storeSizes[t] = d ? d.set.size : 0;
  // Data file sizes
  const fileSizes = {};
  for (const t of Object.keys(store)) {
    const f = path.join(DATA_DIR, `${t}.json`);
    try { fileSizes[t] = Math.round(fs.statSync(f).size / 1024) + ' KB'; } catch { fileSizes[t] = null; }
  }
  res.json({
    uptime_seconds: Math.round(uptime),
    uptime_human: `${Math.floor(uptime/3600)}h ${Math.floor((uptime%3600)/60)}m`,
    memory: { rss_mb: toMB(mem.rss), heap_used_mb: toMB(mem.heapUsed), heap_total_mb: toMB(mem.heapTotal) },
    store_sizes: storeSizes,
    file_sizes: fileSizes,
    rate_limit_keys: _rateMap.size,
    node_version: process.version,
    pid: process.pid,
  });
});

app.post('/admin/webhook-test', requireAdmin, express.json(), async (req, res) => {
  const { webhook } = req.body || {};
  if (!webhook) return res.status(400).json({ error: 'webhook required' });
  const payload = { event: 'test', message: 'NCSA Blacklist webhook test ping', timestamp: new Date().toISOString() };
  const body = JSON.stringify(payload);
  const headers = { 'Content-Type': 'application/json' };
  const secret = process.env.WEBHOOK_SECRET;
  if (secret) {
    const crypto = require('crypto');
    headers['X-Signature'] = 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
  }
  try {
    const r = await fetch(webhook, { method: 'POST', headers, body, signal: AbortSignal.timeout(6000) });
    res.json({ ok: r.ok, status: r.status, statusText: r.statusText });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get('/admin/wazuh/alerts', requireAdminIfConfigured, rateLimit(30, 60_000), async (req, res) => {
  let cfg = {};
  try { cfg = fs.existsSync(ORG_CONFIG_FILE) ? JSON.parse(fs.readFileSync(ORG_CONFIG_FILE, 'utf8')) : {}; } catch {}
  const wazuhIP = cfg.wazuhIP;
  if (!wazuhIP || wazuhIP === 'WAZUH-SERVER') return res.status(400).json({ ok: false, error: 'wazuhIP not configured' });
  const hours = Math.min(Math.max(parseInt(req.query.hours) || 24, 1), 168);
  try {
    const result = await wazuh.queryAlerts({
      wazuhIP,
      wazuhUser: cfg.wazuhUser || 'admin',
      wazuhPass: cfg.wazuhPass || '',
      insecureTLS: !!cfg.wazuhInsecureTLS,
      hours,
    });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(502).json({ ok: false, error: e.message });
  }
});

app.get('/admin/summary', requireAdmin, async (req, res) => {
  const days = parseInt(req.query.days) || 7;
  const since = new Date(Date.now() - days * 86400_000).toISOString();
  let entries = [];
  try {
    const lines = fs.readFileSync(HISTORY_FILE, 'utf8').trim().split('\n').filter(Boolean);
    entries = lines.map(l => JSON.parse(l)).filter(e => e.date >= since);
  } catch {}
  const summary = {};
  for (const e of entries) {
    if (!summary[e.type]) summary[e.type] = { syncs: 0, total_added: 0, total_removed: 0, latest_total: 0 };
    summary[e.type].syncs++;
    summary[e.type].total_added += e.added || 0;
    summary[e.type].total_removed += e.removed || 0;
    summary[e.type].latest_total = e.total || summary[e.type].latest_total;
  }
  const store_sizes = {};
  for (const [t, d] of Object.entries(store)) store_sizes[t] = d ? d.set.size : 0;
  const text = [
    `NCSA Blacklist — ${days}-day summary (${new Date().toISOString().slice(0,10)})`,
    '',
    ...Object.entries(summary).map(([t, s]) =>
      `[${t}] syncs:${s.syncs} +${s.total_added} -${s.total_removed} current:${s.latest_total}`),
    '',
    `Store: IP ${store_sizes.ip || 0} / domain ${store_sizes.domain || 0} / hash ${store_sizes.hash || 0}`,
  ].join('\n');

  const send = req.query.send === 'true';
  if (send) {
    const { notifyEmail } = require('./notify');
    try { await notifyEmail('[NCSA] Weekly Blacklist Summary', text); }
    catch (e) { return res.status(502).json({ error: `email failed: ${e.message}`, summary }); }
  }
  res.json({ days, since, summary, store_sizes, text, email_sent: send });
});

app.get('/history', (req, res) => {
  const { type } = req.query;
  if (!fs.existsSync(HISTORY_FILE)) return res.json([]);
  const lines = fs.readFileSync(HISTORY_FILE, 'utf8').trim().split('\n').filter(Boolean);
  const entries = lines.map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter((e) => e && (!type || e.type === type));
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

app.get('/export/csv/:type', (req, res) => {
  const { type } = req.params;
  const d = store[type];
  if (!d) return res.status(404).send('# not found\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="ncsa-${type}.csv"`);
  res.send([type, ...[...d.set]].join('\n') + '\n');
});

app.get('/export/json', (req, res) => {
  const out = {};
  for (const [type, d] of Object.entries(store)) {
    if (d) out[type] = { feed: d.meta.feed, generated_at: d.meta.generated_at, total: d.meta.total, data: [...d.set] };
  }
  res.setHeader('Content-Disposition', 'attachment; filename="ncsa-blacklist.json"');
  res.json(out);
});

app.get('/watch', requireAdminIfConfigured, (req, res) => {
  res.json(watchlist.load());
});

function validateTypeValue(type, value) {
  if (!type || !value) return 'type and value required';
  if (!VALID_TYPES.has(type)) return `type must be one of: ${[...VALID_TYPES].join(', ')}`;
  const s = String(value).trim();
  if (type === 'ip' && !IPV4_RE.test(s) && !IPV6_RE.test(s)) return 'invalid IP address';
  if (type === 'hash' && !/^[0-9a-fA-F]{64}$/.test(s)) return 'invalid SHA256 hash (must be 64 hex chars)';
  if (type === 'domain' && (s.includes('/') || s.includes(' '))) return 'invalid domain';
  return null;
}

app.post('/watch', requireAdmin, express.json(), (req, res) => {
  const { type, value } = req.body || {};
  const err = validateTypeValue(type, value);
  if (err) return res.status(400).json({ error: err });
  console.log(`watch add by admin "${req.adminName || 'default'}": ${type}:${value}`);
  res.json(watchlist.add(type, value));
});

app.delete('/watch', requireAdmin, express.json(), (req, res) => {
  const { type, value } = req.body || {};
  if (!type || !value) return res.status(400).json({ error: 'type and value required' });
  console.log(`watch remove by admin "${req.adminName || 'default'}": ${type}:${value}`);
  res.json(watchlist.remove(type, value));
});

app.get('/allowlist', requireAdminIfConfigured, (req, res) => {
  res.json(allowlist.load());
});

app.post('/allowlist', requireAdmin, express.json(), (req, res) => {
  const { type, value } = req.body || {};
  const err = validateTypeValue(type, value);
  if (err) return res.status(400).json({ error: err });
  console.log(`allowlist add by admin "${req.adminName || 'default'}": ${type}:${value}`);
  res.json(allowlist.add(type, value));
});

app.delete('/allowlist', requireAdmin, express.json(), (req, res) => {
  const { type, value } = req.body || {};
  if (!type || !value) return res.status(400).json({ error: 'type and value required' });
  console.log(`allowlist remove by admin "${req.adminName || 'default'}": ${type}:${value}`);
  res.json(allowlist.remove(type, value));
});

// --- Alert Rules ---
app.get('/admin/alert-rules', requireAdmin, (req, res) => {
  res.json(alertRules.load());
});

app.post('/admin/alert-rules', requireAdmin, express.json(), (req, res) => {
  const { name, enabled, condition, action, cooldown_minutes } = req.body || {};
  if (!name || !condition || !condition.field || !condition.operator) {
    return res.status(400).json({ error: 'name and condition.field/operator required' });
  }
  const cooldown = cooldown_minutes != null ? Number(cooldown_minutes) : 60;
  if (!Number.isFinite(cooldown) || cooldown < 0) {
    return res.status(400).json({ error: 'cooldown_minutes must be a non-negative number' });
  }
  try {
    res.json(alertRules.create({ name, enabled: enabled !== false, condition, action: action || 'notify', cooldown_minutes: cooldown, last_fired: null }));
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.put('/admin/alert-rules/:id', requireAdmin, express.json(), (req, res) => {
  const result = alertRules.update(req.params.id, req.body || {});
  if (!result) return res.status(404).json({ error: 'rule not found' });
  res.json(result);
});

app.delete('/admin/alert-rules/:id', requireAdmin, (req, res) => {
  res.json(alertRules.remove(req.params.id));
});

// --- Prometheus metrics ---
app.get('/metrics', (req, res, next) => {
  const metricsToken = process.env.METRICS_TOKEN;
  if (metricsToken) {
    const auth = req.get('Authorization');
    if (!auth || auth !== `Bearer ${metricsToken}`) {
      return res.status(401).set('WWW-Authenticate', 'Bearer realm="metrics"').end();
    }
    return next();
  }
  // No METRICS_TOKEN — fall back to admin token if configured
  requireAdminIfConfigured(req, res, next);
}, (req, res) => {
  const mem = process.memoryUsage();
  const uptime = process.uptime();
  let syncTs = 0;
  try {
    const lines = fs.readFileSync(HISTORY_FILE, 'utf8').trim().split('\n').filter(Boolean);
    if (lines.length) syncTs = Math.floor(new Date(JSON.parse(lines[lines.length - 1]).date).getTime() / 1000);
  } catch {}
  const lines = [
    '# NCSA Blacklist Metrics',
    '# Protect this endpoint with ADMIN_TOKEN in production',
    '# HELP ncsa_store_size Number of entries in each feed',
    '# TYPE ncsa_store_size gauge',
    ...Object.entries(store).map(([t, d]) => `ncsa_store_size{type="${t}"} ${d ? d.set.size : 0}`),
    '# HELP ncsa_process_uptime_seconds Process uptime',
    '# TYPE ncsa_process_uptime_seconds counter',
    `ncsa_process_uptime_seconds ${Math.round(uptime)}`,
    '# HELP ncsa_memory_rss_bytes Resident set size',
    '# TYPE ncsa_memory_rss_bytes gauge',
    `ncsa_memory_rss_bytes ${mem.rss}`,
    '# HELP ncsa_memory_heap_used_bytes Heap used',
    '# TYPE ncsa_memory_heap_used_bytes gauge',
    `ncsa_memory_heap_used_bytes ${mem.heapUsed}`,
    '# HELP ncsa_rate_limit_keys Active rate limit keys',
    '# TYPE ncsa_rate_limit_keys gauge',
    `ncsa_rate_limit_keys ${_rateMap.size}`,
    '# HELP ncsa_sync_last_run_timestamp Unix timestamp of last sync',
    '# TYPE ncsa_sync_last_run_timestamp gauge',
    `ncsa_sync_last_run_timestamp ${syncTs}`,
    '# HELP ncsa_feed_file_age_seconds Seconds since feed data file was last written (-1 if missing)',
    '# TYPE ncsa_feed_file_age_seconds gauge',
    '# HELP ncsa_feed_up Feed file present and fresher than 25h (1=ok, 0=stale/missing)',
    '# TYPE ncsa_feed_up gauge',
  ];
  const nowMs = Date.now();
  for (const t of Object.keys(FEEDS)) {
    const f = path.join(DATA_DIR, `${t}.json`);
    let age = -1, up = 0;
    try { age = Math.round((nowMs - fs.statSync(f).mtimeMs) / 1000); up = age < 25 * 3600 ? 1 : 0; } catch {}
    lines.push(`ncsa_feed_file_age_seconds{type="${t}"} ${age}`);
    lines.push(`ncsa_feed_up{type="${t}"} ${up}`);
  }
  lines.push('');
  res.set('Content-Type', 'text/plain; version=0.0.4');
  res.send(lines.join('\n'));
});

// --- ASN Analysis ---
app.get('/analyze/asns', (req, res) => {
  const d = store.ip;
  if (!d) return res.status(503).json({ error: 'ip data not loaded' });
  const counts = new Map();
  for (const ip of d.set) {
    if (!IPV4_RE.test(ip)) continue;
    const g = geoLookup(ip);
    const asn = g?.as || 'Unknown';
    const org = g?.org || g?.as || 'Unknown';
    const key = asn;
    const e = counts.get(key) || { asn, org, count: 0, country: g?.country || null };
    e.count++;
    counts.set(key, e);
  }
  const top = [...counts.values()]
    .sort((a, b) => b.count - a.count)
    .slice(0, 30);
  res.json({ total_ips: d.set.size, total_asns: counts.size, top });
});

// --- Stats + Info with cache headers ---
app.use('/stats', (req, res, next) => { res.set('Cache-Control', 'public, max-age=60'); next(); });
app.use('/info', (req, res, next) => { res.set('Cache-Control', 'public, max-age=300'); next(); });

// --- Scan result CSV download ---
app.post('/scan/csv', rateLimit(30, 60_000), express.text({ limit: '2mb' }), (req, res) => {
  const text = req.body;
  if (!text) return res.status(400).json({ error: 'body required' });
  const d = store.ip;
  if (!d) return res.status(503).json({ error: 'ip data not loaded' });
  const result = scanLogWithContext(text, d.set);
  const allowed = new Set(allowlist.load().filter(e => e.type === 'ip').map(e => e.value));
  if (allowed.size) {
    for (const l of result.lines) l.ips = l.ips.filter(ip => !allowed.has(ip));
    result.lines = result.lines.filter(l => l.ips.length > 0);
  }
  const { hits, lines: hitLines } = result;
  const rows = [['line_no', 'ip', 'log_excerpt']];
  for (const l of (hitLines || [])) {
    for (const ip of l.ips) rows.push([l.line, ip, l.text.replace(/"/g, '""')]);
  }
  const csv = rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n');
  res.set('Content-Type', 'text/csv');
  res.set('Content-Disposition', `attachment; filename="ncsa-scan-${Date.now()}.csv"`);
  res.send(csv);
});

app.get('/admin/feed-health', requireAdmin, (req, res) => {
  const nowMs = Date.now();
  const feeds = {};
  for (const t of Object.keys(FEEDS)) {
    const f = path.join(DATA_DIR, `${t}.json`);
    const d = store[t];
    let file_age_seconds = null, last_modified = null, file_size_kb = null, status = 'missing';
    try {
      const stat = fs.statSync(f);
      file_age_seconds = Math.round((nowMs - stat.mtimeMs) / 1000);
      last_modified = new Date(stat.mtimeMs).toISOString();
      file_size_kb = Math.round(stat.size / 1024);
      status = file_age_seconds < 25 * 3600 ? 'ok' : 'stale';
    } catch {}
    feeds[t] = { status, entries: d ? d.set.size : null, file_age_seconds, last_modified, file_size_kb, url: FEEDS[t] };
  }
  res.json({ feeds });
});

// Manual sync trigger
app.post('/admin/sync', requireAdmin, async (req, res) => {
  try {
    const { fetchAll } = require('./fetch');
    fetchAll()
      .then(() => { store = loadAll(); recordTrendEntry(); })
      .catch(err => console.error('Manual sync error:', err));
    res.json({ ok: true, message: 'Sync triggered in background — check /admin/feed-health in 30-60s' });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// --- Trend (90-day IOC count history) ---
app.get('/trend', (req, res) => {
  res.json(readTrend());
});

// --- Feed management ---
app.get('/admin/feeds', requireAdmin, (req, res) => {
  const envFeeds = (process.env.EXTRA_FEEDS || '').split(',').filter(Boolean).map(s => {
    const [name, ...rest] = s.split(':');
    return { name: name.trim(), url: rest.join(':').trim(), source: 'env' };
  });
  let fileFeeds = [];
  try {
    fileFeeds = JSON.parse(fs.readFileSync(EXTRA_FEEDS_FILE, 'utf8')).map(f => ({ ...f, source: 'file' }));
  } catch {}
  res.json({ env: envFeeds, file: fileFeeds });
});

app.post('/admin/feeds', requireAdmin, express.json(), (req, res) => {
  const { feeds } = req.body || {};
  if (!Array.isArray(feeds)) return res.status(400).json({ error: 'feeds[] required' });
  for (const f of feeds) {
    if (!f.name || !f.url) return res.status(400).json({ error: 'each feed needs name and url' });
    if (!FEEDS[f.name]) FEEDS[f.name] = f.url;
  }
  fs.writeFileSync(EXTRA_FEEDS_FILE, JSON.stringify(feeds));
  const { fetchAll } = require('./fetch');
  fetchAll().then(() => { store = loadAll(); recordTrendEntry(); }).catch(err => console.error('Feed sync error:', err));
  res.json({ ok: true, saved: feeds.length, message: 'Feeds saved and sync triggered' });
});

// --- FortiGate block proxy ---
app.post('/admin/fortigate-block', requireAdmin, express.json(), async (req, res) => {
  const { host, token, vdom = 'root', ips } = req.body || {};
  if (!host || !token || !Array.isArray(ips) || !ips.length) {
    return res.status(400).json({ error: 'host, token, ips[] required' });
  }
  const members = ips.map(ip => ({ name: ip }));
  const fgBase = host.startsWith('https://') ? host : `https://${host}`;
  const url = `${fgBase}/api/v2/cmdb/firewall/addrgrp/NCSA-Blacklist?vdom=${vdom}`;
  try {
    // Try PUT (update existing group) first, fallback to POST (create)
    let r = await fetch(url, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'NCSA-Blacklist', member: members }),
      signal: AbortSignal.timeout(10000),
    });
    if (r.status === 404) {
      r = await fetch(`${fgBase}/api/v2/cmdb/firewall/addrgrp?vdom=${vdom}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'NCSA-Blacklist', member: members }),
        signal: AbortSignal.timeout(10000),
      });
    }
    const data = await r.json().catch(() => ({}));
    res.json({ ok: r.ok, status: r.status, fortigate: data, ips_blocked: ips.length });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// --- MISP push IOC ---
app.post('/admin/misp-push', requireAdmin, express.json(), async (req, res) => {
  const { url: misp_url, apikey, iocs, tlp = 'TLP:GREEN' } = req.body || {};
  if (!misp_url || !apikey || !Array.isArray(iocs) || !iocs.length) {
    return res.status(400).json({ error: 'url, apikey, iocs[] required' });
  }
  if (!misp_url.startsWith('https://')) {
    return res.status(400).json({ error: 'MISP URL ต้องเป็น HTTPS เท่านั้น เพื่อป้องกัน API Key รั่วไหล' });
  }
  const distribution = tlp === 'TLP:RED' ? 4 : tlp === 'TLP:AMBER' ? 3 : tlp === 'TLP:GREEN' ? 2 : 0;
  const event = {
    Event: {
      info: `NCSA Blacklist IOC Report — ${new Date().toISOString().slice(0, 10)}`,
      distribution,
      threat_level_id: 2,
      analysis: 2,
      Attribute: iocs.map(({ type, value, comment = '' }) => ({
        type: type === 'ip' ? 'ip-src' : type === 'domain' ? 'domain' : 'md5',
        value,
        comment,
        distribution,
        to_ids: true,
      })),
    },
  };
  try {
    const r = await fetch(`${misp_url}/events`, {
      method: 'POST',
      headers: { 'Authorization': apikey, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(15000),
    });
    const data = await r.json().catch(() => ({}));
    res.json({ ok: r.ok, status: r.status, misp: data, iocs_pushed: iocs.length });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// --- Executive report email ---
app.post('/admin/report-email', requireAdmin, express.json({ limit: '2mb' }), async (req, res) => {
  const { html, subject = `[NCSA SOC] Executive Report ${new Date().toISOString().slice(0, 10)}` } = req.body || {};
  if (!html) return res.status(400).json({ error: 'html required' });
  if (!process.env.SMTP_HOST || !process.env.SMTP_TO) {
    return res.status(503).json({ error: 'SMTP_HOST and SMTP_TO must be set in .env' });
  }
  let nodemailer;
  try { nodemailer = require('nodemailer'); } catch { return res.status(500).json({ error: 'nodemailer not installed' }); }
  const transport = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
  try {
    await transport.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: process.env.SMTP_TO,
      subject,
      html,
    });
    res.json({ ok: true, to: process.env.SMTP_TO, subject });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// ============================================================
// FEATURE 1: USER AUTHENTICATION
// ============================================================
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const _sessions = new Map(); // token → {userId, username, role, expires}

function parseCookieStr(str = '') {
  const out = {};
  for (const part of str.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    try { out[decodeURIComponent(part.slice(0, idx).trim())] = decodeURIComponent(part.slice(idx + 1).trim()); } catch {}
  }
  return out;
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function readUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { return []; }
}
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// Bootstrap default admin user on startup
(function bootstrapAuth() {
  if (fs.existsSync(USERS_FILE)) return;
  const salt = crypto.randomBytes(16).toString('hex');
  const password = process.env.ADMIN_TOKEN || 'admin1234';
  const passwordHash = hashPassword(password, salt);
  writeUsers([{ id: 1, username: 'admin', passwordHash, salt, role: 'admin', createdAt: new Date().toISOString() }]);
  console.log('[auth] created default admin user (username: admin, password: ADMIN_TOKEN or admin1234)');
})();

function requireAuth(role = null) {
  return (req, res, next) => {
    const cookies = parseCookieStr(req.headers.cookie || '');
    const token = cookies.ncsa_session || req.headers['x-session-token'] || '';
    const session = _sessions.get(token);
    if (!session || session.expires < Date.now()) {
      // Fallback: accept existing ADMIN_TOKEN Bearer for API clients
      const bearer = (req.headers.authorization || '').replace('Bearer ', '').trim();
      if (bearer && adminTokens[bearer]) {
        req.user = { userId: 0, username: 'api', role: 'admin' };
        return next();
      }
      return res.status(401).json({ error: 'Unauthorized — please login at /auth/login' });
    }
    if (role && role !== 'admin' && session.role !== role && session.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden — insufficient role' });
    }
    req.user = session;
    next();
  };
}

function setCookieHeader(res, token) {
  res.setHeader('Set-Cookie', `ncsa_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`);
}

// POST /auth/login
app.post('/auth/login', express.json(), (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const users = readUsers();
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const hash = hashPassword(password, user.salt);
  if (hash !== user.passwordHash) return res.status(401).json({ error: 'Invalid credentials' });
  const token = crypto.randomBytes(32).toString('hex');
  _sessions.set(token, { userId: user.id, username: user.username, role: user.role, expires: Date.now() + 8 * 3600_000 });
  setCookieHeader(res, token);
  auditLogRaw({ ip: req.ip }, 'login', username);
  res.json({ ok: true, username: user.username, role: user.role });
});

// POST /auth/logout
app.post('/auth/logout', (req, res) => {
  const cookies = parseCookieStr(req.headers.cookie || '');
  const token = cookies.ncsa_session || req.headers['x-session-token'] || '';
  if (token) _sessions.delete(token);
  res.setHeader('Set-Cookie', 'ncsa_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  auditLogRaw({ ip: req.ip, user: { username: 'unknown' } }, 'logout', '');
  res.json({ ok: true });
});

// GET /auth/me
app.get('/auth/me', requireAuth(), (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

// GET /auth/users — admin only
app.get('/auth/users', requireAuth('admin'), (req, res) => {
  const users = readUsers().map(({ passwordHash, salt, ...u }) => u);
  res.json(users);
});

// POST /auth/users — admin only: create user
app.post('/auth/users', requireAuth('admin'), express.json(), (req, res) => {
  const { username, password, role = 'analyst' } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (!['admin', 'analyst', 'viewer'].includes(role)) return res.status(400).json({ error: 'role must be admin|analyst|viewer' });
  const users = readUsers();
  if (users.find(u => u.username === username)) return res.status(409).json({ error: 'username already exists' });
  const salt = crypto.randomBytes(16).toString('hex');
  const newUser = { id: Date.now(), username, passwordHash: hashPassword(password, salt), salt, role, createdAt: new Date().toISOString() };
  users.push(newUser);
  writeUsers(users);
  auditLogRaw(req, 'user_create', username);
  res.json({ ok: true, id: newUser.id, username, role });
});

// DELETE /auth/users/:id — admin only
app.delete('/auth/users/:id', requireAuth('admin'), (req, res) => {
  const id = parseInt(req.params.id);
  const users = readUsers();
  const idx = users.findIndex(u => u.id === id);
  if (idx < 0) return res.status(404).json({ error: 'user not found' });
  const [removed] = users.splice(idx, 1);
  writeUsers(users);
  auditLogRaw(req, 'user_delete', removed.username);
  res.json({ ok: true });
});

// PUT /auth/users/:id/password — admin only
app.put('/auth/users/:id/password', requireAuth('admin'), express.json(), (req, res) => {
  const id = parseInt(req.params.id);
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'password required' });
  const users = readUsers();
  const user = users.find(u => u.id === id);
  if (!user) return res.status(404).json({ error: 'user not found' });
  user.salt = crypto.randomBytes(16).toString('hex');
  user.passwordHash = hashPassword(password, user.salt);
  writeUsers(users);
  auditLogRaw(req, 'password_reset', user.username);
  res.json({ ok: true });
});

// Clean expired sessions every hour
setInterval(() => { const now = Date.now(); for (const [t, s] of _sessions) if (s.expires < now) _sessions.delete(t); }, 3600_000).unref();

// ============================================================
// FEATURE 2: AUDIT LOG
// ============================================================
const AUDIT_FILE = path.join(DATA_DIR, 'audit.json');

function auditLogRaw(req, action, detail = '') {
  const entry = {
    id: Date.now(),
    ts: new Date().toISOString(),
    user: req.user?.username || 'anonymous',
    action,
    detail: String(detail).substring(0, 500),
    ip: req.ip || req.connection?.remoteAddress || 'unknown',
  };
  let log = [];
  try { log = JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8')); } catch {}
  log.push(entry);
  if (log.length > 10000) log = log.slice(-10000);
  try { fs.writeFileSync(AUDIT_FILE, JSON.stringify(log)); } catch {}
}

// GET /admin/audit
app.get('/admin/audit', requireAuth('admin'), (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  const offset = parseInt(req.query.offset) || 0;
  let log = [];
  try { log = JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8')); } catch {}
  const total = log.length;
  const slice = log.slice().reverse().slice(offset, offset + limit);
  res.json({ total, offset, limit, entries: slice });
});

// ============================================================
// FEATURE 3: SERVER-SIDE DATA API
// ============================================================
const VALID_DATA_TYPES = new Set(['assets','vulns','tickets','incidents','bcpdrills','pdpa','policies','training','licensed','phishing','pentest','vendors','risks','zerotrust','ctam','moph100','kpi','nist','iomtdevices','cloudassets']);

function dataFile(type) { return path.join(DATA_DIR, `data_${type}.json`); }
async function readData(type) { try { return JSON.parse(await fs.promises.readFile(dataFile(type), 'utf8')); } catch { return []; } }
async function writeData(type, data) { await fs.promises.writeFile(dataFile(type), JSON.stringify(data)); }

// GET /data/:type
app.get('/data/:type', requireAuth(), async (req, res) => {
  const { type } = req.params;
  if (!VALID_DATA_TYPES.has(type)) return res.status(400).json({ error: `unknown type: ${type}` });
  res.json(await readData(type));
});

// POST /data/:type — append
app.post('/data/:type', requireAuth(), express.json({ limit: '1mb' }), async (req, res) => {
  const { type } = req.params;
  if (!VALID_DATA_TYPES.has(type)) return res.status(400).json({ error: `unknown type: ${type}` });
  const item = { ...req.body, id: Date.now() + Math.floor(Math.random() * 1000), _createdBy: req.user.username, _createdAt: new Date().toISOString() };
  const data = await readData(type);
  data.push(item);
  await writeData(type, data);
  auditLogRaw(req, 'data_write', `POST /data/${type}`);
  res.json(item);
});

// PUT /data/:type/:id — update
app.put('/data/:type/:id', requireAuth(), express.json({ limit: '1mb' }), async (req, res) => {
  const { type, id } = req.params;
  if (!VALID_DATA_TYPES.has(type)) return res.status(400).json({ error: `unknown type: ${type}` });
  const data = await readData(type);
  const idx = data.findIndex(d => String(d.id) === id);
  if (idx < 0) return res.status(404).json({ error: 'not found' });
  data[idx] = { ...data[idx], ...req.body, id: data[idx].id, _updatedBy: req.user.username, _updatedAt: new Date().toISOString() };
  await writeData(type, data);
  auditLogRaw(req, 'data_write', `PUT /data/${type}/${id}`);
  res.json(data[idx]);
});

// DELETE /data/:type/:id
app.delete('/data/:type/:id', requireAuth(), async (req, res) => {
  const { type, id } = req.params;
  if (!VALID_DATA_TYPES.has(type)) return res.status(400).json({ error: `unknown type: ${type}` });
  const data = await readData(type);
  const idx = data.findIndex(d => String(d.id) === id);
  if (idx < 0) return res.status(404).json({ error: 'not found' });
  data.splice(idx, 1);
  await writeData(type, data);
  auditLogRaw(req, 'data_write', `DELETE /data/${type}/${id}`);
  res.json({ ok: true });
});

// GET /data/:type/export — download JSON
app.get('/data/:type/export', requireAuth(), async (req, res) => {
  const { type } = req.params;
  if (!VALID_DATA_TYPES.has(type)) return res.status(400).json({ error: `unknown type: ${type}` });
  const data = await readData(type);
  res.setHeader('Content-Disposition', `attachment; filename="ncsa-${type}-${new Date().toISOString().slice(0,10)}.json"`);
  res.json(data);
});

// POST /data/:type/import — bulk replace
app.post('/data/:type/import', requireAuth('admin'), express.json({ limit: '10mb' }), async (req, res) => {
  const { type } = req.params;
  if (!VALID_DATA_TYPES.has(type)) return res.status(400).json({ error: `unknown type: ${type}` });
  if (!Array.isArray(req.body)) return res.status(400).json({ error: 'body must be a JSON array' });
  await writeData(type, req.body);
  auditLogRaw(req, 'data_import', `${type} count=${req.body.length}`);
  res.json({ ok: true, imported: req.body.length });
});

// ============================================================
// FEATURE 4: LINE OA BOT (2-WAY)
// ============================================================
function verifyLineSignature(rawBody, signature, secret) {
  const hash = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
  return hash === signature;
}

async function lineReply(replyToken, messages, channelAccessToken) {
  await fetch('https://api.line.me/v2/bot/message/reply', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + channelAccessToken },
    body: JSON.stringify({ replyToken, messages: messages.map(text => ({ type: 'text', text })) }),
    signal: AbortSignal.timeout(8000),
  });
}

app.post('/webhook/line', express.raw({ type: 'application/json' }), async (req, res) => {
  const secret = process.env.LINE_OA_SECRET;
  const token = process.env.LINE_OA_TOKEN;
  if (!secret || !token) return res.sendStatus(200); // graceful no-op

  const sig = req.headers['x-line-signature'] || '';
  const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body);
  if (!verifyLineSignature(rawBody, sig, secret)) return res.status(401).send('bad signature');

  let payload;
  try { payload = JSON.parse(rawBody.toString('utf8')); } catch { return res.sendStatus(400); }

  res.sendStatus(200); // respond immediately; process async

  for (const event of (payload.events || [])) {
    if (event.type !== 'message' || event.message?.type !== 'text') continue;
    const text = (event.message.text || '').trim();
    const replyToken = event.replyToken;
    try {
      if (/^(ตรวจ|check)\s+(.+)/i.test(text)) {
        const value = text.replace(/^(ตรวจ|check)\s+/i, '').trim();
        const type = autoDetectType(value);
        const d = store[type];
        if (!d) { await lineReply(replyToken, [`ไม่สามารถตรวจสอบได้: ข้อมูล ${type} ไม่พร้อม`], token); continue; }
        const bl = type === 'domain' ? domainCheck(d.set, value).blacklisted : d.set.has(value);
        const geo = type === 'ip' ? geoLookup(value) : null;
        const msg = bl
          ? `🚨 พบใน Blacklist!\nค่า: ${value}\nประเภท: ${type}${geo ? `\nประเทศ: ${geo.country || '?'}` : ''}`
          : `✅ ไม่พบใน Blacklist\nค่า: ${value}\nประเภท: ${type}`;
        await lineReply(replyToken, [msg], token);
      } else if (/^(สถานะ|status)$/i.test(text)) {
        const ip = store.ip ? store.ip.set.size.toLocaleString() : '?';
        const domain = store.domain ? store.domain.set.size.toLocaleString() : '?';
        const hash = store.hash ? store.hash.set.size.toLocaleString() : '?';
        await lineReply(replyToken, [`📊 NCSA Blacklist Status\nIP: ${ip} รายการ\nDomain: ${domain} รายการ\nHash: ${hash} รายการ`], token);
      } else if (/^(ช่วย|help)$/i.test(text)) {
        await lineReply(replyToken, ['📋 คำสั่งที่รองรับ:\n• ตรวจ <IP/domain/hash> — ตรวจสอบ\n• สถานะ — ดูสถิติ feed\n• ช่วย — แสดงคำสั่ง'], token);
      } else {
        await lineReply(replyToken, ["ไม่เข้าใจคำสั่ง พิมพ์ 'ช่วย' เพื่อดูคำสั่งที่รองรับ"], token);
      }
    } catch (e) { console.error('[line-bot] reply error:', e.message); }
  }
});

// ============================================================
// FEATURE 5: AUTOMATED SCHEDULED REPORTS (weekly Monday 08:00)
// ============================================================
try {
  const cron = require('node-cron');
  const nodemailerAuto = require('nodemailer');
  cron.schedule('0 8 * * 1', async () => {
    const to = process.env.REPORT_EMAIL_TO || process.env.SMTP_TO;
    if (!to || !process.env.SMTP_HOST) return;
    try {
      const assets = await readData('assets');
      const vulns = await readData('vulns');
      const tickets = await readData('tickets');
      const openVulns = vulns.filter(v => v.status === 'Open' || !v.status);
      const openTickets = tickets.filter(t => t.status !== 'Closed');
      const html = `<h2 style="color:#1e40af">รายงาน Cybersecurity ประจำสัปดาห์</h2>
        <p>วันที่: ${new Date().toLocaleDateString('th-TH', {year:'numeric',month:'long',day:'numeric'})}</p>
        <table style="border-collapse:collapse;width:100%">
          <tr style="background:#f1f5f9"><td style="padding:8px;border:1px solid #e2e8f0"><b>Assets ทั้งหมด</b></td><td style="padding:8px;border:1px solid #e2e8f0">${assets.length}</td></tr>
          <tr><td style="padding:8px;border:1px solid #e2e8f0"><b>ช่องโหว่ที่ยังเปิด</b></td><td style="padding:8px;border:1px solid #e2e8f0;color:${openVulns.length>0?'#dc2626':'#16a34a'}">${openVulns.length}</td></tr>
          <tr style="background:#f1f5f9"><td style="padding:8px;border:1px solid #e2e8f0"><b>Incident ที่ค้างอยู่</b></td><td style="padding:8px;border:1px solid #e2e8f0;color:${openTickets.length>0?'#d97706':'#16a34a'}">${openTickets.length}</td></tr>
          <tr><td style="padding:8px;border:1px solid #e2e8f0"><b>IP Blacklist</b></td><td style="padding:8px;border:1px solid #e2e8f0">${store.ip?.set.size?.toLocaleString() || 0}</td></tr>
        </table>
        <p style="color:#64748b;font-size:0.8em">สร้างอัตโนมัติโดย NCSA Blacklist SOC Dashboard</p>`;
      const transport = nodemailerAuto.createTransport({
        host: process.env.SMTP_HOST, port: parseInt(process.env.SMTP_PORT || '587'),
        secure: process.env.SMTP_SECURE === 'true',
        auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
      });
      await transport.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to, subject: `[NCSA Dashboard] รายงานประจำสัปดาห์ ${new Date().toLocaleDateString('th-TH')}`, html });
      console.log('[weekly-report] sent to', to);
    } catch (e) { console.error('[weekly-report] failed:', e.message); }
  }, { timezone: 'Asia/Bangkok' });
} catch (e) { console.warn('[weekly-report] cron setup failed:', e.message); }

// ============================================================
// FEATURE 6: VULNERABILITY SCANNER WEBHOOK
// ============================================================
app.post('/webhook/vuln-scanner', requireAuth(), express.json({ limit: '10mb' }), async (req, res) => {
  const body = req.body;
  if (!body) return res.status(400).json({ error: 'body required' });

  const normalize = (items) => items.map(item => ({
    id: Date.now() + Math.floor(Math.random() * 100000),
    cveId: item.cveId || item.cve || item.CVE || '',
    host: item.host || item.ip || item.target || '',
    severity: (item.severity || item.risk || item.level || 'Medium').toUpperCase(),
    title: item.title || item.name || item.description?.substring(0, 100) || '',
    description: item.description || item.summary || '',
    status: 'Open',
    source: item._source || 'webhook',
    importedAt: new Date().toISOString(),
  }));

  let items = [];
  // OpenVAS/Greenbone
  if (body.report?.results?.result) {
    const results = Array.isArray(body.report.results.result) ? body.report.results.result : [body.report.results.result];
    items = results.map(r => ({ cveId: r.nvt?.cve || '', host: r.host?.text || r.host || '', severity: r.severity?.value || r.threat || 'Medium', title: r.name || r.nvt?.name || '', description: r.description || r.nvt?.tags?.summary || '', _source: 'openvas' }));
  } else if (body.results) {
    items = (Array.isArray(body.results) ? body.results : [body.results]).map(r => ({ ...r, _source: 'openvas' }));
  }
  // Generic array
  else if (Array.isArray(body)) {
    items = body;
  }
  // Nessus-ish
  else if (body.policy || body.nessusClientData_v2) {
    items = [{ cveId: '', host: 'nessus-import', severity: 'Medium', title: 'Nessus import — parse manually', description: JSON.stringify(body).substring(0, 200) }];
  }

  if (!items.length) return res.status(400).json({ error: 'no vulnerability items found in payload' });

  const normalized = normalize(items);
  const existing = await readData('vulns');
  const existingKeys = new Set(existing.map(v => `${v.cveId}|${v.host}`));
  const toAdd = normalized.filter(v => !existingKeys.has(`${v.cveId}|${v.host}`));
  const skipped = normalized.length - toAdd.length;
  await writeData('vulns', [...existing, ...toAdd]);
  auditLogRaw(req, 'vuln_import', `imported=${toAdd.length} skipped=${skipped}`);
  res.json({ ok: true, imported: toAdd.length, skipped, total: existing.length + toAdd.length });
});

// ============================================================
const PORT = process.env.PORT || 3939;
if (require.main === module) {
  const server = app.listen(PORT, () => console.log(`ncsa-blacklist API on :${PORT}`));
  function shutdown(signal) {
    console.log(`${signal} — shutting down gracefully`);
    server.close(() => { console.log('server closed'); process.exit(0); });
    setTimeout(() => { console.error('force exit after 10s'); process.exit(1); }, 10_000).unref();
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}
module.exports = { app };
