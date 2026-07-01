const CACHE_MAX = 5000;
const CACHE_TTL = 3600_000;

const _cache = new Map();

function cacheGet(key) {
  const hit = _cache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.ts >= CACHE_TTL) {
    _cache.delete(key);
    return null;
  }
  // refresh recency for simple LRU behavior
  _cache.delete(key);
  _cache.set(key, hit);
  return hit.data;
}

function cacheSet(key, data) {
  if (_cache.size >= CACHE_MAX) {
    const oldestKey = _cache.keys().next().value;
    _cache.delete(oldestKey);
  }
  _cache.set(key, { data, ts: Date.now() });
}

async function fetchAbuseIpDb(ip, apiKey) {
  const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
    headers: { Key: apiKey, Accept: 'application/json' },
    signal: AbortSignal.timeout(5000),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const j = await r.json();
  const d = j.data || {};
  return {
    score: d.abuseConfidenceScore ?? 0,
    totalReports: d.totalReports ?? 0,
    lastReported: d.lastReportedAt ?? null,
    isp: d.isp ?? '',
    usageType: d.usageType ?? '',
  };
}

async function fetchVirusTotal(ip, apiKey) {
  const r = await fetch(`https://www.virustotal.com/api/v3/ip-addresses/${encodeURIComponent(ip)}`, {
    headers: { 'x-apikey': apiKey },
    signal: AbortSignal.timeout(5000),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const j = await r.json();
  const attr = j.data?.attributes || {};
  const stats = attr.last_analysis_stats || {};
  const malicious = stats.malicious ?? 0;
  const total = (stats.malicious ?? 0) + (stats.suspicious ?? 0) + (stats.harmless ?? 0) + (stats.undetected ?? 0);
  return {
    score: total > 0 ? Math.round((malicious / total) * 100) : 0,
    maliciousVotes: malicious,
    totalVotes: total,
    asOwner: attr.as_owner ?? '',
    country: attr.country ?? '',
  };
}

const SOURCES = {
  abuseipdb: { envKey: 'ABUSEIPDB_KEY', fetch: fetchAbuseIpDb },
  virustotal: { envKey: 'VIRUSTOTAL_KEY', fetch: fetchVirusTotal },
};

async function lookup(ip) {
  const active = Object.entries(SOURCES).filter(([, s]) => process.env[s.envKey]);
  if (active.length === 0) return [{ source: 'abuseipdb', available: false }];

  return Promise.all(active.map(async ([name, s]) => {
    const cacheKey = `${name}:${ip}`;
    const cached = cacheGet(cacheKey);
    if (cached) return { source: name, available: true, ...cached };
    try {
      const data = await s.fetch(ip, process.env[s.envKey]);
      cacheSet(cacheKey, data);
      return { source: name, available: true, ...data };
    } catch (e) {
      return { source: name, available: false, error: e.message };
    }
  }));
}

module.exports = { lookup, SOURCES, _cache };
