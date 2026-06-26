const fs = require('fs');
const path = require('path');
const { notify } = require('./notify');
const watchlist = require('./watchlist');
const { DATA_DIR } = require('./paths');
const { diffSets } = require('./diff');

const FEEDS = {
  ip: 'https://opendata.ncsa.or.th/ip/blocklist.json',
  domain: 'https://opendata.ncsa.or.th/domain/blocklist.json',
  hash: 'https://opendata.ncsa.or.th/hash/sha256.json',
};

const HISTORY_FILE = path.join(DATA_DIR, 'history.jsonl');

function appendHistory(entry) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.appendFileSync(HISTORY_FILE, JSON.stringify(entry) + '\n');
}

const ANOMALY_REMOVED_RATIO = 0.5;
const ANOMALY_MIN_PREV = 10;

async function fetchFeed(type, url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${type} fetch failed: HTTP ${res.status}`);
  const json = await res.json();
  if (!Array.isArray(json.data)) throw new Error(`${type} fetch returned malformed payload (no data array)`);

  const filePath = path.join(DATA_DIR, `${type}.json`);
  let prevValues = [];
  let prevSha256 = null;
  if (fs.existsSync(filePath)) {
    const prev = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    prevValues = prev.data;
    prevSha256 = prev.file?.sha256 ?? null;
  }

  // Skip write + history when upstream data is identical (same file SHA256)
  const newSha256 = json.file?.sha256 ?? null;
  if (prevSha256 && newSha256 && prevSha256 === newSha256) {
    return { type, total: json.total, added: 0, removed: 0, generated_at: json.generated_at, unchanged: true, watchHits: [] };
  }

  const { added, removed } = diffSets(prevValues, json.data);

  if (prevValues.length >= ANOMALY_MIN_PREV && removed.length / prevValues.length > ANOMALY_REMOVED_RATIO) {
    const pct = Math.round((removed.length / prevValues.length) * 100);
    throw new Error(`${type} anomaly: removed ${removed.length}/${prevValues.length} (${pct}%) in one sync — skipped write, check upstream feed`);
  }

  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(json));

  const watched = watchlist.load().filter((w) => w.type === type);
  const watchHits = watched.filter((w) => added.includes(w.value)).map((w) => w.value);

  const entry = {
    type,
    total: json.total,
    added: added.length,
    removed: removed.length,
    generated_at: json.generated_at,
    sha256: newSha256,
  };
  appendHistory({ date: new Date().toISOString(), ...entry });

  return { ...entry, watchHits };
}

async function fetchAll() {
  const results = [];
  for (const [type, url] of Object.entries(FEEDS)) {
    try {
      results.push(await fetchFeed(type, url));
    } catch (err) {
      results.push({ type, error: err.message });
    }
  }
  console.log(JSON.stringify(results, null, 2));
  await notify(results);
  return results;
}

if (require.main === module) {
  fetchAll();
}

module.exports = { fetchAll, FEEDS, DATA_DIR };
