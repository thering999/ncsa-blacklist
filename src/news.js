const CKAN_PKG = 'https://data.go.th/api/3/action/package_show?id=gdpublish-https-www-thaicert-or-th-category-cybernews';

let cache = { items: [], source: null, fetchedAt: 0 };
const TTL = 6 * 60 * 60 * 1000; // 6 hours

function parseCSV(text) {
  const lines = text.trim().split('\n');
  const results = [];
  // skip header row (ข่าวที่,ข่าวเรื่อง,แหล่งข่าว)
  for (let i = 1; i < lines.length; i++) {
    const cols = splitCSVLine(lines[i]);
    if (cols.length >= 3) {
      results.push({ id: cols[0].trim(), headline: cols[1].trim(), url: cols[2].trim() });
    }
  }
  return results;
}

function splitCSVLine(line) {
  const cols = [];
  let i = 0;
  while (i <= line.length) {
    if (i === line.length) break;
    if (line[i] === '"') {
      let j = i + 1;
      while (j < line.length) {
        if (line[j] === '"') { if (line[j + 1] === '"') { j += 2; continue; } break; }
        j++;
      }
      cols.push(line.slice(i + 1, j).replace(/""/g, '"'));
      i = j + 2;
    } else {
      const j = line.indexOf(',', i);
      if (j === -1) { cols.push(line.slice(i)); break; }
      cols.push(line.slice(i, j));
      i = j + 1;
    }
  }
  return cols;
}

async function fetchLatestNews() {
  if (cache.fetchedAt && Date.now() - cache.fetchedAt < TTL) return cache;

  try {
    const pkg = await fetch(CKAN_PKG, { signal: AbortSignal.timeout(10_000) }).then(r => r.json());
    const resources = pkg.result?.resources ?? [];
    // newest resource is last in the list (CKAN append order)
    const latest = [...resources].reverse().find(r => r.url);
    if (!latest) throw new Error('no resource found');

    const csv = await fetch(latest.url, { signal: AbortSignal.timeout(15_000) }).then(r => r.text());
    const items = parseCSV(csv).reverse(); // newest items first

    cache = { items, source: latest.name || latest.created?.slice(0, 7), fetchedAt: Date.now() };
    console.log(`news: fetched ${items.length} items from "${latest.name}"`);
  } catch (err) {
    console.error('news fetch failed:', err.message);
    // return stale cache if available, else empty
  }
  return cache;
}

module.exports = { fetchLatestNews };
