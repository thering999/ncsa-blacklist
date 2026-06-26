const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Must set DATA_DIR before requiring server (paths.js reads env at load time)
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncsa-server-test-'));
process.env.DATA_DIR = tmpDir;

function fixture(type, data) {
  return {
    feed: type,
    generated_at: new Date().toISOString(),
    valid_for_days: 7,
    total: data.length,
    data,
    file: { sha256: 'abc123', entries: data.length },
  };
}

const HASH = 'a'.repeat(64);
fs.writeFileSync(path.join(tmpDir, 'ip.json'), JSON.stringify(fixture('ip', ['1.2.3.4', '5.6.7.8'])));
fs.writeFileSync(path.join(tmpDir, 'domain.json'), JSON.stringify(fixture('domain', ['evil.com', 'bad.org'])));
fs.writeFileSync(path.join(tmpDir, 'hash.json'), JSON.stringify(fixture('hash', [HASH])));

const { app } = require('../src/server');

let server, baseUrl;
const openSockets = new Set();

before(() => new Promise((resolve) => {
  server = app.listen(0, '127.0.0.1', () => {
    baseUrl = `http://127.0.0.1:${server.address().port}`;
    resolve();
  });
  server.on('connection', (socket) => {
    openSockets.add(socket);
    socket.on('close', () => openSockets.delete(socket));
  });
}));

after(() => new Promise((resolve) => {
  for (const socket of openSockets) socket.destroy();
  const cleanup = () => { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {} resolve(); };
  server.close(cleanup);
  // Force resolve after 2s in case connections linger (unref = don't hold event loop)
  setTimeout(cleanup, 2000).unref();
}));

async function get(p) {
  const res = await fetch(baseUrl + p);
  const ct = res.headers.get('content-type') || '';
  return { status: res.status, body: ct.includes('json') ? await res.json() : await res.text() };
}

async function post(p, body, text = false) {
  const res = await fetch(baseUrl + p, {
    method: 'POST',
    headers: { 'Content-Type': text ? 'text/plain' : 'application/json' },
    body: text ? body : JSON.stringify(body),
  });
  const ct = res.headers.get('content-type') || '';
  return { status: res.status, body: ct.includes('json') ? await res.json() : await res.text() };
}

test('GET /healthz returns ok', async () => {
  const { status, body } = await get('/healthz');
  assert.strictEqual(status, 200);
  assert.strictEqual(body.ok, true);
});

test('GET /stats returns feed counts', async () => {
  const { status, body } = await get('/stats');
  assert.strictEqual(status, 200);
  assert.strictEqual(body.ip.total, 2);
  assert.strictEqual(body.domain.total, 2);
  assert.strictEqual(body.hash.total, 1);
});

test('GET /info returns feed metadata', async () => {
  const { status, body } = await get('/info');
  assert.strictEqual(status, 200);
  assert.strictEqual(body.ip.feed, 'ip');
});

test('GET /check/auto/ blacklisted IP', async () => {
  const { status, body } = await get('/check/auto/1.2.3.4');
  assert.strictEqual(status, 200);
  assert.strictEqual(body.blacklisted, true);
  assert.strictEqual(body.type, 'ip');
});

test('GET /check/auto/ clean IP', async () => {
  const { body } = await get('/check/auto/9.9.9.9');
  assert.strictEqual(body.blacklisted, false);
});

test('GET /check/auto/ blacklisted domain', async () => {
  const { body } = await get('/check/auto/evil.com');
  assert.strictEqual(body.blacklisted, true);
  assert.strictEqual(body.type, 'domain');
});

test('GET /check/auto/ parent-domain match', async () => {
  const { body } = await get('/check/auto/sub.evil.com');
  assert.strictEqual(body.blacklisted, true);
  assert.strictEqual(body.matchType, 'parent');
});

test('GET /check/auto/ blacklisted hash', async () => {
  const { body } = await get(`/check/auto/${HASH}`);
  assert.strictEqual(body.blacklisted, true);
  assert.strictEqual(body.type, 'hash');
});

test('GET /check/:type/:value - domain lookup', async () => {
  const { status, body } = await get('/check/domain/bad.org');
  assert.strictEqual(status, 200);
  assert.strictEqual(body.blacklisted, true);
});

test('POST /check/bulk auto-detects types', async () => {
  const { status, body } = await post('/check/bulk', { type: 'auto', values: ['1.2.3.4', '9.9.9.9', 'evil.com'] });
  assert.strictEqual(status, 200);
  assert.strictEqual(body.results[0].blacklisted, true);
  assert.strictEqual(body.results[1].blacklisted, false);
  assert.strictEqual(body.results[2].blacklisted, true);
});

test('POST /check/bulk rejects > 10000 values', async () => {
  const { status } = await post('/check/bulk', { values: new Array(10001).fill('1.2.3.4') });
  assert.strictEqual(status, 400);
});

test('POST /check/cidr finds hits in range', async () => {
  const { status, body } = await post('/check/cidr', { cidr: '1.2.3.0/24' });
  assert.strictEqual(status, 200);
  assert.ok(body.hits.some((h) => h.ip === '1.2.3.4'));
});

test('POST /check/cidr rejects too-large range', async () => {
  const { status } = await post('/check/cidr', { cidr: '0.0.0.0/15' });
  assert.strictEqual(status, 400);
});

test('POST /check/cidr rejects invalid CIDR', async () => {
  const { status } = await post('/check/cidr', { cidr: 'not-a-cidr' });
  assert.strictEqual(status, 400);
});

test('POST /check/cidr IPv6 range returns 200', async () => {
  // fixture has no IPv6 IPs so hits will be empty, but request should succeed
  const { status, body } = await post('/check/cidr', { cidr: '2001:db8::/112' });
  assert.strictEqual(status, 200);
  assert.ok(Array.isArray(body.hits));
  assert.strictEqual(body.hits.length, 0);
  assert.ok(typeof body.total_in_range === 'number');
});

test('POST /check/cidr rejects too-large IPv6 range', async () => {
  const { status } = await post('/check/cidr', { cidr: '2001:db8::/111' });
  assert.strictEqual(status, 400);
});

test('GET /search returns matching results', async () => {
  const { status, body } = await get('/search?type=ip&q=1.2.3');
  assert.strictEqual(status, 200);
  assert.ok(body.results.includes('1.2.3.4'));
});

test('GET /search rejects short query', async () => {
  const { status } = await get('/search?type=ip&q=ab');
  assert.strictEqual(status, 400);
});

test('POST /scan finds blacklisted IPs in log text', async () => {
  const { status, body } = await post('/scan', 'Connection from 1.2.3.4 to server', true);
  assert.strictEqual(status, 200);
  assert.ok(body.hits.includes('1.2.3.4'));
});

test('POST /scan returns zero hits for clean text', async () => {
  const { body } = await post('/scan', 'Connection from 9.9.9.9 only', true);
  assert.strictEqual(body.hits.length, 0);
});

test('GET /analyze/countries returns breakdown', async () => {
  const { status, body } = await get('/analyze/countries');
  assert.strictEqual(status, 200);
  assert.ok(typeof body.total_ips === 'number');
  assert.ok(Array.isArray(body.top));
});

test('GET /analyze/networks returns top /24 networks', async () => {
  const { status, body } = await get('/analyze/networks');
  assert.strictEqual(status, 200);
  assert.ok(typeof body.total_networks === 'number');
});

test('GET /analyze/asns returns ASN breakdown', async () => {
  const { status, body } = await get('/analyze/asns');
  assert.strictEqual(status, 200);
  assert.ok(Array.isArray(body.top));
});

test('GET /watch returns array', async () => {
  const { status, body } = await get('/watch');
  assert.strictEqual(status, 200);
  assert.ok(Array.isArray(body));
});

test('GET /metrics returns Prometheus text', async () => {
  const res = await fetch(baseUrl + '/metrics');
  const text = await res.text();
  assert.strictEqual(res.status, 200);
  assert.ok(text.includes('ncsa_store_size'));
  assert.ok(text.includes('ncsa_feed_up'));
  assert.ok(text.includes('ncsa_feed_file_age_seconds'));
});

test('GET /history returns array', async () => {
  const { status, body } = await get('/history');
  assert.strictEqual(status, 200);
  assert.ok(Array.isArray(body));
});

test('GET /metrics open when METRICS_TOKEN unset', async () => {
  const res = await fetch(baseUrl + '/metrics');
  assert.strictEqual(res.status, 200);
});

test('GET /metrics returns 401 when METRICS_TOKEN set and no auth', async () => {
  process.env.METRICS_TOKEN = 'secret123';
  const res = await fetch(baseUrl + '/metrics');
  assert.strictEqual(res.status, 401);
  delete process.env.METRICS_TOKEN;
});

test('GET /metrics accepts correct METRICS_TOKEN', async () => {
  process.env.METRICS_TOKEN = 'secret123';
  const res = await fetch(baseUrl + '/metrics', { headers: { Authorization: 'Bearer secret123' } });
  assert.strictEqual(res.status, 200);
  delete process.env.METRICS_TOKEN;
});

test('GET /allowlist returns array', async () => {
  const { status, body } = await get('/allowlist');
  assert.strictEqual(status, 200);
  assert.ok(Array.isArray(body));
});

test('GET /check/auto/ allowlisted IP overrides blacklist', async () => {
  // 1.2.3.4 is in blacklist fixture; add to allowlist
  await post('/allowlist', { type: 'ip', value: '1.2.3.4' });
  const { body } = await get('/check/auto/1.2.3.4');
  assert.strictEqual(body.blacklisted, false);
  assert.strictEqual(body.allowlisted, true);
  // cleanup
  await fetch(baseUrl + '/allowlist', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'ip', value: '1.2.3.4' }) });
});

test('responses include X-Request-Id header', async () => {
  const res = await fetch(baseUrl + '/healthz');
  const rid = res.headers.get('x-request-id');
  assert.ok(rid, 'X-Request-Id header must be present');
  assert.match(rid, /^[0-9a-f-]{36}$/, 'must be a UUID');
});

test('POST /watch rejects invalid IP format', async () => {
  const { status, body } = await post('/watch', { type: 'ip', value: 'not-an-ip' });
  assert.strictEqual(status, 400);
  assert.ok(body.error.includes('invalid IP'));
});

test('POST /allowlist rejects invalid hash format', async () => {
  const { status, body } = await post('/allowlist', { type: 'hash', value: 'tooshort' });
  assert.strictEqual(status, 400);
  assert.ok(body.error.includes('SHA256'));
});

test('POST /scan excludes allowlisted IPs from hits', async () => {
  // Add 1.2.3.4 to allowlist
  await post('/allowlist', { type: 'ip', value: '1.2.3.4' });
  const { body } = await post('/scan', 'Connection from 1.2.3.4 and 5.6.7.8', true);
  assert.ok(!body.hits.includes('1.2.3.4'), '1.2.3.4 should be excluded by allowlist');
  assert.ok(body.hits.includes('5.6.7.8'), '5.6.7.8 should still be reported');
  // cleanup
  await fetch(baseUrl + '/allowlist', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'ip', value: '1.2.3.4' }) });
});

test('GET /admin/feed-health returns per-feed status (no auth configured)', async () => {
  const { status, body } = await get('/admin/feed-health');
  assert.strictEqual(status, 200);
  assert.ok(body.feeds);
  assert.ok('ip' in body.feeds);
  assert.ok('domain' in body.feeds);
  assert.ok('hash' in body.feeds);
  assert.strictEqual(body.feeds.ip.status, 'ok');
  assert.strictEqual(body.feeds.ip.entries, 2);
  assert.ok(typeof body.feeds.ip.file_age_seconds === 'number');
  assert.ok(body.feeds.ip.last_modified);
  assert.ok(body.feeds.ip.file_size_kb >= 0);
  assert.ok(body.feeds.ip.url.startsWith('https://'));
});
