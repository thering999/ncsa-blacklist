const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncsa-fetch-test-'));
process.env.DATA_DIR = tmpDir;
process.env.FETCH_RETRY_BASE_MS = '10'; // fast retries in tests (2^1*10=20ms, 2^2*10=40ms)

const feedData = {
  feed: 'ip',
  generated_at: new Date().toISOString(),
  valid_for_days: 7,
  total: 1,
  data: ['10.0.0.1'],
  file: { sha256: 'deadbeef01', entries: 1 },
};

let mockServer, mockPort;
let lastRequestHeaders = {};
let nextStatus = 200;
let nextEtag = null;
let failCount = 0; // number of times to return 500 before succeeding

before(() => new Promise((resolve) => {
  mockServer = http.createServer((req, res) => {
    lastRequestHeaders = Object.assign({}, req.headers);
    if (failCount > 0) { failCount--; res.writeHead(500); res.end('error'); return; }
    if (nextStatus === 304) { res.writeHead(304); res.end(); return; }
    const h = { 'Content-Type': 'application/json' };
    if (nextEtag) h['ETag'] = nextEtag;
    res.writeHead(200, h);
    res.end(JSON.stringify(feedData));
  });
  mockServer.listen(0, '127.0.0.1', () => {
    mockPort = mockServer.address().port;

    // Point ip feed at mock server (module not yet required — safe)
    const { FEEDS } = require('../src/fetch');
    FEEDS.ip = `http://127.0.0.1:${mockPort}/ip`;
    FEEDS.domain = `http://127.0.0.1:${mockPort}/domain`;
    FEEDS.hash = `http://127.0.0.1:${mockPort}/hash`;

    resolve();
  });
}));

after(() => new Promise((resolve) => {
  mockServer.close(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    resolve();
  });
}));

test('fetchAll writes data file on first fetch', async () => {
  nextStatus = 200; nextEtag = null;
  const { fetchAll } = require('../src/fetch');
  const results = await fetchAll();
  const r = results.find(r => r.type === 'ip');
  assert.ok(!r?.error, r?.error);
  assert.ok(fs.existsSync(path.join(tmpDir, 'ip.json')));
});

test('fetchAll persists ETag after response', async () => {
  nextStatus = 200; nextEtag = '"v1"';
  const { fetchAll } = require('../src/fetch');
  // New sha256 so it doesn't skip on sha256 match
  feedData.file.sha256 = 'deadbeef02';
  await fetchAll();
  const state = JSON.parse(fs.readFileSync(path.join(tmpDir, 'etag-state.json'), 'utf8'));
  assert.strictEqual(state.ip?.etag, '"v1"');
});

test('fetchAll sends If-None-Match on next request', async () => {
  nextStatus = 200; nextEtag = '"v1"';
  feedData.file.sha256 = 'deadbeef03';
  const { fetchAll } = require('../src/fetch');
  await fetchAll();
  assert.ok(lastRequestHeaders['if-none-match'], 'If-None-Match header must be sent');
  assert.strictEqual(lastRequestHeaders['if-none-match'], '"v1"');
});

test('fetchAll handles 304 without error', async () => {
  nextStatus = 304;
  const { fetchAll } = require('../src/fetch');
  const results = await fetchAll();
  const r = results.find(r => r.type === 'ip');
  assert.ok(!r?.error);
  assert.ok(r?.cached || r?.unchanged);
});

test('fetchWithRetry retries on HTTP 500 and succeeds', async () => {
  nextStatus = 200; nextEtag = null;
  feedData.file.sha256 = 'deadbeef04';
  failCount = 1; // fail once then succeed (consumed by ip's first attempt)
  const { fetchAll } = require('../src/fetch');
  const results = await fetchAll();
  const ipResult = results.find(r => r.type === 'ip');
  assert.ok(!ipResult?.error, `ip should succeed after retry, got: ${ipResult?.error}`);
  assert.strictEqual(failCount, 0, 'server failure should have been consumed by retry');
});
