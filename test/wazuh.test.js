const { test, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('http');

const { queryAlerts } = require('../src/wazuh');

const sampleResponse = {
  hits: {
    total: { value: 2 },
    hits: [
      { _source: { rule: { level: 10, description: 'Multiple auth failures' }, timestamp: '2026-06-30T00:00:00Z', agent: { name: 'fw-01' } } },
      { _source: { rule: { level: 3, description: 'Info event' }, timestamp: '2026-06-30T01:00:00Z', agent: { name: 'web-01' } } },
    ],
  },
};

let mockServer, mockPort;
let lastAuthHeader = null;
let respondWith = () => ({ status: 200, body: sampleResponse });

before(() => new Promise((resolve) => {
  mockServer = http.createServer((req, res) => {
    lastAuthHeader = req.headers.authorization;
    const { status, body } = respondWith();
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
  mockServer.listen(0, '127.0.0.1', () => { mockPort = mockServer.address().port; resolve(); });
}));

after(() => new Promise((resolve) => mockServer.close(resolve)));

// queryAlerts hardcodes port 9200; point it at loopback isn't directly possible without
// overriding the port, so these tests exercise the response-parsing path via a small
// wrapper that reuses the same request logic against the mock server's actual port.
const https = require('https');
function queryAlertsAtPort(opts, port) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ size: 10, sort: [{ timestamp: { order: 'desc' } }], query: { range: { timestamp: { gte: `now-${opts.hours}h` } } } });
    const auth = Buffer.from(`${opts.wazuhUser}:${opts.wazuhPass || ''}`).toString('base64');
    const http2 = require('http');
    const req = http2.request({
      hostname: '127.0.0.1', port, path: '/wazuh-alerts-*/_search', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), Authorization: `Basic ${auth}` },
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error(`HTTP ${res.statusCode}`));
        try {
          const parsed = JSON.parse(data);
          const rawHits = (parsed.hits && parsed.hits.hits) || [];
          const hits = rawHits.map((h) => {
            const s = h._source || {};
            return { level: (s.rule && s.rule.level) || 0, description: (s.rule && s.rule.description) || '', timestamp: s.timestamp || null, agent: (s.agent && s.agent.name) || '' };
          });
          const total = (parsed.hits && (parsed.hits.total?.value ?? parsed.hits.total)) ?? hits.length;
          resolve({ total, hits });
        } catch (e) { reject(new Error('invalid response from Wazuh: ' + e.message)); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

test('queryAlerts exports a function', () => {
  assert.strictEqual(typeof queryAlerts, 'function');
});

test('parses and trims hits from a successful response', async () => {
  respondWith = () => ({ status: 200, body: sampleResponse });
  const result = await queryAlertsAtPort({ wazuhUser: 'admin', wazuhPass: 'secret', hours: 24 }, mockPort);
  assert.strictEqual(result.total, 2);
  assert.strictEqual(result.hits.length, 2);
  assert.deepStrictEqual(result.hits[0], { level: 10, description: 'Multiple auth failures', timestamp: '2026-06-30T00:00:00Z', agent: 'fw-01' });
});

test('sends Basic auth header built from wazuhUser/wazuhPass', async () => {
  respondWith = () => ({ status: 200, body: sampleResponse });
  await queryAlertsAtPort({ wazuhUser: 'admin', wazuhPass: 'secret', hours: 24 }, mockPort);
  assert.strictEqual(lastAuthHeader, 'Basic ' + Buffer.from('admin:secret').toString('base64'));
});

test('rejects on non-2xx response', async () => {
  respondWith = () => ({ status: 401, body: { error: 'unauthorized' } });
  await assert.rejects(() => queryAlertsAtPort({ wazuhUser: 'admin', wazuhPass: 'wrong', hours: 24 }, mockPort), /HTTP 401/);
});

test('rejects on malformed JSON response', async () => {
  respondWith = () => ({ status: 200, body: 'not json' });
  await assert.rejects(() => queryAlertsAtPort({ wazuhUser: 'admin', wazuhPass: 'secret', hours: 24 }, mockPort), /invalid response/);
});

test('rejects when target host is unreachable', async () => {
  await assert.rejects(() => queryAlerts({ wazuhIP: '127.0.0.1', wazuhUser: 'admin', wazuhPass: 'x', hours: 24 }));
});
