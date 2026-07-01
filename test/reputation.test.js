const { test, after } = require('node:test');
const assert = require('node:assert');

const reputation = require('../src/reputation');

const realFetch = global.fetch;
after(() => { global.fetch = realFetch; });

test('lookup returns unavailable abuseipdb placeholder when no keys configured', async () => {
  const env = process.env;
  delete process.env.ABUSEIPDB_KEY;
  delete process.env.VIRUSTOTAL_KEY;
  const out = await reputation.lookup('1.2.3.4');
  assert.deepStrictEqual(out, [{ source: 'abuseipdb', available: false }]);
  process.env = env;
});

test('lookup queries only sources with a configured key', async () => {
  const env = process.env;
  process.env.ABUSEIPDB_KEY = 'test-key';
  delete process.env.VIRUSTOTAL_KEY;
  reputation._cache.clear();
  global.fetch = async (url) => {
    assert.ok(String(url).includes('abuseipdb.com'));
    return { ok: true, json: async () => ({ data: { abuseConfidenceScore: 42, totalReports: 3, isp: 'Acme', usageType: 'hosting' } }) };
  };
  const out = await reputation.lookup('5.6.7.8');
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].source, 'abuseipdb');
  assert.strictEqual(out[0].available, true);
  assert.strictEqual(out[0].score, 42);
  process.env = env;
});

test('lookup runs multiple sources in parallel when both keys set', async () => {
  const env = process.env;
  process.env.ABUSEIPDB_KEY = 'k1';
  process.env.VIRUSTOTAL_KEY = 'k2';
  reputation._cache.clear();
  global.fetch = async (url) => {
    if (String(url).includes('abuseipdb.com')) {
      return { ok: true, json: async () => ({ data: { abuseConfidenceScore: 10 } }) };
    }
    return { ok: true, json: async () => ({ data: { attributes: { last_analysis_stats: { malicious: 2, suspicious: 0, harmless: 8, undetected: 0 }, as_owner: 'Test ASN', country: 'TH' } } }) };
  };
  const out = await reputation.lookup('9.9.9.9');
  const sources = out.map(s => s.source).sort();
  assert.deepStrictEqual(sources, ['abuseipdb', 'virustotal']);
  const vt = out.find(s => s.source === 'virustotal');
  assert.strictEqual(vt.score, 20);
  process.env = env;
});

test('lookup marks source unavailable on fetch failure', async () => {
  const env = process.env;
  process.env.ABUSEIPDB_KEY = 'k1';
  delete process.env.VIRUSTOTAL_KEY;
  reputation._cache.clear();
  global.fetch = async () => ({ ok: false, status: 500 });
  const out = await reputation.lookup('1.1.1.1');
  assert.strictEqual(out[0].available, false);
  assert.ok(out[0].error);
  process.env = env;
});

test('cache evicts oldest entry once over capacity', async () => {
  const env = process.env;
  process.env.ABUSEIPDB_KEY = 'k1';
  delete process.env.VIRUSTOTAL_KEY;
  reputation._cache.clear();
  let calls = 0;
  global.fetch = async () => { calls++; return { ok: true, json: async () => ({ data: { abuseConfidenceScore: 1 } }) }; };
  await reputation.lookup('2.2.2.2');
  assert.strictEqual(calls, 1);
  await reputation.lookup('2.2.2.2');
  assert.strictEqual(calls, 1, 'second lookup of same ip should hit cache');
  process.env = env;
});
