const { test } = require('node:test');
const assert = require('node:assert');
const { scanLog } = require('../src/scan');

test('flags IPs present in the blocklist set', () => {
  const set = new Set(['1.2.3.4']);
  const log = 'GET / from 1.2.3.4 then 8.8.8.8 again';
  const result = scanLog(log, set);
  assert.strictEqual(result.scanned, 2);
  assert.deepStrictEqual(result.hits, ['1.2.3.4']);
});

test('dedupes repeated IPs before counting', () => {
  const set = new Set();
  const log = '1.2.3.4 1.2.3.4 1.2.3.4';
  const result = scanLog(log, set);
  assert.strictEqual(result.scanned, 1);
});

test('returns no hits when nothing matches', () => {
  const set = new Set(['9.9.9.9']);
  const result = scanLog('8.8.8.8 1.1.1.1', set);
  assert.strictEqual(result.hits.length, 0);
});

test('ignores text with no IPv4 addresses', () => {
  const result = scanLog('no ip here, just text', new Set());
  assert.strictEqual(result.scanned, 0);
  assert.deepStrictEqual(result.hits, []);
});
