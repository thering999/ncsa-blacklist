const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncsa-watchlist-test-'));
process.env.DATA_DIR = tmpDir;

const watchlist = require('../src/watchlist');

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('starts empty', () => {
  assert.deepStrictEqual(watchlist.load(), []);
});

test('add stores an entry', () => {
  watchlist.add('ip', '1.2.3.4');
  assert.deepStrictEqual(watchlist.load(), [{ type: 'ip', value: '1.2.3.4' }]);
});

test('add is idempotent for duplicate type+value', () => {
  watchlist.add('ip', '1.2.3.4');
  assert.strictEqual(watchlist.load().length, 1);
});

test('remove deletes the matching entry', () => {
  watchlist.add('domain', 'evil.com');
  watchlist.remove('ip', '1.2.3.4');
  assert.deepStrictEqual(watchlist.load(), [{ type: 'domain', value: 'evil.com' }]);
});
