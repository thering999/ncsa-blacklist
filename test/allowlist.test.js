const { test, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncsa-allowlist-test-'));
process.env.DATA_DIR = tmpDir;

const allowlist = require('../src/allowlist');

after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

test('starts empty', () => {
  assert.deepStrictEqual(allowlist.load(), []);
});

test('add stores entry', () => {
  allowlist.add('ip', '8.8.8.8');
  assert.deepStrictEqual(allowlist.load(), [{ type: 'ip', value: '8.8.8.8' }]);
});

test('add is idempotent', () => {
  allowlist.add('ip', '8.8.8.8');
  assert.strictEqual(allowlist.load().length, 1);
});

test('check returns true for allowlisted value', () => {
  assert.strictEqual(allowlist.check('ip', '8.8.8.8'), true);
});

test('check returns false for non-allowlisted value', () => {
  assert.strictEqual(allowlist.check('ip', '1.2.3.4'), false);
});

test('check is type-scoped', () => {
  assert.strictEqual(allowlist.check('domain', '8.8.8.8'), false);
});

test('remove deletes matching entry', () => {
  allowlist.add('domain', 'safe.com');
  allowlist.remove('ip', '8.8.8.8');
  assert.deepStrictEqual(allowlist.load(), [{ type: 'domain', value: 'safe.com' }]);
});
