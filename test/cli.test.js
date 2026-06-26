const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncsa-cli-test-'));
const HASH = 'c'.repeat(64);

before(() => {
  function fixture(type, data) {
    return { feed: type, generated_at: '2026-01-01T00:00:00Z', valid_for_days: 7, total: data.length, data, file: { sha256: 'abc', entries: data.length } };
  }
  fs.writeFileSync(path.join(tmpDir, 'ip.json'), JSON.stringify(fixture('ip', ['1.2.3.4'])));
  fs.writeFileSync(path.join(tmpDir, 'domain.json'), JSON.stringify(fixture('domain', ['evil.com'])));
  fs.writeFileSync(path.join(tmpDir, 'hash.json'), JSON.stringify(fixture('hash', [HASH])));
});

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

const CLI = path.join(__dirname, '..', 'src', 'cli.js');
const ENV = { ...process.env, DATA_DIR: tmpDir };

function run(...args) {
  const r = spawnSync('node', [CLI, ...args], { env: ENV, encoding: 'utf8' });
  return { stdout: r.stdout, stderr: r.stderr, code: r.status };
}

test('cli: blacklisted IP shows BLACKLISTED', () => {
  const { stdout, code } = run('1.2.3.4');
  assert.ok(stdout.includes('BLACKLISTED'), `expected BLACKLISTED in: ${stdout}`);
  assert.strictEqual(code, 0);
});

test('cli: clean IP shows clean', () => {
  const { stdout, code } = run('9.9.9.9');
  assert.ok(stdout.includes('clean'), `expected clean in: ${stdout}`);
  assert.strictEqual(code, 0);
});

test('cli: blacklisted domain shows BLACKLISTED', () => {
  const { stdout, code } = run('evil.com');
  assert.ok(stdout.includes('BLACKLISTED'), stdout);
  assert.strictEqual(code, 0);
});

test('cli: blacklisted hash shows BLACKLISTED', () => {
  const { stdout, code } = run(HASH);
  assert.ok(stdout.includes('BLACKLISTED'), stdout);
  assert.strictEqual(code, 0);
});

test('cli: legacy "ip value" syntax works', () => {
  const { stdout, code } = run('ip', '1.2.3.4');
  assert.ok(stdout.includes('BLACKLISTED'), stdout);
  assert.strictEqual(code, 0);
});

test('cli: no args prints usage and exits 1', () => {
  const { stderr, code } = run();
  assert.ok(stderr.includes('usage'), stderr);
  assert.strictEqual(code, 1);
});
