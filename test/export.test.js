const { test, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncsa-export-test-'));
const HASH = 'b'.repeat(64);

before(() => {
  function fixture(type, data) {
    return { feed: type, generated_at: '2026-01-01T00:00:00Z', valid_for_days: 7, total: data.length, data, file: { sha256: 'abc', entries: data.length } };
  }
  fs.writeFileSync(path.join(tmpDir, 'ip.json'), JSON.stringify(fixture('ip', ['10.0.0.1', '10.0.0.2'])));
  fs.writeFileSync(path.join(tmpDir, 'domain.json'), JSON.stringify(fixture('domain', ['evil.com', 'bad.org'])));
  fs.writeFileSync(path.join(tmpDir, 'hash.json'), JSON.stringify(fixture('hash', [HASH])));
});

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function run(script) {
  return execFileSync('node', [path.join(__dirname, '..', 'src', script)], {
    env: { ...process.env, DATA_DIR: tmpDir },
  }).toString();
}

test('export-iptables generates ipset commands', () => {
  const out = run('export-iptables.js');
  assert.ok(out.includes('#!/bin/sh'));
  assert.ok(out.includes('ipset create ncsa-blacklist'));
  assert.ok(out.includes('ipset add ncsa-blacklist 10.0.0.1'));
  assert.ok(out.includes('ipset add ncsa-blacklist 10.0.0.2'));
  assert.ok(out.includes('iptables -I INPUT'));
});

test('export-dnsmasq generates address= entries', () => {
  const out = run('export-dnsmasq.js');
  assert.ok(out.includes('address=/evil.com/0.0.0.0'));
  assert.ok(out.includes('address=/bad.org/0.0.0.0'));
});

test('export-wazuh-cdb generates hash:label lines', () => {
  const out = run('export-wazuh-cdb.js');
  assert.ok(out.includes(`${HASH}:ncsa-blacklist`));
});
