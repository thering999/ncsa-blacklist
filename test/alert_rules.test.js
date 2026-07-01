const { test, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncsa-alertrules-test-'));
process.env.DATA_DIR = tmpDir;

const alertRules = require('../src/alert_rules');
const { evaluateRules } = require('../src/notify');

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('starts empty', () => {
  assert.deepStrictEqual(alertRules.load(), []);
});

test('create stores rule with defaults', () => {
  const r = alertRules.create({ name: 'r1', enabled: true, condition: { field: 'added_count', operator: 'gt', value: '0' }, cooldown_minutes: 60, last_fired: null });
  assert.strictEqual(r.name, 'r1');
  assert.strictEqual(alertRules.load().length, 1);
});

test('update patches fields by id', () => {
  const [r] = alertRules.load();
  const updated = alertRules.update(r.id, { last_fired: '2026-01-01T00:00:00.000Z' });
  assert.strictEqual(updated.last_fired, '2026-01-01T00:00:00.000Z');
});

test('remove deletes rule', () => {
  const [r] = alertRules.load();
  alertRules.remove(r.id);
  assert.deepStrictEqual(alertRules.load(), []);
});

test('max rules enforced', () => {
  for (let i = 0; i < 20; i++) {
    alertRules.create({ name: `r${i}`, enabled: true, condition: { field: 'added_count', operator: 'gt', value: '0' } });
  }
  assert.throws(() => alertRules.create({ name: 'overflow', enabled: true, condition: { field: 'added_count', operator: 'gt', value: '0' } }));
  for (const r of alertRules.load()) alertRules.remove(r.id);
});

test('evaluateRules fires on match with no channels configured (no-op send, cooldown recorded)', async () => {
  const env = process.env;
  delete process.env.WEBHOOK_URL;
  delete process.env.LINE_NOTIFY_TOKEN;
  delete process.env.SMTP_HOST;
  const rule = alertRules.create({ name: 'spike', enabled: true, condition: { field: 'total_count', operator: 'gte', value: '100' }, cooldown_minutes: 60, last_fired: null });
  await evaluateRules([{ type: 'ip', added: 5, removed: 0, total: 150 }]);
  const after1 = alertRules.load().find(r => r.id === rule.id);
  assert.ok(after1.last_fired, 'last_fired should be set after a match');
  process.env = env;
});

test('evaluateRules suppresses repeat fire within cooldown window', async () => {
  const env = process.env;
  delete process.env.WEBHOOK_URL;
  delete process.env.LINE_NOTIFY_TOKEN;
  delete process.env.SMTP_HOST;
  for (const r of alertRules.load()) alertRules.remove(r.id);
  const rule = alertRules.create({ name: 'watch', enabled: true, condition: { field: 'watch_hit_count', operator: 'gt', value: '0' }, cooldown_minutes: 60, last_fired: new Date().toISOString() });
  await evaluateRules([{ type: 'ip', added: 1, removed: 0, total: 10, watchHits: ['1.2.3.4'] }]);
  const stillSame = alertRules.load().find(r => r.id === rule.id);
  assert.strictEqual(stillSame.last_fired, rule.last_fired, 'last_fired must not change while on cooldown');
  process.env = env;
});

test('evaluateRules fires again once cooldown has expired', async () => {
  const env = process.env;
  delete process.env.WEBHOOK_URL;
  delete process.env.LINE_NOTIFY_TOKEN;
  delete process.env.SMTP_HOST;
  for (const r of alertRules.load()) alertRules.remove(r.id);
  const stale = new Date(Date.now() - 120 * 60_000).toISOString();
  const rule = alertRules.create({ name: 'expired', enabled: true, condition: { field: 'removed_count', operator: 'gte', value: '1' }, cooldown_minutes: 60, last_fired: stale });
  await evaluateRules([{ type: 'domain', added: 0, removed: 3, total: 10 }]);
  const refreshed = alertRules.load().find(r => r.id === rule.id);
  assert.notStrictEqual(refreshed.last_fired, stale, 'cooldown expired rule should refire and update last_fired');
  process.env = env;
});
