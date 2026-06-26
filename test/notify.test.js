const { test, after } = require('node:test');
const assert = require('node:assert');

test('notifyStale exported from notify', () => {
  const { notify, notifyStale } = require('../src/notify');
  assert.strictEqual(typeof notify, 'function');
  assert.strictEqual(typeof notifyStale, 'function');
});

test('notifyStale returns without sending when no channels configured', async () => {
  const env = process.env;
  delete process.env.WEBHOOK_URL;
  delete process.env.LINE_NOTIFY_TOKEN;
  delete process.env.SMTP_HOST;
  const { notifyStale } = require('../src/notify');
  // should resolve without error even with stale feeds
  await assert.doesNotReject(() => notifyStale([{ type: 'ip', age_hours: 30 }]));
  process.env = env;
});

test('notifyStale no-ops for empty list', async () => {
  const { notifyStale } = require('../src/notify');
  await assert.doesNotReject(() => notifyStale([]));
});
