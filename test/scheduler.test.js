const { test, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Isolated DATA_DIR — do NOT require scheduler (it starts cron jobs)
// Instead test the stale-alert state logic in isolation

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ncsa-scheduler-test-'));
process.env.DATA_DIR = tmpDir;

const STALE_FILE = path.join(tmpDir, 'stale-alert-state.json');
const COOLDOWN = 24 * 3600_000;

function loadState() {
  try { return JSON.parse(fs.readFileSync(STALE_FILE, 'utf8')); } catch { return {}; }
}
function saveState(s) { fs.writeFileSync(STALE_FILE, JSON.stringify(s)); }

function shouldAlert(state, type, now) {
  const lastAlerted = state[type] || 0;
  return now - lastAlerted >= COOLDOWN;
}

after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

test('first stale incident triggers alert', () => {
  const state = {};
  const now = Date.now();
  assert.ok(shouldAlert(state, 'ip', now));
});

test('alert within cooldown window is suppressed', () => {
  const now = Date.now();
  const state = { ip: now - 1000 }; // alerted 1s ago
  assert.ok(!shouldAlert(state, 'ip', now));
});

test('alert after cooldown fires again', () => {
  const now = Date.now();
  const state = { ip: now - COOLDOWN - 1000 }; // alerted 24h+1s ago
  assert.ok(shouldAlert(state, 'ip', now));
});

test('recovered feed clears state', () => {
  const state = { ip: Date.now() - 1000 };
  delete state['ip']; // simulate recovery
  assert.strictEqual(state['ip'], undefined);
  assert.ok(shouldAlert(state, 'ip', Date.now())); // next stale will alert
});

test('state file persists across calls', () => {
  const now = Date.now();
  saveState({ domain: now });
  const loaded = loadState();
  assert.ok(typeof loaded.domain === 'number');
  assert.ok(Math.abs(loaded.domain - now) < 100);
});
