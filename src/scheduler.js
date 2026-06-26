const cron = require('node-cron');
const fs = require('fs');
const path = require('path');
const { fetchAll, FEEDS, DATA_DIR } = require('./fetch');
const { notifyStale } = require('./notify');

cron.schedule('0 1 * * *', () => {
  console.log('running daily NCSA feed sync...');
  fetchAll();
});

const STALE_ALERT_FILE = path.join(DATA_DIR, 'stale-alert-state.json');
const ALERT_COOLDOWN_MS = 24 * 3600_000; // re-alert at most once per 24h per feed

function loadAlertState() {
  try { return JSON.parse(fs.readFileSync(STALE_ALERT_FILE, 'utf8')); } catch { return {}; }
}

function saveAlertState(state) {
  try { fs.writeFileSync(STALE_ALERT_FILE, JSON.stringify(state)); } catch {}
}

// Hourly stale check: alert if any feed file > 25h old or missing (deduped per 24h)
cron.schedule('0 * * * *', async () => {
  const now = Date.now();
  const state = loadAlertState();
  const toAlert = [];

  for (const type of Object.keys(FEEDS)) {
    const f = path.join(DATA_DIR, `${type}.json`);
    let isStale = false;
    let age_hours = null;
    try {
      const age = now - fs.statSync(f).mtimeMs;
      if (age > 25 * 3600_000) { isStale = true; age_hours = Math.round(age / 3600_000); }
    } catch { isStale = true; }

    if (isStale) {
      const lastAlerted = state[type] || 0;
      if (now - lastAlerted >= ALERT_COOLDOWN_MS) {
        toAlert.push({ type, age_hours });
        state[type] = now;
      }
    } else {
      // feed recovered — clear state so next stale triggers a fresh alert
      delete state[type];
    }
  }

  if (toAlert.length) {
    console.warn('stale feeds (alerting):', toAlert.map(s => s.type).join(', '));
    await notifyStale(toAlert);
    saveAlertState(state);
  } else if (Object.keys(state).length) {
    saveAlertState(state);
  }
});

console.log('scheduler started — daily sync at 01:00, stale check every hour');
