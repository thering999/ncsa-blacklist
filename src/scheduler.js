const cron = require('node-cron');
const fs = require('fs');
const path = require('path');
const { fetchAll, FEEDS, DATA_DIR } = require('./fetch');
const { notifyStale } = require('./notify');

cron.schedule('0 1 * * *', () => {
  console.log('running daily NCSA feed sync...');
  fetchAll();
});

// Hourly stale check: alert if any feed file > 25h old or missing
cron.schedule('0 * * * *', async () => {
  const now = Date.now();
  const stale = [];
  for (const type of Object.keys(FEEDS)) {
    const f = path.join(DATA_DIR, `${type}.json`);
    try {
      const age = now - fs.statSync(f).mtimeMs;
      if (age > 25 * 3600_000) stale.push({ type, age_hours: Math.round(age / 3600_000) });
    } catch {
      stale.push({ type, age_hours: null });
    }
  }
  if (stale.length) {
    console.warn('stale feeds:', stale.map(s => s.type).join(', '));
    await notifyStale(stale);
  }
});

console.log('scheduler started — daily sync at 01:00, stale check every hour');
