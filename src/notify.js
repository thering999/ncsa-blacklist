const crypto = require('crypto');

async function notify(results) {
  const url = process.env.WEBHOOK_URL;
  if (!url) return;

  const errorLines = results
    .filter((r) => r.error)
    .map((r) => `ERROR [${r.type}]: ${r.error}`);

  const lines = results
    .filter((r) => !r.error)
    .filter((r) => r.added > 0 || r.removed > 0)
    .map((r) => `${r.type}: +${r.added} -${r.removed} (total ${r.total})`);

  const watchLines = results
    .filter((r) => r.watchHits && r.watchHits.length > 0)
    .map((r) => `WATCH HIT [${r.type}]: ${r.watchHits.join(', ')}`);

  if (errorLines.length === 0 && lines.length === 0 && watchLines.length === 0) return;

  const text = `NCSA blocklist sync\n${[...errorLines, ...lines, ...watchLines].join('\n')}`;
  const body = JSON.stringify({ text });
  const headers = { 'Content-Type': 'application/json' };

  const secret = process.env.WEBHOOK_SECRET;
  if (secret) {
    headers['X-Signature'] = 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
  }

  try {
    await fetch(url, { method: 'POST', headers, body });
  } catch (err) {
    console.error('notify failed:', err.message);
  }
}

module.exports = { notify };
