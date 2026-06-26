const crypto = require('crypto');

async function notifyWebhook(url, body, headers) {
  const secret = process.env.WEBHOOK_SECRET;
  if (secret) headers['X-Signature'] = 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
  try {
    await fetch(url, { method: 'POST', headers, body });
  } catch (err) {
    console.error('webhook notify failed:', err.message);
  }
}

async function notifyLine(text) {
  const token = process.env.LINE_NOTIFY_TOKEN;
  if (!token) return;
  const params = new URLSearchParams({ message: '\n' + text });
  try {
    await fetch('https://notify-api.line.me/api/notify', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
  } catch (err) {
    console.error('line notify failed:', err.message);
  }
}

async function notifyEmail(subject, text) {
  const host = process.env.SMTP_HOST;
  if (!host) return;
  let nodemailer;
  try { nodemailer = require('nodemailer'); } catch { return; }
  const transporter = nodemailer.createTransport({
    host,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
  });
  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: process.env.SMTP_TO,
      subject,
      text,
    });
  } catch (err) {
    console.error('email notify failed:', err.message);
  }
}

async function notify(results) {
  const errorLines = results.filter(r => r.error).map(r => `ERROR [${r.type}]: ${r.error}`);
  const lines = results.filter(r => !r.error && (r.added > 0 || r.removed > 0))
    .map(r => `${r.type}: +${r.added} -${r.removed} (total ${r.total})`);
  const watchLines = results.filter(r => r.watchHits?.length > 0)
    .map(r => `WATCH HIT [${r.type}]: ${r.watchHits.join(', ')}`);

  if (errorLines.length === 0 && lines.length === 0 && watchLines.length === 0) return;
  const text = `NCSA blocklist sync\n${[...errorLines, ...lines, ...watchLines].join('\n')}`;

  const webhookUrl = process.env.WEBHOOK_URL;
  if (webhookUrl) {
    const body = JSON.stringify({ text });
    await notifyWebhook(webhookUrl, body, { 'Content-Type': 'application/json' });
  }

  if (process.env.LINE_NOTIFY_TOKEN) await notifyLine(text);

  if (process.env.SMTP_HOST && process.env.SMTP_TO) {
    const hasWatch = watchLines.length > 0;
    await notifyEmail(
      hasWatch ? `[NCSA] Watch hit detected` : `[NCSA] Blocklist sync update`,
      text
    );
  }
}

module.exports = { notify };
