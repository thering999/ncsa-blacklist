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

function buildHtml(subject, lines) {
  const rows = lines.map(l => {
    const isWatch = l.startsWith('WATCH');
    const isError = l.startsWith('ERROR');
    const color = isWatch ? '#dc2626' : isError ? '#d97706' : '#374151';
    const bg = isWatch ? '#fef2f2' : isError ? '#fffbeb' : 'transparent';
    return `<tr><td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:13px;color:${color};background:${bg}">${l.replace(/</g,'&lt;')}</td></tr>`;
  }).join('');
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;background:#f9fafb;padding:24px">
<div style="max-width:560px;margin:0 auto;background:#fff;border-radius:8px;border:1px solid #e5e7eb;overflow:hidden">
  <div style="background:#1d4ed8;padding:16px 20px">
    <span style="color:#fff;font-size:16px;font-weight:700">🛡️ NCSA Blacklist</span>
  </div>
  <div style="padding:16px 20px">
    <p style="margin:0 0 12px;color:#374151;font-size:14px">${subject}</p>
    <table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:6px;overflow:hidden">${rows}</table>
    <p style="margin:16px 0 0;font-size:11px;color:#9ca3af">ส่งโดย NCSA Blacklist · <a href="https://github.com/thering999/ncsa-blacklist" style="color:#6b7280">GitHub</a></p>
  </div>
</div></body></html>`;
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
  const textLines = text.split('\n').filter(Boolean).slice(1); // skip header line
  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: process.env.SMTP_TO,
      subject,
      text,
      html: buildHtml(subject, textLines),
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

async function notifyStale(staleFeeds) {
  if (!staleFeeds.length) return;
  const lines = staleFeeds.map(f =>
    f.age_hours != null
      ? `STALE [${f.type}]: last updated ${f.age_hours}h ago`
      : `MISSING [${f.type}]: data file not found`
  );
  const text = `NCSA blocklist stale alert\n${lines.join('\n')}`;
  const webhookUrl = process.env.WEBHOOK_URL;
  if (webhookUrl) await notifyWebhook(webhookUrl, JSON.stringify({ text }), { 'Content-Type': 'application/json' });
  if (process.env.LINE_NOTIFY_TOKEN) await notifyLine(text);
  if (process.env.SMTP_HOST && process.env.SMTP_TO) await notifyEmail('[NCSA] Feed stale alert', text);
}

module.exports = { notify, notifyStale };
