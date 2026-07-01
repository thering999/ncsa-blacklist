const crypto = require('crypto');
const alertRules = require('./alert_rules');

async function notifyWebhook(url, body, headers) {
  const secret = process.env.WEBHOOK_SECRET;
  if (secret) headers['X-Signature'] = 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, { method: 'POST', headers, body, signal: AbortSignal.timeout(10_000) });
      if (res.ok) return;
      throw new Error(`HTTP ${res.status}`);
    } catch (err) {
      if (attempt === 3) { console.error('webhook notify failed after 3 attempts:', err.message); return; }
      await new Promise((r) => setTimeout(r, 2 ** attempt * 1000));
    }
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

function matchRule(condition, result) {
  const { field, operator, value } = condition;
  let actual;
  if (field === 'type') actual = result.type;
  else if (field === 'added_count') actual = result.added ?? 0;
  else if (field === 'removed_count') actual = result.removed ?? 0;
  else if (field === 'total_count') actual = result.total ?? 0;
  else if (field === 'watch_hit_count') actual = result.watchHits?.length ?? 0;
  else return false;
  if (operator === 'eq') return String(actual) === String(value);
  if (operator === 'gt') return Number(actual) > Number(value);
  if (operator === 'lt') return Number(actual) < Number(value);
  if (operator === 'gte') return Number(actual) >= Number(value);
  if (operator === 'lte') return Number(actual) <= Number(value);
  if (operator === 'contains') return String(actual).includes(String(value));
  return false;
}

function ruleOnCooldown(rule) {
  if (!rule.last_fired) return false;
  const cooldownMs = (rule.cooldown_minutes ?? 60) * 60_000;
  return Date.now() - new Date(rule.last_fired).getTime() < cooldownMs;
}

async function evaluateRules(results) {
  const rules = alertRules.load();
  for (const rule of rules) {
    if (!rule.enabled || ruleOnCooldown(rule)) continue;
    for (const result of results) {
      if (result.error) continue;
      if (matchRule(rule.condition, result)) {
        const text = `[ALERT RULE] ${rule.name}\n${result.type}: +${result.added ?? 0} -${result.removed ?? 0} (total ${result.total ?? '?'})`;
        if (process.env.LINE_NOTIFY_TOKEN) await notifyLine(text);
        if (process.env.SMTP_HOST && process.env.SMTP_TO) await notifyEmail(`[NCSA] Alert: ${rule.name}`, text);
        if (process.env.WEBHOOK_URL) await notifyWebhook(process.env.WEBHOOK_URL, JSON.stringify({ text }), { 'Content-Type': 'application/json' });
        alertRules.update(rule.id, { last_fired: new Date().toISOString() });
        break;
      }
    }
  }
}

async function notify(results) {
  const errorLines = results.filter(r => r.error).map(r => `ERROR [${r.type}]: ${r.error}`);
  const lines = results.filter(r => !r.error && (r.added > 0 || r.removed > 0))
    .map(r => `${r.type}: +${r.added} -${r.removed} (total ${r.total})`);
  const watchLines = results.filter(r => r.watchHits?.length > 0)
    .map(r => `WATCH HIT [${r.type}]: ${r.watchHits.join(', ')}`);
  const watchRemovalLines = results.filter(r => r.watchRemovals?.length > 0)
    .map(r => `WATCH REMOVED [${r.type}]: ${r.watchRemovals.join(', ')}`);

  if (errorLines.length === 0 && lines.length === 0 && watchLines.length === 0 && watchRemovalLines.length === 0) return;
  const text = `NCSA blocklist sync\n${[...errorLines, ...lines, ...watchLines, ...watchRemovalLines].join('\n')}`;

  const webhookUrl = process.env.WEBHOOK_URL;
  if (webhookUrl) {
    const body = JSON.stringify({ text });
    await notifyWebhook(webhookUrl, body, { 'Content-Type': 'application/json' });
  }

  if (process.env.LINE_NOTIFY_TOKEN) await notifyLine(text);

  if (process.env.SMTP_HOST && process.env.SMTP_TO) {
    const hasWatch = watchLines.length > 0 || watchRemovalLines.length > 0;
    await notifyEmail(
      hasWatch ? `[NCSA] Watch alert` : `[NCSA] Blocklist sync update`,
      text
    );
  }
  await evaluateRules(results);
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

async function notifySummary(totals) {
  const entries = Object.entries(totals);
  if (!entries.length) return;
  const lines = entries.map(([type, s]) =>
    `${type}: ${s.syncs} syncs, +${s.added} added, -${s.removed} removed, total ${s.latest_total}`
  );
  const text = `NCSA blocklist weekly summary\n${lines.join('\n')}`;
  const webhookUrl = process.env.WEBHOOK_URL;
  if (webhookUrl) await notifyWebhook(webhookUrl, JSON.stringify({ text }), { 'Content-Type': 'application/json' });
  if (process.env.LINE_NOTIFY_TOKEN) await notifyLine(text);
  if (process.env.SMTP_HOST && process.env.SMTP_TO) await notifyEmail('[NCSA] Weekly summary', text);
}

module.exports = { notify, notifyStale, notifySummary, notifyEmail, evaluateRules };
