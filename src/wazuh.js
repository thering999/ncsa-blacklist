const https = require('https');

function queryAlerts({ wazuhIP, wazuhUser, wazuhPass, insecureTLS, hours }) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      size: 10,
      sort: [{ timestamp: { order: 'desc' } }],
      query: { range: { timestamp: { gte: `now-${hours}h` } } },
    });
    const auth = Buffer.from(`${wazuhUser}:${wazuhPass || ''}`).toString('base64');
    const req = https.request({
      hostname: wazuhIP,
      port: 9200,
      path: '/wazuh-alerts-*/_search',
      method: 'POST',
      rejectUnauthorized: !insecureTLS,
      timeout: 5000,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        Authorization: `Basic ${auth}`,
      },
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error(`HTTP ${res.statusCode}`));
        }
        try {
          const parsed = JSON.parse(data);
          const rawHits = (parsed.hits && parsed.hits.hits) || [];
          const hits = rawHits.map((h) => {
            const s = h._source || {};
            return {
              level: (s.rule && s.rule.level) || 0,
              description: (s.rule && s.rule.description) || '',
              timestamp: s.timestamp || null,
              agent: (s.agent && s.agent.name) || '',
            };
          });
          const total = (parsed.hits && (parsed.hits.total?.value ?? parsed.hits.total)) ?? hits.length;
          resolve({ total, hits });
        } catch (e) {
          reject(new Error('invalid response from Wazuh: ' + e.message));
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('Wazuh request timed out')));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

module.exports = { queryAlerts };
