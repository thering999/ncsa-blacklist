const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}/g;

function scanLog(text, ipSet) {
  const found = new Set(text.match(IP_RE) || []);
  const hits = [...found].filter((ip) => ipSet.has(ip));
  return { scanned: found.size, hits };
}

function scanLogWithContext(text, ipSet) {
  const lines = text.split('\n');
  const allIps = new Set();
  const hitLines = [];
  for (let i = 0; i < lines.length; i++) {
    const lineIps = lines[i].match(IP_RE) || [];
    for (const ip of lineIps) allIps.add(ip);
    const lineHits = [...new Set(lineIps)].filter((ip) => ipSet.has(ip));
    if (lineHits.length > 0) {
      hitLines.push({ line: i + 1, text: lines[i].slice(0, 400), ips: lineHits });
    }
  }
  const hits = [...new Set(hitLines.flatMap((l) => l.ips))];
  return { scanned: allIps.size, hits, lines: hitLines };
}

module.exports = { scanLog, scanLogWithContext };
