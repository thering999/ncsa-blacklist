const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;

function scanLog(text, ipSet) {
  const found = new Set(text.match(IP_RE) || []);
  const hits = [...found].filter((ip) => ipSet.has(ip));
  return { scanned: found.size, hits };
}

module.exports = { scanLog };
