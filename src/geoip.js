let geo;
try {
  geo = require('geoip-lite');
} catch (_) {
  geo = null;
}

function lookup(ip) {
  if (!geo) return null;
  const r = geo.lookup(ip);
  if (!r) return null;
  return {
    country: r.country || null,
    region: r.region || null,
    city: r.city || null,
    as: r.as || null,
    org: r.org || null,
  };
}

module.exports = { lookup };
