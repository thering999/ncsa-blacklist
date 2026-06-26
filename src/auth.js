function parseTokens(env) {
  const tokens = {};
  if (env.ADMIN_TOKENS) {
    for (const pair of env.ADMIN_TOKENS.split(',')) {
      const [name, token] = pair.split(':').map((s) => s && s.trim());
      if (name && token) tokens[name] = token;
    }
  }
  if (env.ADMIN_TOKEN) tokens.default = env.ADMIN_TOKEN;
  return tokens;
}

function makeRequireAdmin(tokens) {
  const hasTokens = Object.keys(tokens).length > 0;
  return function requireAdmin(req, res, next) {
    if (!hasTokens) return next();
    const m = /^Bearer (.+)$/.exec(req.get('Authorization') || '');
    if (!m) return res.status(401).json({ error: 'unauthorized' });
    const name = Object.keys(tokens).find((k) => tokens[k] === m[1]);
    if (!name) return res.status(401).json({ error: 'unauthorized' });
    req.adminName = name;
    next();
  };
}

module.exports = { parseTokens, makeRequireAdmin };
