const fs = require('fs');
const path = require('path');
const { DATA_DIR, FEEDS } = require('./fetch');

function loadType(type) {
  const file = path.join(DATA_DIR, `${type}.json`);
  if (!fs.existsSync(file)) return null;
  let json;
  try { json = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { console.error(`store: failed to parse ${file}: ${e.message}`); return null; }
  return { meta: json, set: new Set(json.data) };
}

function loadAll() {
  const store = {};
  for (const type of Object.keys(FEEDS)) {
    store[type] = loadType(type);
  }
  return store;
}

module.exports = { loadAll, loadType };
