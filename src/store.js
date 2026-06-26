const fs = require('fs');
const path = require('path');
const { DATA_DIR, FEEDS } = require('./fetch');

function loadType(type) {
  const file = path.join(DATA_DIR, `${type}.json`);
  if (!fs.existsSync(file)) return null;
  const json = JSON.parse(fs.readFileSync(file, 'utf8'));
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
