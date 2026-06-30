const fs = require('fs');
const path = require('path');
const { DATA_DIR } = require('./paths');

const FILE = path.join(DATA_DIR, 'alert_rules.json');
const MAX_RULES = 20;

let _cache = null;

function load() {
  if (_cache) return _cache;
  if (!fs.existsSync(FILE)) return (_cache = []);
  try { _cache = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { _cache = []; }
  return _cache;
}

function save(list) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(list));
  _cache = list;
}

function create(rule) {
  const list = load();
  if (list.length >= MAX_RULES) throw new Error(`max ${MAX_RULES} rules`);
  const entry = { id: Date.now().toString(), enabled: true, created_at: new Date().toISOString(), ...rule };
  list.push(entry);
  save(list);
  return entry;
}

function update(id, patch) {
  const list = load();
  const idx = list.findIndex(r => r.id === id);
  if (idx < 0) return null;
  list[idx] = { ...list[idx], ...patch, id };
  save(list);
  return list[idx];
}

function remove(id) {
  const list = load().filter(r => r.id !== id);
  save(list);
  return list;
}

module.exports = { load, create, update, remove };
