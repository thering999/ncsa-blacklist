const fs = require('fs');
const path = require('path');
const { DATA_DIR } = require('./paths');

const FILE = path.join(DATA_DIR, 'watchlist.json');

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

function add(type, value) {
  const list = load();
  if (!list.some((w) => w.type === type && w.value === value)) {
    list.push({ type, value });
    save(list);
  }
  return list;
}

function remove(type, value) {
  const list = load().filter((w) => !(w.type === type && w.value === value));
  save(list);
  return list;
}

module.exports = { load, add, remove };
