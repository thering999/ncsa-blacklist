const fs = require('fs');
const path = require('path');
const { DATA_DIR } = require('./paths');

const FILE = path.join(DATA_DIR, 'allowlist.json');

function load() {
  if (!fs.existsSync(FILE)) return [];
  return JSON.parse(fs.readFileSync(FILE, 'utf8'));
}

function save(list) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(list));
}

function add(type, value) {
  const list = load();
  if (!list.some((e) => e.type === type && e.value === value)) {
    list.push({ type, value });
    save(list);
  }
  return list;
}

function remove(type, value) {
  const list = load().filter((e) => !(e.type === type && e.value === value));
  save(list);
  return list;
}

function check(type, value) {
  return load().some((e) => e.type === type && e.value === value);
}

module.exports = { load, add, remove, check };
