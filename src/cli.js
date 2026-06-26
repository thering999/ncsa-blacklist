#!/usr/bin/env node
const { loadType } = require('./store');

const [type, value] = process.argv.slice(2);
if (!type || !value) {
  console.error('usage: npm run lookup -- <ip|domain|hash> <value>');
  process.exit(1);
}

const d = loadType(type);
if (!d) {
  console.error(`no data for type "${type}" — run "npm run fetch" first`);
  process.exit(1);
}

console.log(d.set.has(value) ? 'BLACKLISTED' : 'clean');
