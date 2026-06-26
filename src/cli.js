#!/usr/bin/env node
const { loadAll } = require('./store');
const { lookup: geoLookup } = require('./geoip');
const allowlist = require('./allowlist');

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function autoDetectType(value) {
  if (/^[0-9a-f]{64}$/i.test(value)) return 'hash';
  if (IPV4_RE.test(value)) return 'ip';
  return 'domain';
}

const args = process.argv.slice(2);
if (!args.length) {
  console.error('usage: npm run lookup -- <value> [value2 ...]');
  console.error('       npm run lookup -- <ip|domain|hash> <value>');
  process.exit(1);
}

// Support legacy: npm run lookup -- ip 1.2.3.4
let values;
if (args.length === 2 && ['ip', 'domain', 'hash'].includes(args[0])) {
  values = [{ type: args[0], value: args[1] }];
} else {
  values = args.map(v => ({ type: autoDetectType(v), value: v }));
}

const store = loadAll();

let anyError = false;
for (const { type, value } of values) {
  const d = store[type];
  if (!d) {
    console.error(`[${value}] no data for type "${type}" — run "npm run fetch" first`);
    anyError = true;
    continue;
  }

  if (allowlist.check(type, value)) {
    console.log(`[${value}] type=${type} ALLOWLISTED (not checked against blacklist)`);
    continue;
  }

  const blacklisted = d.set.has(value);
  const status = blacklisted ? 'BLACKLISTED' : 'clean';

  if (type === 'ip') {
    const geo = geoLookup(value);
    const country = geo?.country || '??';
    const org = geo?.org || geo?.as || '';
    console.log(`[${value}] type=ip ${status} country=${country}${org ? ` org="${org}"` : ''}`);
  } else {
    console.log(`[${value}] type=${type} ${status}`);
  }
}

if (anyError) process.exit(1);
