const { loadType } = require('./store');

const d = loadType('ip');
if (!d) {
  console.error('no ip data — run "npm run fetch" first');
  process.exit(1);
}

console.log('#!/bin/sh');
console.log('# generated from NCSA ip blocklist —', d.meta.generated_at);
console.log('ipset create ncsa-blacklist hash:ip -exist');
for (const ip of d.set) {
  console.log(`ipset add ncsa-blacklist ${ip} -exist`);
}
console.log('iptables -I INPUT -m set --match-set ncsa-blacklist src -j DROP');
