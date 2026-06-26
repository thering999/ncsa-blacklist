const { loadType } = require('./store');

const d = loadType('hash');
if (!d) {
  console.error('no hash data — run "npm run fetch" first');
  process.exit(1);
}

for (const hash of d.set) {
  console.log(`${hash.toLowerCase()}:ncsa-blacklist`);
}
