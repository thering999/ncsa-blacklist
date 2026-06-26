const { loadType } = require('./store');

const d = loadType('domain');
if (!d) {
  console.error('no domain data — run "npm run fetch" first');
  process.exit(1);
}

console.log('# generated from NCSA domain blocklist —', d.meta.generated_at);
for (const domain of d.set) {
  console.log(`address=/${domain}/0.0.0.0`);
}
