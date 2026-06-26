const cron = require('node-cron');
const { fetchAll } = require('./fetch');

cron.schedule('0 1 * * *', () => {
  console.log('running daily NCSA feed sync...');
  fetchAll();
});

console.log('scheduler started — daily sync at 01:00');
