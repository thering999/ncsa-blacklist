const { test } = require('node:test');
const assert = require('node:assert');
const { diffSets } = require('../src/diff');

test('detects added values', () => {
  const { added, removed } = diffSets(['a', 'b'], ['a', 'b', 'c']);
  assert.deepStrictEqual(added, ['c']);
  assert.deepStrictEqual(removed, []);
});

test('detects removed values', () => {
  const { added, removed } = diffSets(['a', 'b', 'c'], ['a', 'b']);
  assert.deepStrictEqual(added, []);
  assert.deepStrictEqual(removed, ['c']);
});

test('handles empty previous set (first run)', () => {
  const { added, removed } = diffSets([], ['a', 'b']);
  assert.deepStrictEqual(added, ['a', 'b']);
  assert.deepStrictEqual(removed, []);
});

test('no change when sets are identical', () => {
  const { added, removed } = diffSets(['a', 'b'], ['a', 'b']);
  assert.deepStrictEqual(added, []);
  assert.deepStrictEqual(removed, []);
});
