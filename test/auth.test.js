const { test } = require('node:test');
const assert = require('node:assert');
const { parseTokens, makeRequireAdmin } = require('../src/auth');

function mockReqRes(authHeader) {
  const req = { get: (h) => (h === 'Authorization' ? authHeader : undefined) };
  let status, body;
  const res = { status(s) { status = s; return this; }, json(b) { body = b; return this; } };
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  return { req, res, next, getStatus: () => status, getBody: () => body, wasNext: () => nextCalled };
}

test('parseTokens reads ADMIN_TOKENS as name:token pairs', () => {
  const tokens = parseTokens({ ADMIN_TOKENS: 'alice:tok1,bob:tok2' });
  assert.deepStrictEqual(tokens, { alice: 'tok1', bob: 'tok2' });
});

test('parseTokens falls back to ADMIN_TOKEN as "default"', () => {
  const tokens = parseTokens({ ADMIN_TOKEN: 'legacy' });
  assert.deepStrictEqual(tokens, { default: 'legacy' });
});

test('parseTokens merges both', () => {
  const tokens = parseTokens({ ADMIN_TOKENS: 'alice:tok1', ADMIN_TOKEN: 'legacy' });
  assert.deepStrictEqual(tokens, { alice: 'tok1', default: 'legacy' });
});

test('requireAdmin allows everything when no tokens configured', () => {
  const requireAdmin = makeRequireAdmin({});
  const { req, res, next, wasNext } = mockReqRes(undefined);
  requireAdmin(req, res, next);
  assert.strictEqual(wasNext(), true);
});

test('requireAdmin rejects missing/wrong token', () => {
  const requireAdmin = makeRequireAdmin({ alice: 'tok1' });
  const { req, res, next, getStatus, wasNext } = mockReqRes('Bearer wrong');
  requireAdmin(req, res, next);
  assert.strictEqual(wasNext(), false);
  assert.strictEqual(getStatus(), 401);
});

test('requireAdmin accepts correct token and sets adminName', () => {
  const requireAdmin = makeRequireAdmin({ alice: 'tok1', bob: 'tok2' });
  const { req, res, next, wasNext } = mockReqRes('Bearer tok2');
  requireAdmin(req, res, next);
  assert.strictEqual(wasNext(), true);
  assert.strictEqual(req.adminName, 'bob');
});
