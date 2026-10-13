import assert from 'node:assert/strict';
import { test } from 'node:test';
import { computeThumbprint, selectVerificationKeys } from '../src/jwk.js';

/** RFC 7638, section 3.1. */
const RFC7638_RSA = {
  kty: 'RSA',
  n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
  e: 'AQAB',
  alg: 'RS256',
  kid: '2011-04-29',
};
const RFC7638_THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

/** RFC 8037, appendix A.3. */
const RFC8037_OKP = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };
const RFC8037_THUMBPRINT = 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k';

const EC = { kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0' };

test('computes the RFC 7638 example thumbprint', () => {
  assert.equal(computeThumbprint(RFC7638_RSA), RFC7638_THUMBPRINT);
});

test('computes the RFC 8037 example thumbprint', () => {
  assert.equal(computeThumbprint(RFC8037_OKP), RFC8037_THUMBPRINT);
});

test('ignores members outside the thumbprint input', () => {
  assert.equal(computeThumbprint({ ...EC, kid: 'a', use: 'sig', alg: 'ES256' }), computeThumbprint(EC));
});

test('returns no thumbprint when a required member is missing or not a string', () => {
  assert.equal(computeThumbprint({ kty: 'EC', crv: 'P-256', x: EC.x }), null);
  assert.equal(computeThumbprint({ ...EC, y: 5 }), null);
  assert.equal(computeThumbprint({ ...EC, y: '' }), null);
});

test('returns no thumbprint for an unknown or inherited key type name', () => {
  assert.equal(computeThumbprint({ kty: 'oct', k: 'AAAA' }), null);
  assert.equal(computeThumbprint({ kty: 'constructor' }), null);
  assert.equal(computeThumbprint({ kty: 7 }), null);
});

test('keeps a key that declares neither use nor key_ops, preserving kid', () => {
  const [selected] = selectVerificationKeys([{ ...EC, kid: 'key-1' }]);
  assert.equal(selected.thumbprint, computeThumbprint(EC));
  assert.deepEqual(selected.jwk, { ...EC, kid: 'key-1' });
});

test('removes private parameters and keeps the public key', () => {
  const [selected] = selectVerificationKeys([{ ...EC, d: 'secret' }]);
  assert.equal(Object.hasOwn(selected.jwk, 'd'), false);
  assert.equal(selected.jwk.x, EC.x);

  const [rsa] = selectVerificationKeys([{ ...RFC7638_RSA, d: 's', p: 's', q: 's', dp: 's', dq: 's', qi: 's', oth: [] }]);
  assert.deepEqual(rsa.jwk, RFC7638_RSA);
});

test('discards keys not usable for verifying signatures', () => {
  const kept = selectVerificationKeys([
    { ...EC, use: 'enc' },
    { ...RFC8037_OKP, key_ops: ['sign'] },
    { ...RFC7638_RSA, key_ops: 'verify' },
    { kty: 'oct', k: 'c2VjcmV0' },
    { kty: 'EC', crv: 'P-256', x: EC.x },
    'not a key',
    null,
    [EC],
  ]);
  assert.deepEqual(kept, []);
});

test('keeps keys marked for signature verification', () => {
  const kept = selectVerificationKeys([
    { ...EC, use: 'sig' },
    { ...RFC8037_OKP, key_ops: ['sign', 'verify'] },
  ]);
  assert.deepEqual(kept.map(({ thumbprint }) => thumbprint), [computeThumbprint(EC), RFC8037_THUMBPRINT]);
});

test('returns a key published twice only once', () => {
  const kept = selectVerificationKeys([{ ...EC, kid: 'first' }, { ...EC, kid: 'second' }]);
  assert.equal(kept.length, 1);
  assert.equal(kept[0].jwk.kid, 'first');
});
