import assert from 'node:assert/strict';
import { test } from 'node:test';
import { FetchError } from '../src/errors.js';
import { computeThumbprint } from '../src/jwk.js';
import { createResolver } from '../src/resolver.js';

const DID = 'did:cimd:example.com:agents:billing';
const BASE_URL = 'https://example.com/agents/billing';
const JWKS_URI = 'https://example.com/agents/billing/jwks.json';
const SERVICE_TYPE =
  'https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#name-client-id-metadata-document';
const KEY = { kty: 'EC', crv: 'P-256', kid: 'key-1', use: 'sig', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0' };
const OTHER_KEY = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };

/**
 * Stands in for the network. Keys are "host[:port]path"; a value is a response
 * or an Error to throw. Every request is recorded.
 */
function network(responses) {
  const requests = [];
  const fetchJson = async ({ host, port, path }) => {
    const key = `${host}${port === null ? '' : `:${port}`}${path}`;
    requests.push(key);
    const response = responses[key];
    if (response === undefined) {
      return { status: 404 };
    }
    if (response instanceof Error) {
      throw response;
    }
    return response;
  };
  return { fetchJson, requests };
}

const ok = (json) => ({ status: 200, json });
const document = (members) => ok({ client_id: BASE_URL, client_name: 'Billing Agent', ...members });

async function resolveWith(responses, did = DID) {
  const { fetchJson, requests } = network(responses);
  const result = await createResolver({ fetchJson })(did);
  return { result, requests };
}

function assertError(result, type) {
  assert.equal(result.didDocument, null);
  assert.equal(result.didResolutionMetadata.error.type, type);
  assert.equal(typeof result.didResolutionMetadata.error.title, 'string');
  assert.equal(typeof result.didResolutionMetadata.error.detail, 'string');
  assert.deepEqual(result.didDocumentMetadata, {});
}

test('resolves the example of the specification (section 6)', async () => {
  const { result, requests } = await resolveWith({
    'example.com/agents/billing': document({ jwks_uri: JWKS_URI, token_endpoint_auth_method: 'private_key_jwt' }),
    'example.com/agents/billing/jwks.json': ok({ keys: [KEY] }),
  });
  const keyId = `${DID}#${computeThumbprint(KEY)}`;
  assert.deepEqual(result, {
    didDocument: {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
      id: DID,
      alsoKnownAs: [BASE_URL],
      verificationMethod: [{ id: keyId, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: KEY }],
      authentication: [keyId],
      service: [{ id: `${DID}#cimd`, type: SERVICE_TYPE, serviceEndpoint: BASE_URL }],
    },
    didResolutionMetadata: { contentType: 'application/did+ld+json' },
    didDocumentMetadata: {},
  });
  assert.deepEqual(requests, ['example.com/agents/billing', 'example.com/agents/billing/jwks.json']);
});

test('resolves keys published inline in jwks without a second fetch', async () => {
  const { result, requests } = await resolveWith({
    'example.com/agents/billing': document({ jwks: { keys: [KEY, OTHER_KEY] } }),
  });
  assert.equal(result.didDocument.verificationMethod.length, 2);
  assert.deepEqual(result.didDocument.authentication, result.didDocument.verificationMethod.map(({ id }) => id));
  assert.deepEqual(requests, ['example.com/agents/billing']);
});

test('assigns no verification relationship other than authentication', async () => {
  const { result } = await resolveWith({ 'example.com/agents/billing': document({ jwks: { keys: [KEY] } }) });
  for (const relationship of ['assertionMethod', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation']) {
    assert.equal(Object.hasOwn(result.didDocument, relationship), false);
  }
});

test('never publishes private key parameters', async () => {
  const { result } = await resolveWith({
    'example.com/agents/billing': document({ jwks: { keys: [{ ...KEY, d: 'private' }] } }),
  });
  assert.deepEqual(result.didDocument.verificationMethod[0].publicKeyJwk, KEY);
});

test('fetches the port the identifier carries, and compares client_id with it', async () => {
  const did = 'did:cimd:example.com%3A8443:agents:billing';
  const url = 'https://example.com:8443/agents/billing';
  const { result, requests } = await resolveWith(
    { 'example.com:8443/agents/billing': ok({ client_id: url, jwks: { keys: [KEY] } }) },
    did
  );
  assert.equal(result.didDocument.id, did);
  assert.deepEqual(result.didDocument.alsoKnownAs, [url]);
  assert.deepEqual(requests, ['example.com:8443/agents/billing']);
});

test('treats an explicit port 443 as a different client from no port', async () => {
  const { result } = await resolveWith(
    { 'example.com:443/c': ok({ client_id: 'https://example.com/c', jwks: { keys: [KEY] } }) },
    'did:cimd:example.com%3A443:c'
  );
  assertError(result, 'NOT_FOUND');
});

test('passes percent-encoded path segments through unchanged', async () => {
  const { result, requests } = await resolveWith(
    { 'example.com/a%3Ab': ok({ client_id: 'https://example.com/a%3Ab', jwks: { keys: [KEY] } }) },
    'did:cimd:example.com:a%3Ab'
  );
  assert.equal(result.didDocument.service[0].serviceEndpoint, 'https://example.com/a%3Ab');
  assert.deepEqual(requests, ['example.com/a%3Ab']);
});

test('reports invalidDid without touching the network', async () => {
  const { result, requests } = await resolveWith({}, 'did:cimd:Example.com:a');
  assertError(result, 'INVALID_DID');
  assert.deepEqual(requests, []);
});

test('reports a deactivated DID for 410 as a success with a null document', async () => {
  const { result } = await resolveWith({ 'example.com/agents/billing': { status: 410 } });
  assert.deepEqual(result, {
    didDocument: null,
    didResolutionMetadata: {},
    didDocumentMetadata: { deactivated: true },
  });
});

for (const status of [301, 302, 307, 308, 404, 401, 403, 500, 204]) {
  test(`reports notFound when the document URL answers ${status}`, async () => {
    const { result, requests } = await resolveWith({ 'example.com/agents/billing': { status } });
    assertError(result, 'NOT_FOUND');
    assert.deepEqual(requests, ['example.com/agents/billing']);
  });
}

test('reports notFound when the fetch fails or is refused', async () => {
  const { result } = await resolveWith({
    'example.com/agents/billing': new FetchError('example.com does not resolve to a public address'),
  });
  assertError(result, 'NOT_FOUND');
  assert.match(result.didResolutionMetadata.error.detail, /does not resolve to a public address/);
});

test('bounds how much of a remote value an error detail repeats', async () => {
  const { result } = await resolveWith({
    'example.com/agents/billing': ok({ client_id: 'x'.repeat(100000), jwks: { keys: [KEY] } }),
  });
  assertError(result, 'NOT_FOUND');
  assert.ok(result.didResolutionMetadata.error.detail.length < 400);
});

const PROFILE_VIOLATIONS = [
  ['the body is not an object', ok(['not', 'an', 'object'])],
  ['client_id is missing', ok({ jwks: { keys: [KEY] } })],
  ['client_id differs from the URL', ok({ client_id: `${BASE_URL}/`, jwks: { keys: [KEY] } })],
  ['client_id differs only in case', ok({ client_id: 'https://EXAMPLE.com/agents/billing', jwks: { keys: [KEY] } })],
  ['both jwks and jwks_uri are present', document({ jwks: { keys: [KEY] }, jwks_uri: JWKS_URI })],
  ['jwks_uri is present next to a null jwks', document({ jwks: null, jwks_uri: JWKS_URI })],
  ['neither jwks nor jwks_uri is present', document({})],
  ['jwks is not a JWK Set', document({ jwks: [KEY] })],
  ['jwks has no keys array', document({ jwks: { keys: KEY } })],
  ['jwks is empty', document({ jwks: { keys: [] } })],
  ['every key is for encryption', document({ jwks: { keys: [{ ...KEY, use: 'enc' }] } })],
  ['jwks_uri is on another host', document({ jwks_uri: 'https://keys.example.com/jwks.json' })],
  ['jwks_uri is on a parent domain', document({ jwks_uri: 'https://com/jwks.json' })],
  ['jwks_uri is on another port', document({ jwks_uri: 'https://example.com:8443/jwks.json' })],
  ['jwks_uri is not https', document({ jwks_uri: 'http://example.com/agents/billing/jwks.json' })],
  ['jwks_uri carries credentials', document({ jwks_uri: 'https://user:pw@example.com/jwks.json' })],
  ['jwks_uri is relative', document({ jwks_uri: '/agents/billing/jwks.json' })],
  ['jwks_uri is not a string', document({ jwks_uri: [JWKS_URI] })],
];

for (const [name, response] of PROFILE_VIOLATIONS) {
  test(`reports notFound when ${name}`, async () => {
    const { result, requests } = await resolveWith({
      'example.com/agents/billing': response,
      'example.com/agents/billing/jwks.json': ok({ keys: [KEY] }),
    });
    assertError(result, 'NOT_FOUND');
    assert.deepEqual(requests, ['example.com/agents/billing']);
  });
}

test('accepts a jwks_uri that names the default port explicitly', async () => {
  const { result, requests } = await resolveWith({
    'example.com/agents/billing': document({ jwks_uri: 'https://example.com:443/keys?set=1' }),
    'example.com/keys?set=1': ok({ keys: [KEY] }),
  });
  assert.equal(result.didDocument.verificationMethod.length, 1);
  assert.equal(requests[1], 'example.com/keys?set=1');
});

test('fetches jwks_uri on the port of the document', async () => {
  const url = 'https://example.com:8443/c';
  const { result, requests } = await resolveWith(
    {
      'example.com:8443/c': ok({ client_id: url, jwks_uri: 'https://example.com:8443/jwks' }),
      'example.com:8443/jwks': ok({ keys: [KEY] }),
    },
    'did:cimd:example.com%3A8443:c'
  );
  assert.equal(result.didDocument.verificationMethod.length, 1);
  assert.deepEqual(requests, ['example.com:8443/c', 'example.com:8443/jwks']);
});

for (const [name, response] of [
  ['answers 404', { status: 404 }],
  ['redirects', { status: 302 }],
  ['is gone', { status: 410 }],
  ['is not a JWK Set', ok({ notKeys: [] })],
  ['cannot be fetched', new FetchError('no complete response within 8000 ms')],
]) {
  test(`reports notFound when jwks_uri ${name}`, async () => {
    const { result } = await resolveWith({
      'example.com/agents/billing': document({ jwks_uri: JWKS_URI }),
      'example.com/agents/billing/jwks.json': response,
    });
    assertError(result, 'NOT_FOUND');
  });
}

test('lets an unexpected failure propagate instead of calling it notFound', async () => {
  await assert.rejects(resolveWith({ 'example.com/agents/billing': new TypeError('bug') }), TypeError);
});
