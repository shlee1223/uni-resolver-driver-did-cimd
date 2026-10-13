import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer, negotiate } from '../src/server.js';

const DID = 'did:cimd:example.com:agents:billing';
const DOCUMENT = { '@context': ['https://www.w3.org/ns/did/v1'], id: DID };
const SUCCESS = {
  didDocument: DOCUMENT,
  didResolutionMetadata: { contentType: 'application/did+ld+json' },
  didDocumentMetadata: {},
};
const error = (type) => ({
  didDocument: null,
  didResolutionMetadata: { error: { type, title: 'title', detail: 'detail' } },
  didDocumentMetadata: {},
});
const DEACTIVATED = { didDocument: null, didResolutionMetadata: {}, didDocumentMetadata: { deactivated: true } };

const RESULTS = {
  [DID]: SUCCESS,
  'did:cimd:example.com:gone': DEACTIVATED,
  'did:cimd:example.com:missing': error('NOT_FOUND'),
  'did:cimd:Example.com:a': error('INVALID_DID'),
};

const resolved = [];
const logged = [];
const server = createServer({
  log: (line) => logged.push(line),
  resolve: async (did) => {
    resolved.push(did);
    if (did === 'did:cimd:example.com:crash') {
      throw new Error('boom');
    }
    return RESULTS[did] ?? SUCCESS;
  },
});

let base;
before(async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => {
  server.closeAllConnections();
  server.close();
});

async function get(identifier, accept) {
  const response = await fetch(`${base}/1.0/identifiers/${identifier}`, {
    headers: accept === undefined ? {} : { accept },
  });
  return { status: response.status, type: response.headers.get('content-type'), body: await response.json() };
}

test('answers the Universal Resolver with a DID resolution result', async () => {
  const { status, type, body } = await get(DID, 'application/did-resolution,application/ld+json');
  assert.equal(status, 200);
  assert.equal(type, 'application/did-resolution');
  assert.deepEqual(body, SUCCESS);
  assert.deepEqual(Object.keys(body), ['didResolutionMetadata', 'didDocument', 'didDocumentMetadata']);
});

test('answers with the DID document alone when only a document type is accepted', async () => {
  const { status, type, body } = await get(DID, 'application/did+ld+json');
  assert.equal(status, 200);
  assert.equal(type, 'application/did+ld+json');
  assert.deepEqual(body, DOCUMENT);
});

test('maps resolution outcomes to the status codes of the HTTP binding', async () => {
  assert.equal((await get('did:cimd:Example.com:a', 'application/did-resolution')).status, 400);
  assert.equal((await get('did:cimd:example.com:missing', 'application/did-resolution')).status, 404);
  assert.equal((await get('did:cimd:example.com:gone', 'application/did-resolution')).status, 410);
});

test('returns the resolution result for an error even when a document was asked for', async () => {
  const { status, type, body } = await get('did:cimd:example.com:missing', 'application/did+ld+json');
  assert.equal(status, 404);
  assert.equal(type, 'application/did-resolution');
  assert.equal(body.didResolutionMetadata.error.type, 'NOT_FOUND');
});

test('returns the deactivation result even when a document was asked for', async () => {
  const { status, body } = await get('did:cimd:example.com:gone');
  assert.equal(status, 410);
  assert.deepEqual(body, DEACTIVATED);
});

test('answers 406 when no acceptable representation exists', async () => {
  const { status, body } = await get(DID, 'text/html, application/did+cbor');
  assert.equal(status, 406);
  assert.equal(body.didResolutionMetadata.error.type, 'REPRESENTATION_NOT_SUPPORTED');
});

test('answers 500 without leaking details when resolution throws', async () => {
  const { status, body } = await get('did:cimd:example.com:crash', 'application/did-resolution');
  assert.equal(status, 500);
  assert.equal(body.didResolutionMetadata.error.type, 'INTERNAL_ERROR');
  assert.doesNotMatch(JSON.stringify(body), /boom/);
  assert.ok(logged.some((line) => line.includes('boom')));
});

test('hands the identifier to the resolver exactly as received', async () => {
  resolved.length = 0;
  await get('did:cimd:example.com%3A8443:a%3Ab:c%2Fd');
  assert.deepEqual(resolved, ['did:cimd:example.com%3A8443:a%3Ab:c%2Fd']);
});

test('decodes once an identifier that arrives entirely percent-encoded', async () => {
  resolved.length = 0;
  await get('did%3Acimd%3Aexample.com%253A8443%3Aa');
  assert.deepEqual(resolved, ['did:cimd:example.com%3A8443:a']);
});

test('logs the reason when a resolution fails, and none when it succeeds', async () => {
  logged.length = 0;
  await get('did:cimd:example.com:missing', 'application/did-resolution');
  await get(DID, 'application/did-resolution');
  assert.match(logged[0], /^"did:cimd:example\.com:missing" -> 404 in \d+ ms: "detail"$/);
  assert.match(logged[1], /^"did:cimd:example\.com:agents:billing" -> 200 in \d+ ms$/);
});

test('logs a decoded identifier on one line', async () => {
  logged.length = 0;
  await get('did%3Acimd%3Aexample.com%3Aa%0Ainjected');
  assert.equal(logged.length, 1);
  assert.doesNotMatch(logged[0], /\n/);
});

test('ignores a query string', async () => {
  resolved.length = 0;
  await get(`${DID}?versionTime=2026-01-01T00:00:00Z`);
  assert.deepEqual(resolved, [DID]);
});

test('rejects methods other than GET', async () => {
  const response = await fetch(`${base}/1.0/identifiers/${DID}`, { method: 'POST' });
  assert.equal(response.status, 405);
  assert.equal(response.headers.get('allow'), 'GET');
});

test('answers 404 outside the identifiers path', async () => {
  assert.equal((await fetch(`${base}/`)).status, 404);
  assert.equal((await fetch(`${base}/1.0/properties`)).status, 404);
});

const NEGOTIATION = [
  [undefined, { documentOnly: true, mediaType: 'application/did+ld+json' }],
  ['', { documentOnly: true, mediaType: 'application/did+ld+json' }],
  ['*/*', { documentOnly: true, mediaType: 'application/did+ld+json' }],
  ['application/json', { documentOnly: true, mediaType: 'application/did+ld+json' }],
  ['application/ld+json', { documentOnly: true, mediaType: 'application/did+ld+json' }],
  ['application/did+json', { documentOnly: true, mediaType: 'application/did+json' }],
  ['application/did', { documentOnly: true, mediaType: 'application/did' }],
  ['Application/DID-Resolution', { documentOnly: false, mediaType: 'application/did-resolution' }],
  ['application/did-resolution,application/ld+json', { documentOnly: false, mediaType: 'application/did-resolution' }],
  ['application/did+ld+json;q=0.5, application/did-resolution;q=0.9', { documentOnly: false, mediaType: 'application/did-resolution' }],
  ['application/did-resolution;q=0, application/did+json', { documentOnly: true, mediaType: 'application/did+json' }],
  ['text/html, */*;q=0.1', { documentOnly: true, mediaType: 'application/did+ld+json' }],
  [
    'application/ld+json;profile="https://w3id.org/did-resolution"',
    { documentOnly: false, mediaType: 'application/ld+json;profile="https://w3id.org/did-resolution"' },
  ],
  ['text/html', null],
  ['application/did+cbor', null],
  ['*/*;q=0', null],
];

for (const [accept, expected] of NEGOTIATION) {
  test(`negotiates ${JSON.stringify(accept)}`, () => {
    assert.deepEqual(negotiate(accept), expected);
  });
}
