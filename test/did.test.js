import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseDid } from '../src/did.js';
import { InvalidDidError } from '../src/errors.js';

const VALID = [
  ['did:cimd:example.com:agents:billing', 'https://example.com/agents/billing', null],
  ['did:cimd:example.com:client.json', 'https://example.com/client.json', null],
  ['did:cimd:example.com%3A8443:agents:billing', 'https://example.com:8443/agents/billing', 8443],
  ['did:cimd:example.com:a%3Ab', 'https://example.com/a%3Ab', null],
  ['did:cimd:example.com%3A443:c', 'https://example.com:443/c', 443],
  ['did:cimd:sub.example.co.uk:a_b:c-d:e.f', 'https://sub.example.co.uk/a_b/c-d/e.f', null],
  ['did:cimd:example.com:a%2Fb:%E2%9C%93', 'https://example.com/a%2Fb/%E2%9C%93', null],
  ['did:cimd:xn--bcher-kva.example:c', 'https://xn--bcher-kva.example/c', null],
  ['did:cimd:example.com:...', 'https://example.com/...', null],
  ['did:cimd:example.com:8443:a', 'https://example.com/8443/a', null],
];

for (const [did, baseUrl, port] of VALID) {
  test(`derives ${baseUrl} from ${did}`, () => {
    const parsed = parseDid(did);
    assert.equal(parsed.baseUrl, baseUrl);
    assert.equal(parsed.port, port);
    assert.equal(parsed.did, did);
  });
}

test('exposes the fetch target of an identifier with a port', () => {
  const parsed = parseDid('did:cimd:example.com%3A8443:agents:billing');
  assert.equal(parsed.host, 'example.com');
  assert.equal(parsed.path, '/agents/billing');
});

const INVALID = [
  ['another method', 'did:web:example.com:a'],
  ['uppercase scheme', 'DID:cimd:example.com:a'],
  ['no path segment', 'did:cimd:example.com'],
  ['empty authority', 'did:cimd::a'],
  ['empty segment in the middle', 'did:cimd:example.com::a'],
  ['trailing colon', 'did:cimd:example.com:a:'],
  ['uppercase host', 'did:cimd:Example.com:a'],
  ['IPv4 literal host', 'did:cimd:192.168.0.1:a'],
  ['hexadecimal IPv4 literal host', 'did:cimd:example.0x7f:a'],
  ['host with an empty label', 'did:cimd:example..com:a'],
  ['host with a trailing dot', 'did:cimd:example.com.:a'],
  ['host label over 63 characters', `did:cimd:${'a'.repeat(64)}.com:a`],
  ['percent-encoded host', 'did:cimd:ex%61mple.com:a'],
  ['lowercase port escape', 'did:cimd:example.com%3a8443:a'],
  ['zero-padded port', 'did:cimd:example.com%3A0443:a'],
  ['port out of range', 'did:cimd:example.com%3A65536:a'],
  ['six-digit port', 'did:cimd:example.com%3A100000:a'],
  ['port escape without digits', 'did:cimd:example.com%3A:a'],
  ['single-dot segment', 'did:cimd:example.com:.:a'],
  ['double-dot segment', 'did:cimd:example.com:a:..'],
  ['lowercase hex in an escape', 'did:cimd:example.com:a%3ab'],
  ['escape of a character that must be literal', 'did:cimd:example.com:%41bc'],
  ['escaped dot segment', 'did:cimd:example.com:%2E%2E'],
  ['truncated escape', 'did:cimd:example.com:a%3'],
  ['slash in a segment', 'did:cimd:example.com:a/b'],
  ['fragment', 'did:cimd:example.com:a#key'],
  ['query', 'did:cimd:example.com:a?x=1'],
  ['tilde in a segment', 'did:cimd:example.com:~a'],
  ['space in a segment', 'did:cimd:example.com:a b'],
];

for (const [name, did] of INVALID) {
  test(`rejects ${name}: ${did}`, () => {
    assert.throws(() => parseDid(did), InvalidDidError);
  });
}

test('rejects a value that is not a string', () => {
  assert.throws(() => parseDid(undefined), InvalidDidError);
});
