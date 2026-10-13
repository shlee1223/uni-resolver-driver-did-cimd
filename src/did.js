import { InvalidDidError } from './errors.js';

const PREFIX = 'did:cimd:';
const AUTHORITY = /^([A-Za-z0-9.-]+)(?:%3A([0-9]{1,5}))?$/;
const SEGMENT = /^(?:[A-Za-z0-9._-]|%[0-9A-F]{2})+$/;
const LITERAL_SEGMENT_CHAR = /^[A-Za-z0-9._-]$/;
const MAX_HOST_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;
const MAX_PORT = 65535;

/**
 * @typedef {object} ParsedDid
 * @property {string} did       the identifier as given
 * @property {string} host      lowercase DNS name
 * @property {number|null} port explicit port, or null when the identifier carries none
 * @property {string} path      path of the base URL, verbatim from the identifier
 * @property {string} baseUrl   the Client Identifier URL (spec 2.2)
 */

/**
 * Validates a did:cimd identifier against the grammar and canonical form and
 * derives its base URL.
 *
 * @param {string} did
 * @returns {ParsedDid}
 * @throws {InvalidDidError}
 */
export function parseDid(did) {
  if (typeof did !== 'string' || !did.startsWith(PREFIX)) {
    throw new InvalidDidError(`identifier does not start with "${PREFIX}"`);
  }
  const fields = did.slice(PREFIX.length).split(':');
  if (fields.length < 2) {
    throw new InvalidDidError('at least one path segment is required after the authority');
  }
  const [authority, ...segments] = fields;
  const { host, port } = parseAuthority(authority);
  segments.forEach(checkSegment);

  const path = `/${segments.join('/')}`;
  const origin = port === null ? host : `${host}:${port}`;
  return { did, host, port, path, baseUrl: `https://${origin}${path}` };
}

function parseAuthority(authority) {
  const match = AUTHORITY.exec(authority);
  if (!match) {
    throw new InvalidDidError(
      `authority "${authority}" is not a host optionally followed by "%3A" and a port`
    );
  }
  const [, host, portDigits] = match;
  checkHost(host);
  return { host, port: portDigits === undefined ? null : parsePort(portDigits) };
}

function checkHost(host) {
  if (host !== host.toLowerCase()) {
    throw new InvalidDidError(`host "${host}" is not lowercase`);
  }
  if (host.length > MAX_HOST_LENGTH) {
    throw new InvalidDidError('host is longer than a DNS name can be');
  }
  const labels = host.split('.');
  if (labels.some((label) => label.length === 0 || label.length > MAX_LABEL_LENGTH)) {
    throw new InvalidDidError(`host "${host}" is not a DNS name`);
  }
  if (/^(?:[0-9]+|0x[0-9a-f]*)$/.test(labels.at(-1))) {
    throw new InvalidDidError(`host "${host}" is an IP literal, not a DNS name`);
  }
}

function parsePort(digits) {
  if (digits.length > 1 && digits.startsWith('0')) {
    throw new InvalidDidError(`port "${digits}" is zero-padded`);
  }
  const port = Number(digits);
  if (port > MAX_PORT) {
    throw new InvalidDidError(`port ${digits} is out of range`);
  }
  return port;
}

function checkSegment(segment) {
  if (!SEGMENT.test(segment)) {
    throw new InvalidDidError(
      `path segment "${segment}" is empty or contains a character or escape the grammar does not admit`
    );
  }
  if (segment === '.' || segment === '..') {
    throw new InvalidDidError('dot path segments are not allowed');
  }
  for (const [escape, hex] of segment.matchAll(/%([0-9A-F]{2})/g)) {
    const character = String.fromCharCode(Number.parseInt(hex, 16));
    if (LITERAL_SEGMENT_CHAR.test(character)) {
      throw new InvalidDidError(
        `"${escape}" encodes "${character}", which must be written literally`
      );
    }
  }
}
