import { parseDid } from './did.js';
import { FetchError, InvalidDidError, NotFoundError } from './errors.js';
import { selectVerificationKeys } from './jwk.js';

const DID_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/jws-2020/v1',
];
const CIMD_SERVICE_TYPE =
  'https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#name-client-id-metadata-document';
const DID_DOCUMENT_MEDIA_TYPE = 'application/did+ld+json';
const HTTPS_DEFAULT_PORT = 443;
const MAX_QUOTED_LENGTH = 200;

/** Error types and titles as the Universal Resolver defines them. */
const ERRORS = {
  INVALID_DID: 'Invalid DID.',
  NOT_FOUND: 'The DID or DID document was not found.',
};

/**
 * @typedef {object} ResolutionResult
 * @property {object|null} didDocument
 * @property {Record<string, unknown>} didResolutionMetadata
 * @property {Record<string, unknown>} didDocumentMetadata
 */

/**
 * Creates the did:cimd Read operation (spec 3.2).
 *
 * @param {object} dependencies
 * @param {(target: import('./fetcher.js').FetchTarget) => Promise<import('./fetcher.js').FetchResponse>} dependencies.fetchJson
 * @returns {(did: string) => Promise<ResolutionResult>}
 */
export function createResolver({ fetchJson }) {
  return async function resolve(did) {
    try {
      const parsed = parseDid(did);
      const metadata = await fetchMetadataDocument(parsed, fetchJson);
      if (metadata === null) {
        return { didDocument: null, didResolutionMetadata: {}, didDocumentMetadata: { deactivated: true } };
      }
      const keys = await readVerificationKeys(parsed, metadata, fetchJson);
      return {
        didDocument: buildDidDocument(parsed, keys),
        didResolutionMetadata: { contentType: DID_DOCUMENT_MEDIA_TYPE },
        didDocumentMetadata: {},
      };
    } catch (error) {
      if (error instanceof InvalidDidError) {
        return errorResult('INVALID_DID', error.message);
      }
      if (error instanceof NotFoundError || error instanceof FetchError) {
        return errorResult('NOT_FOUND', error.message);
      }
      throw error;
    }
  };
}

/** Renders a value taken from a remote document for an error detail, bounded in length. */
function quote(value) {
  const text = JSON.stringify(value) ?? String(value);
  return text.length > MAX_QUOTED_LENGTH ? `${text.slice(0, MAX_QUOTED_LENGTH)}...` : text;
}

function errorResult(type, detail) {
  return {
    didDocument: null,
    didResolutionMetadata: { error: { type, title: ERRORS[type], detail } },
    didDocumentMetadata: {},
  };
}

/**
 * Spec 3.2 step 2 and the document checks of 3.1.
 *
 * @returns {Promise<Record<string, unknown>|null>} null when the DID is deactivated
 */
async function fetchMetadataDocument({ host, port, path, baseUrl }, fetchJson) {
  const response = await fetchJson({ host, port, path });
  if (response.status === 410) {
    return null;
  }
  if (response.status >= 300 && response.status < 400) {
    throw new NotFoundError(
      `${baseUrl} answered ${response.status}; redirects are not followed`
    );
  }
  if (response.status !== 200) {
    throw new NotFoundError(`${baseUrl} answered ${response.status}`);
  }
  const metadata = response.json;
  if (!isObject(metadata)) {
    throw new NotFoundError(`${baseUrl} did not return a JSON object`);
  }
  if (metadata.client_id !== baseUrl) {
    throw new NotFoundError(
      `client_id ${quote(metadata.client_id)} does not equal the document URL ${baseUrl}`
    );
  }
  return metadata;
}

/** Spec 3.2 steps 3 and 4. */
async function readVerificationKeys(parsed, metadata, fetchJson) {
  const hasJwks = Object.hasOwn(metadata, 'jwks');
  const hasJwksUri = Object.hasOwn(metadata, 'jwks_uri');
  if (hasJwks && hasJwksUri) {
    throw new NotFoundError('the document carries both jwks and jwks_uri; exactly one is allowed');
  }
  if (!hasJwks && !hasJwksUri) {
    throw new NotFoundError('the document carries neither jwks nor jwks_uri, so it declares no key');
  }
  const jwkSet = hasJwks ? metadata.jwks : await fetchJwkSet(parsed, metadata.jwks_uri, fetchJson);
  if (!isObject(jwkSet) || !Array.isArray(jwkSet.keys)) {
    throw new NotFoundError('the JWK Set is not an object with a "keys" array');
  }
  const keys = selectVerificationKeys(jwkSet.keys);
  if (keys.length === 0) {
    throw new NotFoundError('the JWK Set contains no key usable for verifying signatures');
  }
  return keys;
}

async function fetchJwkSet({ host, port }, jwksUri, fetchJson) {
  const target = sameOriginTarget(host, port, jwksUri);
  const response = await fetchJson(target);
  if (response.status !== 200) {
    throw new NotFoundError(`jwks_uri ${quote(jwksUri)} answered ${response.status}`);
  }
  return response.json;
}

/**
 * Spec 3.1 item 3: jwks_uri must be on the HTTPS origin of the base URL.
 * Origins are compared as RFC 6454 defines them, so an explicit 443 and an
 * absent port name the same origin.
 */
function sameOriginTarget(host, port, jwksUri) {
  let url;
  try {
    url = new URL(typeof jwksUri === 'string' ? jwksUri : '');
  } catch {
    throw new NotFoundError(`jwks_uri ${quote(jwksUri)} is not an absolute URL`);
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '') {
    throw new NotFoundError(`jwks_uri ${quote(jwksUri)} is not a plain https URL`);
  }
  const jwksPort = url.port === '' ? HTTPS_DEFAULT_PORT : Number(url.port);
  if (url.hostname !== host || jwksPort !== (port ?? HTTPS_DEFAULT_PORT)) {
    throw new NotFoundError(`jwks_uri ${quote(jwksUri)} is not on the origin of the metadata document`);
  }
  return { host, port: url.port === '' ? null : jwksPort, path: `${url.pathname}${url.search}` };
}

/** Spec 3.2 steps 5 and 6. */
function buildDidDocument({ did, baseUrl }, keys) {
  const verificationMethod = keys.map(({ jwk, thumbprint }) => ({
    id: `${did}#${thumbprint}`,
    type: 'JsonWebKey2020',
    controller: did,
    publicKeyJwk: jwk,
  }));
  return {
    '@context': DID_CONTEXT,
    id: did,
    alsoKnownAs: [baseUrl],
    verificationMethod,
    authentication: verificationMethod.map(({ id }) => id),
    service: [{ id: `${did}#cimd`, type: CIMD_SERVICE_TYPE, serviceEndpoint: baseUrl }],
  };
}

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
