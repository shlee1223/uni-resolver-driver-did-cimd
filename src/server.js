import http from 'node:http';

const IDENTIFIERS_PATH = '/1.0/identifiers/';
const RESOLUTION_RESULT = 'application/did-resolution';
const LEGACY_RESOLUTION_PROFILE = 'https://w3id.org/did-resolution';
const DEFAULT_DOCUMENT_TYPE = 'application/did+ld+json';

/** Requested media type -> media type the DID document is served as. */
const DOCUMENT_TYPES = {
  'application/did+ld+json': 'application/did+ld+json',
  'application/ld+json': 'application/did+ld+json',
  'application/did+json': 'application/did+json',
  'application/did': 'application/did',
  'application/json': DEFAULT_DOCUMENT_TYPE,
  'application/*': DEFAULT_DOCUMENT_TYPE,
  '*/*': DEFAULT_DOCUMENT_TYPE,
};

const STATUS_BY_ERROR = {
  INVALID_DID: 400,
  NOT_FOUND: 404,
  REPRESENTATION_NOT_SUPPORTED: 406,
  INTERNAL_ERROR: 500,
};

/**
 * Creates the driver's HTTP interface: GET /1.0/identifiers/<did>, the HTTP(S)
 * binding of DID Resolution that the Universal Resolver calls.
 *
 * @param {object} dependencies
 * @param {(did: string) => Promise<import('./resolver.js').ResolutionResult>} dependencies.resolve
 * @param {(line: string) => void} [dependencies.log]
 * @returns {http.Server}
 */
export function createServer({ resolve, log = () => {} }) {
  return http.createServer(async (request, response) => {
    const started = Date.now();
    const path = request.url.split('?', 1)[0];
    if (!path.startsWith(IDENTIFIERS_PATH)) {
      send(response, 404, 'text/plain', 'Not found. Resolve with GET /1.0/identifiers/<did>\n');
      return;
    }
    if (request.method !== 'GET') {
      response.setHeader('allow', 'GET');
      send(response, 405, 'text/plain', 'Method not allowed\n');
      return;
    }
    const identifier = readIdentifier(path.slice(IDENTIFIERS_PATH.length));
    const result = await resolveSafely(resolve, identifier, log);
    const status = sendResult(response, request.headers.accept, result);
    const failure = result.didResolutionMetadata.error;
    const reason = failure ? `: ${JSON.stringify(failure.detail)}` : '';
    log(`${JSON.stringify(identifier)} -> ${status} in ${Date.now() - started} ms${reason}`);
  });
}

/**
 * The Universal Resolver forwards the identifier as it received it, and decodes
 * it once only when the whole identifier arrived percent-encoded ("did%3A...").
 * The same rule is applied here. Decoding anything else would turn the "%3A" of
 * a port into the ":" that separates path segments.
 */
function readIdentifier(raw) {
  if (!raw.startsWith('did%3A')) {
    return raw;
  }
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

async function resolveSafely(resolve, identifier, log) {
  try {
    return await resolve(identifier);
  } catch (error) {
    log(`internal error resolving ${JSON.stringify(identifier)}: ${error.stack ?? error}`);
    return errorResult('INTERNAL_ERROR', 'An internal error has occurred.', 'The driver failed unexpectedly.');
  }
}

function errorResult(type, title, detail) {
  return {
    didDocument: null,
    didResolutionMetadata: { error: { type, title, detail } },
    didDocumentMetadata: {},
  };
}

function sendResult(response, acceptHeader, result) {
  const representation = negotiate(acceptHeader);
  if (representation === null) {
    const unsupported = errorResult(
      'REPRESENTATION_NOT_SUPPORTED',
      'The representation is not supported.',
      `None of the media types in "${acceptHeader}" can be produced.`
    );
    return sendResolutionResult(response, RESOLUTION_RESULT, unsupported);
  }
  if (representation.documentOnly && result.didDocument !== null) {
    return send(response, 200, representation.mediaType, JSON.stringify(result.didDocument));
  }
  const mediaType = representation.documentOnly ? RESOLUTION_RESULT : representation.mediaType;
  return sendResolutionResult(response, mediaType, result);
}

function sendResolutionResult(response, mediaType, result) {
  const body = {
    didResolutionMetadata: result.didResolutionMetadata,
    didDocument: result.didDocument,
    didDocumentMetadata: result.didDocumentMetadata,
  };
  return send(response, statusOf(result), mediaType, JSON.stringify(body));
}

function statusOf(result) {
  const error = result.didResolutionMetadata.error;
  if (error) {
    return STATUS_BY_ERROR[error.type] ?? 500;
  }
  return result.didDocumentMetadata.deactivated === true ? 410 : 200;
}

function send(response, status, mediaType, body) {
  response.writeHead(status, {
    'content-type': mediaType,
    'content-length': Buffer.byteLength(body),
  });
  response.end(body);
  return status;
}

/**
 * Picks the representation for an Accept header, in the client's order of
 * preference.
 *
 * @param {string|undefined} acceptHeader
 * @returns {{documentOnly: boolean, mediaType: string}|null} null when nothing acceptable can be produced
 */
export function negotiate(acceptHeader) {
  if (acceptHeader === undefined || acceptHeader.trim() === '') {
    return { documentOnly: true, mediaType: DEFAULT_DOCUMENT_TYPE };
  }
  const ranges = acceptHeader
    .split(',')
    .map(parseMediaRange)
    .filter(({ quality }) => quality > 0)
    .sort((a, b) => b.quality - a.quality);
  for (const { type, profile, raw } of ranges) {
    if (type === RESOLUTION_RESULT) {
      return { documentOnly: false, mediaType: RESOLUTION_RESULT };
    }
    if (type === 'application/ld+json' && profile === LEGACY_RESOLUTION_PROFILE) {
      return { documentOnly: false, mediaType: raw };
    }
    if (Object.hasOwn(DOCUMENT_TYPES, type)) {
      return { documentOnly: true, mediaType: DOCUMENT_TYPES[type] };
    }
  }
  return null;
}

function parseMediaRange(range) {
  const [type, ...parameters] = range.split(';').map((part) => part.trim());
  let quality = 1;
  let profile;
  const kept = [];
  for (const parameter of parameters) {
    const separator = parameter.indexOf('=');
    const name = parameter.slice(0, separator).trim().toLowerCase();
    const value = parameter.slice(separator + 1).trim().replace(/^"(.*)"$/, '$1');
    if (name === 'q') {
      quality = Number(value);
    } else {
      kept.push(parameter);
      if (name === 'profile') {
        profile = value;
      }
    }
  }
  return {
    type: type.toLowerCase(),
    profile,
    quality: Number.isNaN(quality) ? 0 : quality,
    raw: [type.toLowerCase(), ...kept].join(';'),
  };
}
