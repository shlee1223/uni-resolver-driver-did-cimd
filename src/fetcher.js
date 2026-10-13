import dns from 'node:dns';
import https from 'node:https';
import { isIP } from 'node:net';
import { isPublicAddress } from './address-policy.js';
import { FetchError } from './errors.js';

const DEFAULT_TIMEOUT_MS = 8000;
const DEFAULT_MAX_BYTES = 256 * 1024;
const USER_AGENT = 'uni-resolver-driver-did-cimd';

/**
 * @typedef {object} FetchTarget
 * @property {string} host
 * @property {number|null} port null selects the transport's default port
 * @property {string} path     request target, sent verbatim
 */

/**
 * @typedef {object} FetchResponse
 * @property {number} status
 * @property {unknown} [json] parsed body, present only when status is 200
 */

/**
 * Creates the fetch function used for the metadata document and the JWK Set.
 *
 * Both URLs are attacker-influenced (spec 3.2 step 2). Every address the host
 * resolves to is checked, and the socket connects to exactly the addresses that
 * were checked: there is no second resolution a DNS answer could change between.
 * Redirects are never followed; a 3xx is returned to the caller as a status.
 *
 * The transport, lookup and address policy are parameters so that tests can
 * exercise this code against a local server. Production code uses the defaults.
 *
 * @param {object} [options]
 * @param {{request: typeof https.request}} [options.transport]
 * @param {typeof dns.lookup} [options.lookup]
 * @param {(address: string) => boolean} [options.isAllowedAddress]
 * @param {number} [options.timeoutMs] bound on one whole fetch
 * @param {number} [options.maxBytes]  bound on one response body
 * @param {(line: string) => void} [options.log]
 * @returns {(target: FetchTarget) => Promise<FetchResponse>}
 */
export function createFetcher({
  transport = https,
  lookup = dns.lookup,
  isAllowedAddress = isPublicAddress,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxBytes = DEFAULT_MAX_BYTES,
  log = () => {},
} = {}) {
  // A caller learns only that the name has no public address. Whether it failed
  // to resolve or resolved to an internal address, and which one, would let the
  // driver be used to map the network it runs in; that goes to the log alone.
  const guardedLookup = (hostname, options, callback) => {
    lookup(hostname, { ...options, all: true }, (error, addresses) => {
      const refused = error ? undefined : addresses.find(({ address }) => !isAllowedAddress(address));
      if (error || addresses.length === 0 || refused) {
        const reason = error ? error.message : refused ? `resolves to ${refused.address}` : 'no address';
        log(`refused to fetch from ${hostname}: ${reason}`);
        callback(new FetchError(`${hostname} does not resolve to a public address`));
        return;
      }
      if (options.all) {
        callback(null, addresses);
      } else {
        callback(null, addresses[0].address, addresses[0].family);
      }
    });
  };

  return function fetchJson({ host, port, path }) {
    return new Promise((resolve, reject) => {
      if (isIP(host) !== 0) {
        reject(new FetchError(`${host} is an IP literal; only DNS names are fetched`));
        return;
      }
      const request = transport.request({
        host,
        port: port ?? undefined,
        path,
        method: 'GET',
        headers: { accept: 'application/json', 'user-agent': USER_AGENT },
        lookup: guardedLookup,
        agent: false,
      });
      const deadline = setTimeout(() => {
        request.destroy(new FetchError(`no complete response within ${timeoutMs} ms`));
      }, timeoutMs);
      const settle = (settler, value) => {
        clearTimeout(deadline);
        settler(value);
      };

      request.on('error', (error) => {
        settle(reject, error instanceof FetchError ? error : new FetchError(error.message));
      });
      request.on('response', (response) => {
        if (response.statusCode !== 200) {
          response.destroy();
          settle(resolve, { status: response.statusCode });
          return;
        }
        readJson(response, maxBytes).then(
          (json) => settle(resolve, { status: 200, json }),
          (error) => {
            request.destroy();
            settle(
              reject,
              error instanceof FetchError
                ? error
                : new FetchError(`response body could not be read: ${error.message}`)
            );
          }
        );
      });
      request.end();
    });
  };
}

async function readJson(response, maxBytes) {
  const chunks = [];
  let received = 0;
  for await (const chunk of response) {
    received += chunk.length;
    if (received > maxBytes) {
      throw new FetchError(`response body exceeds ${maxBytes} bytes`);
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new FetchError('response body is not JSON');
  }
}
