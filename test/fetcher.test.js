import assert from 'node:assert/strict';
import http from 'node:http';
import { after, before, test } from 'node:test';
import { FetchError } from '../src/errors.js';
import { createFetcher } from '../src/fetcher.js';

/** A local origin standing in for the remote one. Records every request line it sees. */
const seen = [];
const origin = http.createServer((request, response) => {
  seen.push(request.url);
  switch (request.url.split('?')[0]) {
    case '/json':
      response.writeHead(200, { 'content-type': 'application/json' }).end('{"a":1}');
      break;
    case '/echo-headers':
      response.writeHead(200).end(JSON.stringify(request.headers));
      break;
    case '/redirect':
      response.writeHead(302, { location: '/json' }).end();
      break;
    case '/gone':
      response.writeHead(410).end('gone');
      break;
    case '/html':
      response.writeHead(200, { 'content-type': 'text/html' }).end('<!doctype html>');
      break;
    case '/large':
      response.writeHead(200).end(JSON.stringify({ padding: 'x'.repeat(4096) }));
      break;
    case '/slow':
      response.writeHead(200);
      response.write('{"a":');
      break;
    case '/silent':
      break;
    default:
      response.writeHead(200).end(JSON.stringify({ path: request.url }));
  }
});

let port;
before(async () => {
  await new Promise((resolve) => origin.listen(0, '127.0.0.1', resolve));
  port = origin.address().port;
});
after(() => {
  origin.closeAllConnections();
  origin.close();
});

const toLoopback = (hostname, options, callback) => {
  const addresses = [{ address: '127.0.0.1', family: 4 }];
  if (options.all) {
    callback(null, addresses);
  } else {
    callback(null, '127.0.0.1', 4);
  }
};

/** Reaches the local origin: plain HTTP, loopback allowed. Everything else is production code. */
function localFetcher(options = {}) {
  return createFetcher({ transport: http, lookup: toLoopback, isAllowedAddress: () => true, ...options });
}

const target = (path) => ({ host: 'origin.test', port, path });

test('returns the parsed body of a 200 response', async () => {
  assert.deepEqual(await localFetcher()(target('/json')), { status: 200, json: { a: 1 } });
});

test('asks for JSON', async () => {
  const { json } = await localFetcher()(target('/echo-headers'));
  assert.equal(json.accept, 'application/json');
  assert.equal(json.host, `origin.test:${port}`);
});

test('sends the path verbatim, escapes included', async () => {
  const { json } = await localFetcher()(target('/a%3Ab/%E2%9C%93?x=%2F'));
  assert.equal(json.path, '/a%3Ab/%E2%9C%93?x=%2F');
});

test('does not follow a redirect', async () => {
  seen.length = 0;
  assert.deepEqual(await localFetcher()(target('/redirect')), { status: 302 });
  assert.deepEqual(seen, ['/redirect']);
});

test('returns other statuses without a body', async () => {
  assert.deepEqual(await localFetcher()(target('/gone')), { status: 410 });
});

test('fails when a 200 response is not JSON', async () => {
  await assert.rejects(localFetcher()(target('/html')), new FetchError('response body is not JSON'));
});

test('fails when the body exceeds the size limit', async () => {
  await assert.rejects(localFetcher({ maxBytes: 1024 })(target('/large')), /exceeds 1024 bytes/);
});

test('fails when the body stalls past the deadline', async () => {
  await assert.rejects(localFetcher({ timeoutMs: 150 })(target('/slow')), /within 150 ms/);
});

test('fails when no response arrives before the deadline', async () => {
  await assert.rejects(localFetcher({ timeoutMs: 150 })(target('/silent')), /within 150 ms/);
});

test('refuses to connect when the host resolves to a non-public address', async () => {
  seen.length = 0;
  const logged = [];
  const fetchJson = createFetcher({ transport: http, lookup: toLoopback, log: (line) => logged.push(line) });
  await assert.rejects(
    fetchJson(target('/json')),
    new FetchError('origin.test does not resolve to a public address')
  );
  assert.deepEqual(seen, []);
  assert.deepEqual(logged, ['refused to fetch from origin.test: resolves to 127.0.0.1']);
});

test('refuses to connect when any one of several addresses is non-public', async () => {
  seen.length = 0;
  const mixed = (hostname, options, callback) => {
    callback(null, [
      { address: '93.184.215.14', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]);
  };
  await assert.rejects(createFetcher({ transport: http, lookup: mixed })(target('/json')), /does not resolve to a public address/);
  assert.deepEqual(seen, []);
});

test('refuses an IP literal host without resolving anything', async () => {
  let lookups = 0;
  const counting = (...args) => {
    lookups += 1;
    toLoopback(...args);
  };
  const fetchJson = createFetcher({ transport: http, lookup: counting, isAllowedAddress: () => true });
  await assert.rejects(fetchJson({ host: '127.0.0.1', port, path: '/json' }), /IP literal/);
  await assert.rejects(fetchJson({ host: '::1', port, path: '/json' }), /IP literal/);
  assert.equal(lookups, 0);
});

test('answers a name that does not resolve exactly like one that resolves internally', async () => {
  const logged = [];
  const failing = (hostname, options, callback) => callback(new Error('getaddrinfo ENOTFOUND origin.test'));
  const fetchJson = createFetcher({ transport: http, lookup: failing, log: (line) => logged.push(line) });
  await assert.rejects(
    fetchJson(target('/json')),
    new FetchError('origin.test does not resolve to a public address')
  );
  assert.deepEqual(logged, ['refused to fetch from origin.test: getaddrinfo ENOTFOUND origin.test']);
});

test('reports a refused connection as a fetch error', async () => {
  const closed = http.createServer();
  await new Promise((resolve) => closed.listen(0, '127.0.0.1', resolve));
  const closedPort = closed.address().port;
  await new Promise((resolve) => closed.close(resolve));
  await assert.rejects(localFetcher()({ host: 'origin.test', port: closedPort, path: '/json' }), FetchError);
});
