import { createFetcher } from './fetcher.js';
import { createResolver } from './resolver.js';
import { createServer } from './server.js';

const DEFAULT_PORT = 8080;

function readPort() {
  const raw = process.env.PORT;
  if (raw === undefined || raw === '') {
    return DEFAULT_PORT;
  }
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`PORT must be an integer between 1 and 65535, got "${raw}"`);
  }
  return port;
}

const log = (line) => console.log(`${new Date().toISOString()} ${line}`);
const resolve = createResolver({ fetchJson: createFetcher({ log }) });
const server = createServer({ resolve, log });

server.listen(readPort(), () => {
  log(`did:cimd driver listening on port ${server.address().port}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    log(`received ${signal}, shutting down`);
    server.close();
    server.closeIdleConnections();
  });
}
