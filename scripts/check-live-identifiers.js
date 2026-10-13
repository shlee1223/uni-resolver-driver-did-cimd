// Resolves the identifiers registered as testIdentifiers in the Universal Resolver
// against the live network and fails when one no longer resolves.
import { createFetcher } from '../src/fetcher.js';
import { createResolver } from '../src/resolver.js';

const TEST_IDENTIFIERS = [
  'did:cimd:shlee1223.github.io:did-cimd-examples:client.json',
  'did:cimd:shlee1223.github.io:did-cimd-examples:client-inline.json',
];

const resolve = createResolver({ fetchJson: createFetcher({ log: console.error }) });
const failures = [];

for (const did of TEST_IDENTIFIERS) {
  const { didDocument, didResolutionMetadata, didDocumentMetadata } = await resolve(did);
  if (didDocument !== null) {
    console.log(`ok       ${did} (${didDocument.verificationMethod.length} key(s))`);
    continue;
  }
  const reason = didDocumentMetadata.deactivated
    ? 'deactivated: the document URL answers 410'
    : didResolutionMetadata.error.detail;
  console.log(`FAILED   ${did}: ${reason}`);
  failures.push(did);
}

if (failures.length > 0) {
  console.error(
    `\n${failures.length} of ${TEST_IDENTIFIERS.length} test identifiers no longer resolve. ` +
      'Restore the documents, or replace the identifiers here, in README.md and in the Universal Resolver application.yml.'
  );
  process.exit(1);
}
