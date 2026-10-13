# Universal Resolver driver: did:cimd

A [Universal Resolver](https://github.com/decentralized-identity/universal-resolver) driver for the
[`did:cimd` method](https://github.com/shlee1223/did-method-cimd/blob/main/did-method-cimd.md).

A `did:cimd` identifier names an OAuth Client ID Metadata Document. The driver fetches that document
over HTTPS, checks it against the method's profile, and builds the DID document from the public keys
the document declares. It keeps no state and needs no configuration.

## Run

```bash
docker run --rm -p 8080:8080 ghcr.io/shlee1223/uni-resolver-driver-did-cimd:0.1.0
```

or from source, with Node.js 22 or later:

```bash
npm start
```

To build the image yourself:

```bash
docker build -t uni-resolver-driver-did-cimd .
docker run --rm -p 8080:8080 uni-resolver-driver-did-cimd
```

`PORT` selects the listening port (default 8080). There are no other settings.

## Resolve

```bash
curl -H 'Accept: application/did-resolution' \
  http://localhost:8080/1.0/identifiers/did:cimd:shlee1223.github.io:did-cimd-examples:client.json
```

Test identifiers, as registered in the Universal Resolver:

| DID | Keys |
|---|---|
| `did:cimd:shlee1223.github.io:did-cimd-examples:client.json` | referenced through `jwks_uri` |
| `did:cimd:shlee1223.github.io:did-cimd-examples:client-inline.json` | inline in `jwks` |

The documents are published from [shlee1223/shlee1223.github.io](https://github.com/shlee1223/shlee1223.github.io).
A weekly workflow resolves both and fails when one stops resolving; `npm run check:live` does the
same locally.

Metadata documents of deployed OAuth clients resolve as well. These did when this version was
released:

| DID | Metadata document |
|---|---|
| `did:cimd:frontpage.fyi:oauth:client-metadata.json` | <https://frontpage.fyi/oauth/client-metadata.json> |
| `did:cimd:tangled.org:oauth:client-metadata.json` | <https://tangled.org/oauth/client-metadata.json> |
| `did:cimd:leaflet.pub:api:oauth:metadata` | <https://leaflet.pub/api/oauth/metadata> |
| `did:cimd:bookhive.buzz:oauth-client-metadata.json` | <https://bookhive.buzz/oauth-client-metadata.json> |

They belong to third parties and can change or disappear without notice.

## Interface

`GET /1.0/identifiers/<did>` is the only route.

| `Accept` | Response body |
|---|---|
| `application/did-resolution` | DID resolution result |
| `application/did+ld+json`, `application/ld+json`, `application/did+json`, `application/did`, `application/json`, `*/*`, or absent | the DID document; the resolution result when there is none |
| anything else | `406` |

| Outcome | Status | `didResolutionMetadata.error.type` |
|---|---|---|
| Resolved | 200 | |
| Deactivated: the document URL answers `410` | 410 | none; `didDocumentMetadata.deactivated` is `true` |
| Identifier violates the grammar or canonical form | 400 | `INVALID_DID` |
| Document missing, unreachable, redirected, or outside the profile | 404 | `NOT_FOUND` |
| No acceptable representation | 406 | `REPRESENTATION_NOT_SUPPORTED` |
| Driver failure | 500 | `INTERNAL_ERROR` |

`error.detail` states the specific reason, for example
`client_id "https://a.example/x" does not equal the document URL https://b.example/x`.

A port is written as `%3A`, as in `did:cimd:example.com%3A8443:agents:billing`, and must reach the
driver undecoded.

## How the method's rules are applied

- **Fetching.** Requests go to DNS names over HTTPS only. Every address a name resolves to must be
  a public one, and the connection is made to the addresses that were checked, so a second DNS
  answer cannot redirect it. Private, loopback, link-local and other special-purpose ranges are
  refused. Redirects are never followed, for the document and for `jwks_uri` alike.
- **Limits.** One fetch has 8 seconds and 256 KiB. Nothing is cached.
- **Profile.** `client_id` must equal the document URL character for character. Exactly one of
  `jwks` and `jwks_uri` must be present. `jwks_uri` must be on the document's HTTPS origin.
- **Keys.** Private parameters are dropped. A key is kept unless `use` is something other than
  `sig`, `key_ops` lacks `verify`, or a member its `kty` requires is missing. `EC`, `OKP` and `RSA`
  keys are supported; other key types are discarded.
- **DID document.** Each key becomes a `JsonWebKey2020` verification method whose fragment is the
  key's RFC 7638 thumbprint, referenced from `authentication` only.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `NOT_FOUND`, detail `... does not resolve to a public address` | The host does not exist, or is internal or loopback. The driver log says which. |
| `NOT_FOUND`, detail `... answered 301; redirects are not followed` | The document moved. Use the DID of the URL that serves it directly. |
| `NOT_FOUND`, detail `client_id ... does not equal the document URL` | The DID was derived from a URL other than the document's `client_id`. |
| `NOT_FOUND`, detail `the document carries neither jwks nor jwks_uri` | A public client. It declares no key, so it has no `did:cimd` DID document. |
| `INVALID_DID` for an identifier with a port | The port separator must be `%3A`, uppercase, and must reach the driver undecoded. |

The driver logs one line per request to standard output, with the reason when resolution fails.

## Develop

```bash
npm test
```

The tests use Node's built-in test runner. They need no network access and no dependencies.

## Release

1. Update `version` in `package.json`, the version in this file, and `CHANGELOG.md`.
2. Tag the commit `v<version>` and push the tag. The workflow tests, builds for `linux/amd64` and
   `linux/arm64`, and publishes `ghcr.io/<owner>/uni-resolver-driver-did-cimd:<version>`.
3. Open a pull request on the Universal Resolver that raises the image version.

## License

[Apache License 2.0](./LICENSE)
