import { createHash } from 'node:crypto';

/** Members that make up the RFC 7638 thumbprint input, in lexicographic order. */
const THUMBPRINT_MEMBERS = {
  EC: ['crv', 'kty', 'x', 'y'],
  OKP: ['crv', 'kty', 'x'],
  RSA: ['e', 'kty', 'n'],
};

/** Private and symmetric key parameters of RFC 7518 and RFC 8037. */
const SECRET_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

/**
 * @typedef {object} VerificationKey
 * @property {Record<string, unknown>} jwk the public JWK, secret members removed
 * @property {string} thumbprint           base64url SHA-256 JWK Thumbprint
 */

/**
 * Applies spec 3.2 steps 3 and 4 to the keys of a JWK Set: secret parameters
 * are dropped, keys not usable for verifying signatures are discarded, and each
 * remaining key is paired with its RFC 7638 thumbprint.
 *
 * A key published twice has one thumbprint and is returned once, since the
 * thumbprint is the verification method identifier.
 *
 * @param {unknown[]} keys the "keys" member of a JWK Set
 * @returns {VerificationKey[]}
 */
export function selectVerificationKeys(keys) {
  const selected = new Map();
  for (const candidate of keys) {
    if (!isObject(candidate)) {
      continue;
    }
    const jwk = withoutSecrets(candidate);
    if (!isForVerification(jwk)) {
      continue;
    }
    const thumbprint = computeThumbprint(jwk);
    if (thumbprint !== null && !selected.has(thumbprint)) {
      selected.set(thumbprint, { jwk, thumbprint });
    }
  }
  return [...selected.values()];
}

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function withoutSecrets(jwk) {
  return Object.fromEntries(
    Object.entries(jwk).filter(([member]) => !SECRET_MEMBERS.includes(member))
  );
}

function isForVerification(jwk) {
  if (Object.hasOwn(jwk, 'use') && jwk.use !== 'sig') {
    return false;
  }
  if (Object.hasOwn(jwk, 'key_ops')) {
    return Array.isArray(jwk.key_ops) && jwk.key_ops.includes('verify');
  }
  return true;
}

/**
 * @param {Record<string, unknown>} jwk
 * @returns {string|null} null when the key lacks a member its kty requires
 */
export function computeThumbprint(jwk) {
  if (typeof jwk.kty !== 'string' || !Object.hasOwn(THUMBPRINT_MEMBERS, jwk.kty)) {
    return null;
  }
  const members = THUMBPRINT_MEMBERS[jwk.kty];
  if (members.some((member) => typeof jwk[member] !== 'string' || jwk[member] === '')) {
    return null;
  }
  const input = `{${members.map((member) => `"${member}":${JSON.stringify(jwk[member])}`).join(',')}}`;
  return createHash('sha256').update(input, 'utf8').digest('base64url');
}
