/** The identifier violates the did:cimd grammar or canonical form (spec 2, 2.1). */
export class InvalidDidError extends Error {
  name = 'InvalidDidError';
}

/** The identity document could not be obtained or violates the profile (spec 3.1, 3.2). */
export class NotFoundError extends Error {
  name = 'NotFoundError';
}

/** A fetch failed below the HTTP layer, was blocked, or exceeded a resource limit. */
export class FetchError extends Error {
  name = 'FetchError';
}
