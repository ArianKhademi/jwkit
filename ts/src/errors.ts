/**
 * Every error jwkit raises, by stable name. The Go module uses the same
 * names, and the conformance suite compares the two implementations by them.
 *
 * The first seven are the core contract. ErrNotYetValid covers nbf/iat in the
 * future, which the core seven have no name for. The last three are not about
 * the token's contents.
 */
export const ERROR_NAMES = [
  'ErrMalformed',
  'ErrUnsupportedAlg',
  'ErrUnknownKey',
  'ErrBadSignature',
  'ErrBadIssuer',
  'ErrBadAudience',
  'ErrExpired',
  'ErrNotYetValid',
  'ErrJWKSUnavailable',
  'ErrMissingToken',
  'ErrInsufficientScope',
] as const

export type ErrorName = (typeof ERROR_NAMES)[number]

/**
 * Base class of every error thrown by token verification.
 *
 * `code` (also exposed as `name`) is the stable contract. `detail` is for
 * humans and logs; it may change between releases and must not be parsed.
 */
export class JwkitError extends Error {
  readonly code: ErrorName
  readonly detail: string

  constructor(code: ErrorName, detail = '', options?: ErrorOptions) {
    super(detail === '' ? `jwkit: ${code}` : `jwkit: ${code}: ${detail}`, options)
    this.name = code
    this.code = code
    this.detail = detail
  }
}

/**
 * The token is not a well-formed compact JWS carrying a JWT (segment count,
 * base64url, JSON, missing kid or exp, oversized, ...).
 */
export class ErrMalformed extends JwkitError {
  constructor(detail?: string) {
    super('ErrMalformed', detail)
  }
}

/**
 * The header names any algorithm other than RS256 or ES256. This includes
 * "none" and every HMAC algorithm.
 */
export class ErrUnsupportedAlg extends JwkitError {
  constructor(detail?: string) {
    super('ErrUnsupportedAlg', detail)
  }
}

/** No key in the issuer's JWKS has the token's kid. */
export class ErrUnknownKey extends JwkitError {
  constructor(detail?: string) {
    super('ErrUnknownKey', detail)
  }
}

/**
 * The signature does not verify with the key the kid refers to, or that key
 * belongs to a different algorithm.
 */
export class ErrBadSignature extends JwkitError {
  constructor(detail?: string) {
    super('ErrBadSignature', detail)
  }
}

/** iss is missing or differs from the configured issuer. */
export class ErrBadIssuer extends JwkitError {
  constructor(detail?: string) {
    super('ErrBadIssuer', detail)
  }
}

/** aud is missing or does not contain the configured audience. */
export class ErrBadAudience extends JwkitError {
  constructor(detail?: string) {
    super('ErrBadAudience', detail)
  }
}

/** exp (plus clock skew) is not in the future. */
export class ErrExpired extends JwkitError {
  constructor(detail?: string) {
    super('ErrExpired', detail)
  }
}

/** nbf or iat (minus clock skew) is in the future. */
export class ErrNotYetValid extends JwkitError {
  constructor(detail?: string) {
    super('ErrNotYetValid', detail)
  }
}

/**
 * The key set could not be fetched and there is no previously fetched set to
 * fall back on, so nothing can be verified. `cause` holds the fetch error.
 */
export class ErrJWKSUnavailable extends JwkitError {
  constructor(detail?: string, options?: ErrorOptions) {
    super('ErrJWKSUnavailable', detail, options)
  }
}

/** The middleware found no token on the request. */
export class ErrMissingToken extends JwkitError {
  constructor(detail?: string) {
    super('ErrMissingToken', detail)
  }
}

/**
 * The token is valid but lacks a scope or role the middleware was configured
 * to require.
 */
export class ErrInsufficientScope extends JwkitError {
  constructor(detail?: string) {
    super('ErrInsufficientScope', detail)
  }
}

/**
 * Returns the stable name of a jwkit error ("ErrExpired", ...), or "" if the
 * value did not originate in this package.
 */
export function errorName(err: unknown): ErrorName | '' {
  return err instanceof JwkitError ? err.code : ''
}
