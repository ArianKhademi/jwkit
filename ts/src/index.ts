/**
 * jwkit verifies JWTs issued by an identity provider that publishes a JWKS
 * endpoint (Auth0, Clerk, Cognito, Keycloak, or an in-house issuer).
 *
 * - Verifier checks a token's signature against the issuer's keys and then
 *   its iss, aud, exp, nbf and iat claims, failing with a typed JwkitError.
 * - Its key cache fetches the JWKS, caches keys by kid, and refetches (rate
 *   limited) when a token arrives signed by a key it has not seen, which is
 *   how key rotation is handled without restarts.
 *
 * A Go module with the same behaviour and the same error names lives next to
 * this package; a shared conformance suite keeps the two in agreement.
 */
export {
  ERROR_NAMES,
  ErrBadAudience,
  ErrBadIssuer,
  ErrBadSignature,
  ErrExpired,
  ErrInsufficientScope,
  ErrJWKSUnavailable,
  ErrMalformed,
  ErrMissingToken,
  ErrNotYetValid,
  ErrUnknownKey,
  ErrUnsupportedAlg,
  errorName,
  JwkitError,
  type ErrorName,
} from './errors.js'
export {
  claimStrings,
  decodeUnverified,
  DEFAULT_CACHE_TTL_SEC,
  DEFAULT_CLOCK_SKEW_SEC,
  DEFAULT_MAX_TOKEN_BYTES,
  DEFAULT_REFETCH_INTERVAL_SEC,
  scopes,
  Verifier,
  type Claims,
  type VerifierConfig,
} from './verifier.js'
