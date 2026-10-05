# jwkit

A small shared SDK, in Go and TypeScript, for verifying JWTs against an
identity provider's JWKS endpoint. Work in progress; see the commit history.

## Conformance matrix

<!-- conformance:start -->
112 cases, 112 identical results across the fixture expectation, Go and TypeScript.

| Expected result | Cases | Go agrees | TypeScript agrees |
|---|---:|---:|---:|
| `ok` | 17 | 17 | 17 |
| `ErrExpired` | 4 | 4 | 4 |
| `ErrNotYetValid` | 2 | 2 | 2 |
| `ErrMalformed` | 44 | 44 | 44 |
| `ErrBadIssuer` | 6 | 6 | 6 |
| `ErrBadAudience` | 5 | 5 | 5 |
| `ErrBadSignature` | 16 | 16 | 16 |
| `ErrUnknownKey` | 6 | 6 | 6 |
| `ErrUnsupportedAlg` | 12 | 12 | 12 |

<details>
<summary>All 112 cases</summary>

| Case | What the token is | Go | TypeScript |
|---|---|---|---|
| `valid-rs256` | A well-formed RS256 token from the issuer. | `ok` | `ok` |
| `valid-es256` | A well-formed ES256 token from the issuer. | `ok` | `ok` |
| `valid-aud-array` | aud is an array that contains the expected audience. | `ok` | `ok` |
| `valid-aud-array-mixed-types` | Non-string aud entries are ignored, not fatal. | `ok` | `ok` |
| `valid-no-iat-no-nbf` | iat and nbf are optional. | `ok` | `ok` |
| `valid-fractional-exp` | NumericDate may have a fractional part. | `ok` | `ok` |
| `valid-exp-within-skew` | Expired 59 s ago, inside the 60 s clock skew. | `ok` | `ok` |
| `valid-nbf-within-skew` | Not valid for another 60 s, inside the clock skew. | `ok` | `ok` |
| `valid-iat-within-skew` | Issued 60 s in the future, inside the clock skew. | `ok` | `ok` |
| `valid-huge-exp` | exp far beyond any calendar (1e300) is still a finite number. | `ok` | `ok` |
| `valid-jku-x5u-ignored` | A genuine token whose header also carries jku and x5u. They must be ignored, not followed. | `ok` | `ok` |
| `valid-unknown-header-members` | Header members jwkit does not know are ignored. | `ok` | `ok` |
| `valid-no-typ` | typ is optional. | `ok` | `ok` |
| `valid-duplicate-alg-last-wins` | Duplicate header member: both JSON parsers keep the last one, RS256. | `ok` | `ok` |
| `valid-whitespace-around-json` | JSON whitespace before and after the header and payload objects. | `ok` | `ok` |
| `valid-prototype-named-claims` | Claims named __proto__ and constructor are ordinary claims. | `ok` | `ok` |
| `valid-at-size-limit` | A valid token of exactly 8192 bytes, the size limit. | `ok` | `ok` |
| `expired` | exp is an hour in the past. | `ErrExpired` | `ErrExpired` |
| `expired-es256` | The same, for an ES256 token. | `ErrExpired` | `ErrExpired` |
| `expired-at-skew-boundary` | exp + skew equals now exactly: no longer valid. | `ErrExpired` | `ErrExpired` |
| `exp-underflows-to-zero` | exp is 1e-400, which every double parser reads as 0. | `ErrExpired` | `ErrExpired` |
| `not-yet-valid` | nbf is 61 s in the future, just outside the clock skew. | `ErrNotYetValid` | `ErrNotYetValid` |
| `issued-in-the-future` | iat is an hour in the future. | `ErrNotYetValid` | `ErrNotYetValid` |
| `missing-exp` | A token without exp never expires; jwkit requires exp. | `ErrMalformed` | `ErrMalformed` |
| `exp-is-a-string` | exp must be a JSON number. | `ErrMalformed` | `ErrMalformed` |
| `exp-overflows-double` | exp is 1e400: Infinity in JavaScript, a range error in Go. Both must reject it. | `ErrMalformed` | `ErrMalformed` |
| `nbf-is-a-string` | nbf must be a JSON number when present. | `ErrMalformed` | `ErrMalformed` |
| `iat-is-null` | A present-but-null iat is not a number. | `ErrMalformed` | `ErrMalformed` |
| `wrong-issuer` | Signed by the right key but iss names someone else. | `ErrBadIssuer` | `ErrBadIssuer` |
| `missing-issuer` | No iss claim. | `ErrBadIssuer` | `ErrBadIssuer` |
| `issuer-is-an-array` | iss must be a string. | `ErrBadIssuer` | `ErrBadIssuer` |
| `issuer-trailing-slash` | Issuer comparison is exact; no URL normalisation. | `ErrBadIssuer` | `ErrBadIssuer` |
| `wrong-audience` | aud names a different API. | `ErrBadAudience` | `ErrBadAudience` |
| `missing-audience` | No aud claim. | `ErrBadAudience` | `ErrBadAudience` |
| `audience-array-without-ours` | aud is an array that lacks the expected audience. | `ErrBadAudience` | `ErrBadAudience` |
| `audience-is-a-number` | aud must be a string or an array. | `ErrBadAudience` | `ErrBadAudience` |
| `wrong-issuer-and-expired` | Two faults: the issuer check comes first. | `ErrBadIssuer` | `ErrBadIssuer` |
| `wrong-audience-and-expired` | Two faults: the audience check comes before expiry. | `ErrBadAudience` | `ErrBadAudience` |
| `claims-inside-proto-member` | The real claims sit under a member named __proto__. JavaScript code that copies the payload with assignment semantics (Object.assign) would turn that member into the object's prototype and then find the claims on it. | `ErrBadIssuer` | `ErrBadIssuer` |
| `tampered-payload` | sub changed to admin after signing. | `ErrBadSignature` | `ErrBadSignature` |
| `tampered-signature` | One bit of the signature flipped. | `ErrBadSignature` | `ErrBadSignature` |
| `tampered-header` | One header member changed after signing. | `ErrBadSignature` | `ErrBadSignature` |
| `wrong-key-same-kid` | Signed by the attacker's key but labelled with the issuer's kid. | `ErrBadSignature` | `ErrBadSignature` |
| `signature-from-another-token` | A genuine signature transplanted onto different claims. | `ErrBadSignature` | `ErrBadSignature` |
| `empty-signature` | An RS256 header with the signature removed. | `ErrBadSignature` | `ErrBadSignature` |
| `expired-and-tampered` | Two faults: the signature is checked before any claim. | `ErrBadSignature` | `ErrBadSignature` |
| `es256-header-rsa-kid` | An ES256 token whose kid names the RSA key. A key is only ever used with its own algorithm. | `ErrBadSignature` | `ErrBadSignature` |
| `rs256-header-ec-kid` | An RS256 token whose kid names the EC key. | `ErrBadSignature` | `ErrBadSignature` |
| `es256-tampered-payload` | ES256: sub changed to admin after signing. | `ErrBadSignature` | `ErrBadSignature` |
| `es256-tampered-signature` | ES256: one bit of the signature flipped. | `ErrBadSignature` | `ErrBadSignature` |
| `es256-der-signature` | A correct ECDSA signature in ASN.1 DER instead of the 64-byte r\|\|s form JWS requires. | `ErrBadSignature` | `ErrBadSignature` |
| `es256-signature-extra-byte` | A correct r\|\|s signature with a zero byte prepended (65 bytes). | `ErrBadSignature` | `ErrBadSignature` |
| `embedded-jwk-attacker-key` | Signed by the attacker, who helpfully embeds their own public key in the jwk header. | `ErrBadSignature` | `ErrBadSignature` |
| `jku-injection-issuer-kid` | Signed by the attacker, issuer's kid, jku pointing at the attacker's JWKS. | `ErrBadSignature` | `ErrBadSignature` |
| `x5u-injection-issuer-kid` | Signed by the attacker, issuer's kid, x5u pointing at the attacker's certificate. | `ErrBadSignature` | `ErrBadSignature` |
| `unknown-kid` | Signed by a key the issuer never published. | `ErrUnknownKey` | `ErrUnknownKey` |
| `jku-injection-attacker-kid` | Signed by the attacker under their own kid, with jku pointing at a JWKS that contains it. | `ErrUnknownKey` | `ErrUnknownKey` |
| `weak-rsa-key` | Correctly signed by a published 1024-bit RSA key. Keys under 2048 bits are never loaded. | `ErrUnknownKey` | `ErrUnknownKey` |
| `p384-key-for-es256` | Signed (ECDSA, SHA-256) by a published P-384 key. Only P-256 keys are loaded for ES256. | `ErrUnknownKey` | `ErrUnknownKey` |
| `encryption-key` | Correctly signed by a published key marked use=enc. Encryption keys are never loaded. | `ErrUnknownKey` | `ErrUnknownKey` |
| `key-pinned-to-ps256` | Correctly signed (RS256) by a published key whose JWK says alg=PS256. The key's own alg is respected. | `ErrUnknownKey` | `ErrUnknownKey` |
| `alg-none` | The classic: {"alg":"none"} and an empty signature. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `alg-none-with-kid` | alg none, naming the issuer's key. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `alg-none-mixed-case` | "nOnE": case tricks do not help. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `alg-none-with-signature` | alg none, but carrying a genuine RS256 signature for the original header. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `hs256-rsa-public-key-pem` | Algorithm confusion: HS256 keyed with the issuer's RSA public key in PEM form. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `hs256-rsa-public-key-der` | Algorithm confusion: HS256 keyed with the issuer's RSA public key in DER form. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `alg-hs384` | No HMAC algorithm is accepted. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `alg-rs384` | RS384 is not on the allow-list. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `alg-ps256` | PS256 is not on the allow-list. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `alg-es384` | ES384 is not on the allow-list. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `alg-lower-case` | "rs256": algorithm names are case-sensitive. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `alg-empty` | alg is the empty string. | `ErrUnsupportedAlg` | `ErrUnsupportedAlg` |
| `alg-missing` | No alg member at all. | `ErrMalformed` | `ErrMalformed` |
| `alg-is-a-number` | alg must be a string. | `ErrMalformed` | `ErrMalformed` |
| `alg-member-upper-case` | The member is spelled "ALG". Member names are case-sensitive, so there is no alg. | `ErrMalformed` | `ErrMalformed` |
| `alg-inside-proto-member` | alg and kid sit under a member named __proto__, where only code that lets it become the object's prototype would find them. | `ErrMalformed` | `ErrMalformed` |
| `missing-kid` | No kid: jwkit never guesses which key to try. | `ErrMalformed` | `ErrMalformed` |
| `empty-kid` | kid is the empty string. | `ErrMalformed` | `ErrMalformed` |
| `kid-is-a-number` | kid must be a string. | `ErrMalformed` | `ErrMalformed` |
| `crit-header` | A crit header demands extensions jwkit does not implement (RFC 7515, 4.1.11). | `ErrMalformed` | `ErrMalformed` |
| `empty-token` | The empty string. | `ErrMalformed` | `ErrMalformed` |
| `one-segment` | No dots at all. | `ErrMalformed` | `ErrMalformed` |
| `two-segments` | Header and payload, no signature segment. | `ErrMalformed` | `ErrMalformed` |
| `four-segments` | One segment too many. | `ErrMalformed` | `ErrMalformed` |
| `five-segments` | Five segments: the shape of a JWE. | `ErrMalformed` | `ErrMalformed` |
| `only-dots` | Three empty segments. | `ErrMalformed` | `ErrMalformed` |
| `bearer-prefix` | The Authorization header value, "Bearer " included, passed as the token. | `ErrMalformed` | `ErrMalformed` |
| `leading-space` | A space before the token. | `ErrMalformed` | `ErrMalformed` |
| `trailing-newline` | A newline after the token. | `ErrMalformed` | `ErrMalformed` |
| `newline-inside-header` | A line break inside a segment. Go's base64 decoder would skip it silently. | `ErrMalformed` | `ErrMalformed` |
| `invalid-base64url-header` | A character outside the base64url alphabet in the header. | `ErrMalformed` | `ErrMalformed` |
| `invalid-base64url-payload` | A character outside the base64url alphabet in the payload. | `ErrMalformed` | `ErrMalformed` |
| `invalid-base64url-signature` | A character outside the base64url alphabet in the signature. Node's decoder would skip it silently. | `ErrMalformed` | `ErrMalformed` |
| `standard-base64-alphabet` | The signature uses '+', from the standard rather than URL-safe alphabet. | `ErrMalformed` | `ErrMalformed` |
| `padded-base64` | The signature carries '=' padding. | `ErrMalformed` | `ErrMalformed` |
| `impossible-base64-length` | A signature segment whose length is 1 mod 4, which no byte string encodes to. | `ErrMalformed` | `ErrMalformed` |
| `non-canonical-base64-signature` | Only the unused trailing bits of the signature's last character differ. A lenient decoder would accept this as the same, valid, signature. | `ErrMalformed` | `ErrMalformed` |
| `non-ascii-character` | A non-ASCII letter in the payload segment. | `ErrMalformed` | `ErrMalformed` |
| `header-not-json` | The header decodes to text that is not JSON. | `ErrMalformed` | `ErrMalformed` |
| `header-json-array` | The header is a JSON array. | `ErrMalformed` | `ErrMalformed` |
| `header-json-null` | The header is JSON null. | `ErrMalformed` | `ErrMalformed` |
| `empty-header` | The header segment is empty. | `ErrMalformed` | `ErrMalformed` |
| `payload-not-json` | The payload is truncated JSON. | `ErrMalformed` | `ErrMalformed` |
| `payload-json-string` | The payload is a JSON string, not an object. | `ErrMalformed` | `ErrMalformed` |
| `nested-jwt` | A correctly signed JWT whose payload is another JWT (cty "JWT"). jwkit does not unwrap nested tokens. | `ErrMalformed` | `ErrMalformed` |
| `payload-trailing-data` | A second JSON value after the claims object. | `ErrMalformed` | `ErrMalformed` |
| `payload-stray-brace` | An extra closing brace after the claims object. | `ErrMalformed` | `ErrMalformed` |
| `payload-invalid-utf8` | The payload contains the byte 0xFF, which is not valid UTF-8. Correctly signed. | `ErrMalformed` | `ErrMalformed` |
| `payload-byte-order-mark` | The payload starts with a UTF-8 byte order mark. Correctly signed. JavaScript's TextDecoder would strip it silently. | `ErrMalformed` | `ErrMalformed` |
| `one-byte-over-size-limit` | A correctly signed token of 8193 bytes, one over the limit. | `ErrMalformed` | `ErrMalformed` |
| `extremely-long-token` | A correctly signed token of roughly 64 KiB. | `ErrMalformed` | `ErrMalformed` |

</details>
<!-- conformance:end -->
