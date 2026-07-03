# TODO

Potential future Sarcophagus features, roughly ordered by expected leverage.

## Supabase and External JWT Verification

- [ ] Add support for asymmetric-key bearer tokens, starting with `RS256` and
  `ES256` verification using public keys.
- [ ] Introduce a JWT verifier config separate from `BearerTokenConfig`, so
  Sarcophagus can validate external issuer tokens without implying it can mint
  them.
- [ ] Parse and validate JWT headers for `alg`, `kid`, and `typ`, rejecting
  unsupported algorithms and unknown keys before claims are trusted.
- [ ] Validate standard external JWT claims: issuer, audience, subject,
  expiration, not-before, issued-at, and key id.
- [ ] Add JWKS loading and caching for asymmetric providers, including refresh
  on unknown `kid` and cache-age behavior suitable for Supabase key rotation.
- [ ] Add a Supabase-oriented helper that derives issuer and JWKS URL from a
  project URL: `https://<project-ref>.supabase.co/auth/v1`.
- [ ] Support claim-based authorization for Supabase tokens, including `role`,
  `client_id`, `user_id`, and optional custom scope claims.
- [ ] Wire external JWT validation into raw Mummy wrappers and TAPIS security
  metadata without breaking existing `oauth2(config, scopes)` behavior.
- [ ] Document the fallback path for legacy Supabase `HS256` projects, where
  public-key verification is not possible and callers must either use the
  shared secret locally or call Supabase Auth to verify the token.

## High Value

- [x] Route-level middleware hooks for pre/post handling, logging, auth
  extensions, request timing, request IDs, CORS, and rate limits.
- [x] First-class CORS support with allowed origins, methods, headers,
  credentials, and automatic `OPTIONS` handling.
- [x] Request ID and tracing header support, including `X-Request-ID` or
  `traceparent` propagation, response headers, and Chroniclers fields.
- [ ] Validation constraints for typed params and bodies, such as min/max
  length, ranges, regex, required fields, better validation errors, and
  OpenAPI output.
- [ ] OpenAPI polish for schema overrides, reusable components, enum
  descriptions, response headers, richer auth examples, and Swagger UI or
  ReDoc helpers.

## Useful Extensions

- [ ] Static file and asset response helpers with content type detection, ETag,
  `Last-Modified`, range requests, and compression interaction.
- [x] Cookie and session helpers for typed cookie parsing, signed cookies,
  secure defaults, SameSite, and expiry handling.
- [x] Browser login helpers for password-login cookies, logout cookie clearing,
  and current-user/session middleware.
- [ ] Multipart and form-data support for typed forms and file uploads.
- [ ] Optional RFC 9457 Problem Details error responses while preserving the
  current structured error format.

## Refinements

- [ ] More complete content negotiation with `Accept` q-value sorting,
  wildcards, and clearer fallback behavior.
- [ ] Clearer documentation and examples for the compile-time JSON backend
  choice between `jsony` and `std/jsonutils`.
- [ ] Nim client generation helpers from registered TAPIS routes or OpenAPI
  metadata.
