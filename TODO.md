# TODO

Potential future Sarcophagus features, roughly ordered by expected leverage.

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
