import std/json

import mummy

import ./bearer_tokens

type
  AuthErrorResponder* =
    proc(request: Request, failure: TokenValidationFailure) {.gcsafe.}

  AuthenticatedRequestHandler* =
    proc(request: Request, claims: BearerTokenClaims) {.gcsafe.}

proc respondJson(request: Request, statusCode: int, body: string) =
  var headers: HttpHeaders
  headers["Content-Type"] = "application/json; charset=utf-8"
  if request.httpMethod == "HEAD":
    headers["Content-Length"] = $body.len
    request.respond(statusCode, headers)
  else:
    request.respond(statusCode, headers, body)

proc defaultAuthErrorResponder*(
    request: Request, failure: TokenValidationFailure
) {.gcsafe.} =
  let body =
    $(
      %*{"status": "error", "error": {"code": failure.code, "message": failure.message}}
    )
  request.respondJson(failure.statusCode, body)

proc validateBearerRequest*(
    request: Request, config: BearerTokenConfig, requiredScopes: openArray[string] = []
): TokenValidationResult {.gcsafe.} =
  let token = bearerTokenFromAuthorizationHeader(request.headers["Authorization"])
  validateBearerToken(config, token, requiredScopes)

proc requireBearerAuth*(
    request: Request,
    config: BearerTokenConfig,
    requiredScopes: openArray[string] = [],
    onError: AuthErrorResponder = defaultAuthErrorResponder,
): bool {.gcsafe.} =
  let validation = validateBearerRequest(request, config, requiredScopes)
  if validation.ok:
    return true

  onError(request, validation.failure)
  false

proc withBearerAuth*(
    wrapped: RequestHandler,
    config: BearerTokenConfig,
    requiredScopes: seq[string],
    onError: AuthErrorResponder = defaultAuthErrorResponder,
): RequestHandler =
  let scopes = requiredScopes
  return proc(request: Request) {.gcsafe.} =
    if not requireBearerAuth(request, config, scopes, onError):
      return
    wrapped(request)

proc withBearerAuth*(
    wrapped: AuthenticatedRequestHandler,
    config: BearerTokenConfig,
    requiredScopes: seq[string],
    onError: AuthErrorResponder = defaultAuthErrorResponder,
): RequestHandler =
  let scopes = requiredScopes
  return proc(request: Request) {.gcsafe.} =
    let validation = validateBearerRequest(request, config, scopes)
    if not validation.ok:
      onError(request, validation.failure)
      return
    wrapped(request, validation.claims)
