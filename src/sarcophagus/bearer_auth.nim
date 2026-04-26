import std/[json, macros]

import mummy

import ./core/jwt_bearer_tokens

type
  AuthErrorResponder* =
    proc(request: Request, failure: TokenValidationFailure) {.gcsafe.}
    ## Callback used when bearer-token validation fails for a Mummy request.

  AuthenticatedRequestHandler* =
    proc(request: Request, claims: BearerTokenClaims) {.gcsafe.}
    ## Mummy handler shape for endpoints that need validated bearer-token claims.

const routeRegistrationNames =
  ["addRoute", "get", "head", "post", "put", "delete", "options", "patch"]

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
  ## Writes a default JSON error response for bearer-token validation failures.
  let body =
    $(
      %*{"status": "error", "error": {"code": failure.code, "message": failure.message}}
    )
  request.respondJson(failure.statusCode, body)

proc validateBearerRequest*(
    request: Request, config: BearerTokenConfig, requiredScopes: openArray[string] = []
): TokenValidationResult {.gcsafe.} =
  ## Validates the request's `Authorization: Bearer ...` token.
  ##
  ## `requiredScopes` must all be present in the token for validation to pass.
  let token = bearerTokenFromAuthorizationHeader(request.headers["Authorization"])
  validateBearerToken(config, token, requiredScopes)

proc requireBearerAuth*(
    request: Request,
    config: BearerTokenConfig,
    requiredScopes: openArray[string] = [],
    onError: AuthErrorResponder = defaultAuthErrorResponder,
): bool {.gcsafe.} =
  ## Validates bearer auth and writes an error response on failure.
  ##
  ## Returns true when the request may continue to the protected handler.
  let validation = validateBearerRequest(request, config, requiredScopes)
  if validation.ok:
    return true

  onError(request, validation.failure)
  false

proc bearerTokAuth*(
    wrapped: RequestHandler,
    config: BearerTokenConfig,
    requiredScopes: openArray[string],
    onError: AuthErrorResponder = defaultAuthErrorResponder,
): RequestHandler =
  ## Wraps a plain Mummy handler with bearer-token authorization.
  let scopes = @requiredScopes
  return proc(request: Request) {.gcsafe.} =
    if not requireBearerAuth(request, config, scopes, onError):
      return
    wrapped(request)

proc bearerTokAuth*(
    wrapped: AuthenticatedRequestHandler,
    config: BearerTokenConfig,
    requiredScopes: openArray[string],
    onError: AuthErrorResponder = defaultAuthErrorResponder,
): RequestHandler =
  ## Wraps a Mummy handler and passes validated token claims to it.
  let scopes = @requiredScopes
  return proc(request: Request) {.gcsafe.} =
    let validation = validateBearerRequest(request, config, scopes)
    if not validation.ok:
      onError(request, validation.failure)
      return
    wrapped(request, validation.claims)

proc isRouteRegistrationCall(node: NimNode): bool =
  if node.kind notin {nnkCall, nnkCommand} or node.len == 0:
    return false
  let callee = node[0]
  if callee.kind != nnkDotExpr or callee.len != 2:
    return false
  if callee[1].kind != nnkIdent:
    return false
  let name = $callee[1]
  name in routeRegistrationNames

proc rewriteWithBearerTokAuth(
    node: NimNode, config: NimNode, requiredScopes: NimNode
): NimNode =
  case node.kind
  of nnkStmtList:
    result = newStmtList()
    for child in node:
      result.add(rewriteWithBearerTokAuth(child, config, requiredScopes))
  of nnkCall, nnkCommand:
    result = copyNimTree(node)
    if isRouteRegistrationCall(node):
      if result.len < 3:
        error(
          "withBearerTokAuth expects route registrations with a handler argument", node
        )
      let handlerIdx = result.len - 1
      result[handlerIdx] =
        newCall(bindSym"bearerTokAuth", result[handlerIdx], config, requiredScopes)
    else:
      for idx in 1 ..< result.len:
        result[idx] = rewriteWithBearerTokAuth(result[idx], config, requiredScopes)
  else:
    result = copyNimTree(node)
    for idx in 0 ..< result.len:
      result[idx] = rewriteWithBearerTokAuth(result[idx], config, requiredScopes)

macro withBearerTokAuth*(config: typed, requiredScopes: typed, body: untyped): untyped =
  ## Applies `bearerTokAuth` to route registrations inside `body`.
  ##
  ## The macro rewrites Mummy route calls such as `router.get(...)` so their
  ## handler argument is wrapped with bearer-token authorization.
  rewriteWithBearerTokAuth(body, config, requiredScopes)
