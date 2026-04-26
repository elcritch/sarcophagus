import std/[json, macros]

import mummy
import mummy/routers

import ./core/jwt_bearer_tokens
import ./core/oauth2

type OAuth2ProtectedRequestHandler* =
  proc(request: Request, claims: BearerTokenClaims) {.gcsafe.}
  ## Mummy handler shape for OAuth2-protected endpoints that need JWT claims.

const routeRegistrationNames =
  ["addRoute", "get", "head", "post", "put", "delete", "options", "patch"]

proc respondJson(
    request: Request, statusCode: int, body: string, headers: HttpHeaders
) =
  var responseHeaders = headers
  responseHeaders["Content-Type"] = "application/json; charset=utf-8"

  if request.httpMethod == "HEAD":
    responseHeaders["Content-Length"] = $body.len
    request.respond(statusCode, responseHeaders)
  else:
    request.respond(statusCode, responseHeaders, body)

proc defaultOAuth2ErrorResponder*(request: Request, failure: OAuth2Failure) {.gcsafe.} =
  ## Writes the default JSON response for OAuth2 resource-server failures.
  var headers: HttpHeaders
  if failure.wwwAuthenticate.len > 0:
    headers["WWW-Authenticate"] = failure.wwwAuthenticate

  let body =
    if failure.error.len == 0:
      $(%*{"status": "error"})
    else:
      $(%*{"status": "error", "error": failure.toJson()})

  request.respondJson(failure.statusCode, body, headers)

proc defaultOAuth2TokenErrorResponder*(
    request: Request, failure: OAuth2Failure
) {.gcsafe.} =
  ## Writes the default JSON response for OAuth2 token endpoint failures.
  ##
  ## The response includes `Cache-Control: no-store` and `Pragma: no-cache`.
  var headers: HttpHeaders
  headers["Cache-Control"] = "no-store"
  headers["Pragma"] = "no-cache"
  if failure.wwwAuthenticate.len > 0:
    headers["WWW-Authenticate"] = failure.wwwAuthenticate

  let body =
    if failure.error.len == 0:
      $(%*{"status": "error"})
    else:
      $(%*{"status": "error", "error": failure.toJson()})

  request.respondJson(failure.statusCode, body, headers)

proc oauth2TokenHandler*(
    config: OAuth2Config,
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2TokenErrorResponder,
): RequestHandler =
  ## Returns a Mummy handler for the OAuth2 client-credentials token endpoint.
  ##
  ## The handler delegates protocol validation to
  ## `core/oauth2.issueClientCredentialsToken` and supports HTTP Basic,
  ## form-body, and JSON-body client authentication.
  return proc(request: Request) {.gcsafe.} =
    if request.httpMethod != "POST":
      var headers: HttpHeaders
      headers["Allow"] = "POST"
      request.respondJson(
        405, $(%*{"status": "error", "error": {"error": "invalid_request"}}), headers
      )
      return

    let tokenResult = issueClientCredentialsToken(
      config,
      request.headers["Authorization"],
      request.headers["Content-Type"],
      request.body,
    )

    if not tokenResult.ok:
      onError(request, tokenResult.failure)
      return

    var headers: HttpHeaders
    headers["Cache-Control"] = "no-store"
    headers["Pragma"] = "no-cache"
    request.respondJson(200, $tokenResult.response.toJson(), headers)

proc registerOAuth2*(
    router: var Router, config: OAuth2Config, tokenPath = "/oauth/token"
) =
  ## Mounts `oauth2TokenHandler(config)` on `router.post(tokenPath)`.
  router.post(tokenPath, oauth2TokenHandler(config))

proc validateOAuth2BearerRequest*(
    request: Request, config: OAuth2Config, requiredScopes: openArray[string] = []
): OAuth2ResourceResult {.gcsafe.} =
  ## Validates the request's `Authorization: Bearer ...` token and scopes.
  validateOAuth2BearerToken(config, request.headers["Authorization"], requiredScopes)

proc validateOAuth2BearerRequest*(
    request: Request, config: OAuth2Config, requiredClaims: openArray[OAuth2ScopeClaim]
): OAuth2ResourceResult {.gcsafe.} =
  ## Validates bearer auth using structured scope-claim pairs.
  validateOAuth2BearerRequest(request, config, scopeClaimsToScopes(requiredClaims))

proc requireOAuth2BearerAuth*(
    request: Request,
    config: OAuth2Config,
    requiredScopes: openArray[string] = [],
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2ErrorResponder,
): bool {.gcsafe.} =
  ## Validates OAuth2 bearer auth and writes an error response on failure.
  ##
  ## Returns true when the request may continue to the protected handler.
  let validation = validateOAuth2BearerRequest(request, config, requiredScopes)
  if validation.ok:
    return true

  onError(request, validation.failure)
  false

proc requireOAuth2BearerAuth*(
    request: Request,
    config: OAuth2Config,
    requiredClaims: openArray[OAuth2ScopeClaim],
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2ErrorResponder,
): bool {.gcsafe.} =
  ## Validates OAuth2 bearer auth using structured scope-claim pairs.
  requireOAuth2BearerAuth(request, config, scopeClaimsToScopes(requiredClaims), onError)

proc oauth2*(
    wrapped: RequestHandler,
    config: OAuth2Config,
    requiredScopes: openArray[string],
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2ErrorResponder,
): RequestHandler =
  ## Wraps a plain Mummy handler with OAuth2 bearer-token authorization.
  let scopes = @requiredScopes
  return proc(request: Request) {.gcsafe.} =
    if not requireOAuth2BearerAuth(request, config, scopes, onError):
      return
    wrapped(request)

proc oauth2*(
    wrapped: OAuth2ProtectedRequestHandler,
    config: OAuth2Config,
    requiredScopes: openArray[string],
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2ErrorResponder,
): RequestHandler =
  ## Wraps a Mummy handler and passes validated bearer-token claims to it.
  let scopes = @requiredScopes
  return proc(request: Request) {.gcsafe.} =
    let validation = validateOAuth2BearerRequest(request, config, scopes)
    if not validation.ok:
      onError(request, validation.failure)
      return
    wrapped(request, validation.claims)

proc oauth2*(
    wrapped: RequestHandler,
    config: OAuth2Config,
    requiredClaims: openArray[OAuth2ScopeClaim],
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2ErrorResponder,
): RequestHandler =
  ## Wraps a plain Mummy handler using structured scope-claim pairs.
  oauth2(wrapped, config, scopeClaimsToScopes(requiredClaims), onError)

proc oauth2*(
    wrapped: OAuth2ProtectedRequestHandler,
    config: OAuth2Config,
    requiredClaims: openArray[OAuth2ScopeClaim],
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2ErrorResponder,
): RequestHandler =
  ## Wraps a claims-aware Mummy handler using structured scope-claim pairs.
  oauth2(wrapped, config, scopeClaimsToScopes(requiredClaims), onError)

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

proc rewriteWithOAuth2(
    node: NimNode, config: NimNode, requiredClaims: NimNode
): NimNode =
  case node.kind
  of nnkStmtList:
    result = newStmtList()
    for child in node:
      result.add(rewriteWithOAuth2(child, config, requiredClaims))
  of nnkCall, nnkCommand:
    result = copyNimTree(node)
    if isRouteRegistrationCall(node):
      if result.len < 3:
        error("withOAuth2 expects route registrations with a handler argument", node)
      let handlerIdx = result.len - 1
      result[handlerIdx] =
        newCall(bindSym"oauth2", result[handlerIdx], config, requiredClaims)
    else:
      for idx in 1 ..< result.len:
        result[idx] = rewriteWithOAuth2(result[idx], config, requiredClaims)
  else:
    result = copyNimTree(node)
    for idx in 0 ..< result.len:
      result[idx] = rewriteWithOAuth2(result[idx], config, requiredClaims)

macro withOAuth2*(config: typed, requiredClaims: typed, body: untyped): untyped =
  ## Applies `oauth2` to Mummy route registrations inside `body`.
  ##
  ## The macro rewrites route calls such as `router.get(...)` so their handler
  ## argument is protected by OAuth2 bearer-token validation.
  rewriteWithOAuth2(body, config, requiredClaims)
