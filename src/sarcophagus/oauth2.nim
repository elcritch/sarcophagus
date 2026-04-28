import std/[json, macros, options, strutils]

import mummy
import mummy/routers

import ./core/jwt_bearer_tokens
import ./core/oauth2
import ./core/typed_api
import ./tapis_utils

export tapis_utils

type OAuth2ProtectedRequestHandler* =
  proc(request: Request, claims: BearerTokenClaims) {.gcsafe.}
  ## Mummy handler shape for OAuth2-protected endpoints that need JWT claims.

type
  OAuth2User* = object
    ## Logged-in browser user returned by an application-owned session callback.
    subject*: string
    displayName*: string
    scopes*: seq[string]

  OAuth2CurrentUserLoader* = proc(request: Request): Option[OAuth2User] {.gcsafe.}
    ## Callback used by `/oauth/authorize` to read the current logged-in user.

const routeRegistrationNames =
  ["addRoute", "get", "head", "post", "put", "delete", "options", "patch"]

proc oauth2JsonResponse(
    statusCode: int, body: JsonNode, headers: HttpHeaders = default(HttpHeaders)
): ApiResponse[JsonNode] =
  apiResponse(body, statusCode, headers.mummyToApiHeaders())

proc oauth2ErrorBody(failure: OAuth2Failure): JsonNode =
  if failure.error.len == 0:
    %*{"status": "error"}
  else:
    %*{"status": "error", "error": failure.toJson()}

proc oauth2MethodNotAllowedResponse(allow: string): ApiResponse[JsonNode] =
  var headers: HttpHeaders
  headers["Allow"] = allow
  oauth2JsonResponse(
    405, %*{"status": "error", "error": {"error": "invalid_request"}}, headers
  )

proc defaultOAuth2ErrorResponder*(request: Request, failure: OAuth2Failure) {.gcsafe.} =
  ## Writes the default JSON response for OAuth2 resource-server failures.
  var headers: HttpHeaders
  if failure.wwwAuthenticate.len > 0:
    headers["WWW-Authenticate"] = failure.wwwAuthenticate

  request.typedHandle(
    proc(): ApiResponse[JsonNode] {.gcsafe.} =
      oauth2JsonResponse(failure.statusCode, oauth2ErrorBody(failure), headers)
  )

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

  request.typedHandle(
    proc(): ApiResponse[JsonNode] {.gcsafe.} =
      oauth2JsonResponse(failure.statusCode, oauth2ErrorBody(failure), headers)
  )

proc defaultOAuth2AuthorizeErrorResponder*(
    request: Request, failure: OAuth2Failure
) {.gcsafe.} =
  ## Writes the default JSON response for OAuth2 authorization endpoint failures.
  request.typedHandle(
    proc(): ApiResponse[JsonNode] {.gcsafe.} =
      oauth2JsonResponse(failure.statusCode, oauth2ErrorBody(failure))
  )

proc appendQueryParam(url, key, value: string): string =
  result = url
  if '?' in result:
    result.add('&')
  else:
    result.add('?')
  result.add(encodeQueryComponent(key))
  result.add('=')
  result.add(encodeQueryComponent(value))

proc redirect(request: Request, location: string, statusCode = 302) =
  var headers: HttpHeaders
  headers["Location"] = location
  request.respond(statusCode, headers)

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
      request.typedHandle(
        proc(): ApiResponse[JsonNode] {.gcsafe.} =
          oauth2MethodNotAllowedResponse("POST")
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
    let tokenResponse = tokenResult.response
    request.typedHandle(
      proc(): ApiResponse[JsonNode] {.gcsafe.} =
        oauth2JsonResponse(200, tokenResponse.toJson(), headers)
    )

proc oauth2TokenHandler*(
    config: OAuth2Config,
    consumeAuthorizationCode: OAuth2AuthorizationCodeConsumer,
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2TokenErrorResponder,
): RequestHandler =
  ## Returns a Mummy handler for client-credentials and authorization-code tokens.
  return proc(request: Request) {.gcsafe.} =
    if request.httpMethod != "POST":
      request.typedHandle(
        proc(): ApiResponse[JsonNode] {.gcsafe.} =
          oauth2MethodNotAllowedResponse("POST")
      )
      return

    let tokenResult = issueOAuth2Token(
      config,
      consumeAuthorizationCode,
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
    let tokenResponse = tokenResult.response
    request.typedHandle(
      proc(): ApiResponse[JsonNode] {.gcsafe.} =
        oauth2JsonResponse(200, tokenResponse.toJson(), headers)
    )

proc registerOAuth2*(
    router: var Router, config: OAuth2Config, tokenPath = "/oauth/token"
) =
  ## Mounts `oauth2TokenHandler(config)` on `router.post(tokenPath)`.
  router.post(tokenPath, oauth2TokenHandler(config))

proc oauth2AuthorizeHandler*(
    config: OAuth2Config,
    saveAuthorizationCode: OAuth2AuthorizationCodeSaver,
    currentUser: OAuth2CurrentUserLoader,
    loginUrl = "/login",
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2AuthorizeErrorResponder,
): RequestHandler =
  ## Returns a browser authorization endpoint for OAuth2 authorization-code login.
  ##
  ## The handler expects an application-owned session callback. When no user is
  ## logged in, it redirects to `loginUrl` with a `next` parameter.
  return proc(request: Request) {.gcsafe.} =
    if request.httpMethod != "GET":
      request.typedHandle(
        proc(): ApiResponse[JsonNode] {.gcsafe.} =
          oauth2MethodNotAllowedResponse("GET")
      )
      return

    let user = currentUser(request)
    if user.isNone:
      request.redirect(loginUrl.appendQueryParam("next", request.uri))
      return

    let responseType = request.queryParams["response_type"]
    if responseType != "code":
      onError(
        request,
        OAuth2Failure(
          statusCode: 400,
          error: "unsupported_response_type",
          errorDescription: "Only response_type=code is supported",
        ),
      )
      return

    let authorizeResult = issueAuthorizationCode(
      config,
      saveAuthorizationCode,
      clientId = request.queryParams["client_id"],
      redirectUri = request.queryParams["redirect_uri"],
      subject = user.get().subject,
      requestedScopeParam = request.queryParams["scope"],
      codeChallenge = request.queryParams["code_challenge"],
      codeChallengeMethod = request.queryParams["code_challenge_method"],
      userAllowedScopes = user.get().scopes,
    )

    if not authorizeResult.ok:
      onError(request, authorizeResult.failure)
      return

    var location = authorizeResult.authorizationCode.redirectUri.appendQueryParam(
      "code", authorizeResult.authorizationCode.code
    )
    let state = request.queryParams["state"]
    if state.len > 0:
      location = location.appendQueryParam("state", state)
    request.redirect(location)

proc registerOAuth2AuthorizationCode*(
    router: var Router,
    config: OAuth2Config,
    saveAuthorizationCode: OAuth2AuthorizationCodeSaver,
    consumeAuthorizationCode: OAuth2AuthorizationCodeConsumer,
    currentUser: OAuth2CurrentUserLoader,
    tokenPath = "/oauth/token",
    authorizationPath = "/oauth/authorize",
    loginUrl = "/login",
) =
  ## Mounts `/oauth/authorize` and an extended `/oauth/token` endpoint.
  ##
  ## Existing client-credentials requests continue to work on the token endpoint.
  router.get(
    authorizationPath,
    oauth2AuthorizeHandler(config, saveAuthorizationCode, currentUser, loginUrl),
  )
  router.post(tokenPath, oauth2TokenHandler(config, consumeAuthorizationCode))

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
