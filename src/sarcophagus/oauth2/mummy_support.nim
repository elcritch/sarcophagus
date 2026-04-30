import std/[macros, options, strutils]

import mummy
import mummy/routers
import chroniclers

import ../core/jwt_bearer_tokens
import ../tapis_utils
import ./common
import ./core

export common
export tapis_utils

type OAuth2ProtectedRequestHandler* =
  proc(request: Request, claims: BearerTokenClaims) {.gcsafe.}
  ## Mummy handler shape for OAuth2-protected endpoints that need JWT claims.

const routeRegistrationNames =
  ["addRoute", "get", "head", "post", "put", "delete", "options", "patch"]

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
    onError: OAuth2ErrorResponder = defaultOAuth2TokenErrorResponder,
): RequestHandler =
  ## Returns a Mummy handler for the OAuth2 token endpoint.
  ##
  ## The handler delegates protocol validation to
  ## `oauth2/core.issueClientCredentialsToken` and supports HTTP Basic,
  ## form-body, and JSON-body client authentication.
  return proc(request: Request) {.gcsafe.} =
    trace "oauth2 token endpoint request",
      httpMethod = request.httpMethod,
      path = request.path,
      contentType = request.headers["Content-Type"],
      authorizationHeaderPresent = request.headers["Authorization"].strip().len > 0
    if request.httpMethod != "POST":
      warn "oauth2 token endpoint method rejected",
        httpMethod = request.httpMethod, path = request.path, allow = "POST"
      request.respondTypedApiValue(oauth2MethodNotAllowedResponse("POST"))
      return

    let tokenResult = issueClientCredentialsToken(
      config,
      request.headers["Authorization"],
      request.headers["Content-Type"],
      request.body,
    )

    if not tokenResult.ok:
      notice "oauth2 token endpoint denied",
        path = request.path,
        statusCode = tokenResult.failure.statusCode,
        error = tokenResult.failure.error,
        errorDescription = tokenResult.failure.errorDescription
      request.respondTypedApiValue(onError(tokenResult.failure))
      return

    let tokenResponse = tokenResult.response
    info "oauth2 token endpoint issued token",
      path = request.path,
      tokenType = tokenResponse.tokenType,
      expiresIn = tokenResponse.expiresIn,
      scope = tokenResponse.scope
    request.respondTypedApiValue(
      apiResponse(
        tokenResponse.to(OAuth2TokenPayload),
        200,
        @[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
      )
    )

proc oauth2TokenHandler*(
    config: OAuth2Config,
    consumeAuthorizationCode: OAuth2AuthorizationCodeConsumer,
    onError: OAuth2ErrorResponder = defaultOAuth2TokenErrorResponder,
): RequestHandler =
  ## Returns a Mummy handler for client-credentials and authorization-code tokens.
  return proc(request: Request) {.gcsafe.} =
    trace "oauth2 token endpoint request",
      httpMethod = request.httpMethod,
      path = request.path,
      contentType = request.headers["Content-Type"],
      authorizationHeaderPresent = request.headers["Authorization"].strip().len > 0
    if request.httpMethod != "POST":
      warn "oauth2 token endpoint method rejected",
        httpMethod = request.httpMethod, path = request.path, allow = "POST"
      request.respondTypedApiValue(oauth2MethodNotAllowedResponse("POST"))
      return

    let tokenResult = issueOAuth2Token(
      config,
      consumeAuthorizationCode,
      request.headers["Authorization"],
      request.headers["Content-Type"],
      request.body,
    )

    if not tokenResult.ok:
      notice "oauth2 token endpoint denied",
        path = request.path,
        statusCode = tokenResult.failure.statusCode,
        error = tokenResult.failure.error,
        errorDescription = tokenResult.failure.errorDescription
      request.respondTypedApiValue(onError(tokenResult.failure))
      return

    let tokenResponse = tokenResult.response
    info "oauth2 token endpoint issued token",
      path = request.path,
      tokenType = tokenResponse.tokenType,
      expiresIn = tokenResponse.expiresIn,
      scope = tokenResponse.scope
    request.respondTypedApiValue(
      apiResponse(
        tokenResponse.to(OAuth2TokenPayload),
        200,
        @[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
      )
    )

proc registerOAuth2*(
    router: var Router, config: OAuth2Config, tokenPath = "/oauth/token"
) =
  ## Mounts the OAuth2 token endpoint on a Mummy router.
  router.post(tokenPath, oauth2TokenHandler(config))

proc oauth2AuthorizeHandler*(
    config: OAuth2Config,
    saveAuthorizationCode: OAuth2AuthorizationCodeSaver,
    currentUser: OAuth2CurrentUserLoader,
    loginUrl = "/login",
    onError: OAuth2ErrorResponder = defaultOAuth2AuthorizeErrorResponder,
): RequestHandler =
  ## Returns a Mummy browser authorization endpoint.
  ##
  ## The handler expects an application-owned session callback. When no user is
  ## logged in, it redirects to `loginUrl` with a `next` parameter.
  return proc(request: Request) {.gcsafe.} =
    trace "oauth2 authorization endpoint request",
      httpMethod = request.httpMethod,
      path = request.path,
      clientIdPresent = request.queryParams["client_id"].strip().len > 0,
      responseType = request.queryParams["response_type"]
    if request.httpMethod != "GET":
      warn "oauth2 authorization endpoint method rejected",
        httpMethod = request.httpMethod, path = request.path, allow = "GET"
      request.respondTypedApiValue(oauth2MethodNotAllowedResponse("GET"))
      return

    let user = currentUser(request.headers.mummyToApiHeaders())
    if user.isNone:
      info "oauth2 authorization login required", path = request.path
      request.redirect(loginUrl.appendQueryParam("next", request.uri))
      return

    let responseType = request.queryParams["response_type"]
    if responseType != "code":
      notice "oauth2 authorization response type rejected",
        path = request.path, responseType = responseType
      request.respondTypedApiValue(
        onError(
          OAuth2Failure(
            statusCode: 400,
            error: "unsupported_response_type",
            errorDescription: "Only response_type=code is supported",
          )
        )
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
      notice "oauth2 authorization endpoint denied",
        path = request.path,
        subject = user.get().subject,
        statusCode = authorizeResult.failure.statusCode,
        error = authorizeResult.failure.error,
        errorDescription = authorizeResult.failure.errorDescription
      request.respondTypedApiValue(onError(authorizeResult.failure))
      return

    var location = authorizeResult.authorizationCode.redirectUri.appendQueryParam(
      "code", authorizeResult.authorizationCode.code
    )
    let state = request.queryParams["state"]
    if state.len > 0:
      location = location.appendQueryParam("state", state)
    info "oauth2 authorization endpoint issued code",
      path = request.path,
      subject = user.get().subject,
      clientId = authorizeResult.authorizationCode.clientId,
      scopeCount = authorizeResult.authorizationCode.scopes.len
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
  ## Mounts OAuth2 authorization-code endpoints on a Mummy router.
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
  trace "validating oauth2 bearer request",
    httpMethod = request.httpMethod,
    path = request.path,
    authorizationHeaderPresent = request.headers["Authorization"].strip().len > 0,
    requiredScopeCount = requiredScopes.len
  result =
    validateOAuth2BearerToken(config, request.headers["Authorization"], requiredScopes)
  if result.ok:
    debug "oauth2 bearer request authorized",
      httpMethod = request.httpMethod,
      path = request.path,
      subject = result.claims.subject,
      scopeCount = result.claims.scopes.len
  else:
    notice "oauth2 bearer request denied",
      httpMethod = request.httpMethod,
      path = request.path,
      statusCode = result.failure.statusCode,
      error = result.failure.error,
      errorDescription = result.failure.errorDescription

proc validateOAuth2BearerRequest*(
    request: Request, config: OAuth2Config, requiredClaims: openArray[OAuth2ScopeClaim]
): OAuth2ResourceResult {.gcsafe.} =
  ## Validates bearer auth using structured scope-claim pairs.
  validateOAuth2BearerRequest(request, config, scopeClaimsToScopes(requiredClaims))

proc requireOAuth2BearerAuth*(
    request: Request,
    config: OAuth2Config,
    requiredScopes: openArray[string] = [],
    onError: OAuth2ErrorResponder = defaultOAuth2ErrorResponder,
): bool {.gcsafe.} =
  ## Validates OAuth2 bearer auth and writes an error response on failure.
  ##
  ## Returns true when the request may continue to the protected handler.
  let validation = validateOAuth2BearerRequest(request, config, requiredScopes)
  if validation.ok:
    return true

  request.respondTypedApiValue(onError(validation.failure))
  false

proc requireOAuth2BearerAuth*(
    request: Request,
    config: OAuth2Config,
    requiredClaims: openArray[OAuth2ScopeClaim],
    onError: OAuth2ErrorResponder = defaultOAuth2ErrorResponder,
): bool {.gcsafe.} =
  ## Validates OAuth2 bearer auth using structured scope-claim pairs.
  requireOAuth2BearerAuth(request, config, scopeClaimsToScopes(requiredClaims), onError)

proc oauth2*(
    wrapped: RequestHandler,
    config: OAuth2Config,
    requiredScopes: openArray[string],
    onError: OAuth2ErrorResponder = defaultOAuth2ErrorResponder,
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
    onError: OAuth2ErrorResponder = defaultOAuth2ErrorResponder,
): RequestHandler =
  ## Wraps a Mummy handler and passes validated bearer-token claims to it.
  let scopes = @requiredScopes
  return proc(request: Request) {.gcsafe.} =
    let validation = validateOAuth2BearerRequest(request, config, scopes)
    if not validation.ok:
      request.respondTypedApiValue(onError(validation.failure))
      return
    debug "oauth2 protected handler authorized",
      path = request.path,
      subject = validation.claims.subject,
      scopeCount = validation.claims.scopes.len
    wrapped(request, validation.claims)

proc oauth2*(
    wrapped: RequestHandler,
    config: OAuth2Config,
    requiredClaims: openArray[OAuth2ScopeClaim],
    onError: OAuth2ErrorResponder = defaultOAuth2ErrorResponder,
): RequestHandler =
  ## Wraps a plain Mummy handler using structured scope-claim pairs.
  oauth2(wrapped, config, scopeClaimsToScopes(requiredClaims), onError)

proc oauth2*(
    wrapped: OAuth2ProtectedRequestHandler,
    config: OAuth2Config,
    requiredClaims: openArray[OAuth2ScopeClaim],
    onError: OAuth2ErrorResponder = defaultOAuth2ErrorResponder,
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
