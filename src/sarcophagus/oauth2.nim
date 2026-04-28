import std/[macros, options, strutils]

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

  OAuth2CurrentUserLoader* = proc(headers: ApiHeaders): Option[OAuth2User] {.gcsafe.}
    ## Callback used by `/oauth/authorize` to read the current logged-in user.

  OAuth2TokenPayload* = object ## HTTP JSON body returned by OAuth2 token endpoints.
    access_token*: string
    token_type*: string
    expires_in*: int
    scope*: string

  OAuth2FailurePayload* = object ## OAuth2 error details serialized in error responses.
    error*: string
    error_description*: string
    error_uri*: string

  OAuth2ErrorResponse* = object ## JSON returned by OAuth2 error responses.
    status*: string
    error*: OAuth2FailurePayload

  OAuth2ApiError* = ApiResponse[OAuth2ErrorResponse]

  OAuth2ErrorResponder* = proc(failure: OAuth2Failure): OAuth2ApiError {.gcsafe.}
    ## Callback used to build OAuth2 error responses.

const routeRegistrationNames =
  ["addRoute", "get", "head", "post", "put", "delete", "options", "patch"]

proc valueFor(values: ApiHeaders, name: string, caseInsensitive = false): string =
  for value in values:
    if value.name == name or (caseInsensitive and cmpIgnoreCase(value.name, name) == 0):
      return value.value

proc headerValue*(headers: ApiHeaders, name: string): string =
  ## Returns one header value from typed API headers.
  headers.valueFor(name, caseInsensitive = true)

proc cookieValue*(headers: ApiHeaders, name: string): string =
  ## Returns one Cookie header value from typed API headers.
  for part in headers.headerValue("Cookie").split(';'):
    let pieces = part.strip().split('=', maxsplit = 1)
    if pieces.len == 2 and pieces[0] == name:
      return pieces[1]

proc toOAuth2TokenPayload(response: OAuth2TokenResponse): OAuth2TokenPayload =
  OAuth2TokenPayload(
    access_token: response.accessToken,
    token_type: response.tokenType,
    expires_in: response.expiresIn,
    scope: response.scope,
  )

proc toOAuth2FailurePayload(failure: OAuth2Failure): OAuth2FailurePayload =
  OAuth2FailurePayload(
    error: failure.error,
    error_description: failure.errorDescription,
    error_uri: failure.errorUri,
  )

proc oauth2ErrorResponse*(
    statusCode: int, failure: OAuth2Failure, headers: HttpHeaders = default(HttpHeaders)
): OAuth2ApiError =
  ## Builds a typed OAuth2 error response.
  apiResponse(
    OAuth2ErrorResponse(status: "error", error: failure.toOAuth2FailurePayload()),
    statusCode,
    headers.mummyToApiHeaders(),
  )

proc oauth2MethodNotAllowedResponse(allow: string): OAuth2ApiError =
  var headers: HttpHeaders
  headers["Allow"] = allow
  oauth2ErrorResponse(
    405, OAuth2Failure(statusCode: 405, error: "invalid_request"), headers
  )

proc defaultOAuth2ErrorResponder*(failure: OAuth2Failure): OAuth2ApiError {.gcsafe.} =
  ## Builds the default JSON response for OAuth2 resource-server failures.
  var headers: HttpHeaders
  if failure.wwwAuthenticate.len > 0:
    headers["WWW-Authenticate"] = failure.wwwAuthenticate
  oauth2ErrorResponse(failure.statusCode, failure, headers)

proc defaultOAuth2TokenErrorResponder*(
    failure: OAuth2Failure
): OAuth2ApiError {.gcsafe.} =
  ## Builds the default JSON response for OAuth2 token endpoint failures.
  ##
  ## The response includes `Cache-Control: no-store` and `Pragma: no-cache`.
  var headers: HttpHeaders
  headers["Cache-Control"] = "no-store"
  headers["Pragma"] = "no-cache"
  if failure.wwwAuthenticate.len > 0:
    headers["WWW-Authenticate"] = failure.wwwAuthenticate
  oauth2ErrorResponse(failure.statusCode, failure, headers)

proc defaultOAuth2AuthorizeErrorResponder*(
    failure: OAuth2Failure
): OAuth2ApiError {.gcsafe.} =
  ## Builds the default JSON response for OAuth2 authorization endpoint failures.
  oauth2ErrorResponse(failure.statusCode, failure)

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
  ## `core/oauth2.issueClientCredentialsToken` and supports HTTP Basic,
  ## form-body, and JSON-body client authentication.
  return proc(request: Request) {.gcsafe.} =
    if request.httpMethod != "POST":
      request.respondTypedApiValue(oauth2MethodNotAllowedResponse("POST"))
      return

    let tokenResult = issueClientCredentialsToken(
      config,
      request.headers["Authorization"],
      request.headers["Content-Type"],
      request.body,
    )

    if not tokenResult.ok:
      request.respondTypedApiValue(onError(tokenResult.failure))
      return

    var headers: HttpHeaders
    headers["Cache-Control"] = "no-store"
    headers["Pragma"] = "no-cache"
    let tokenResponse = tokenResult.response
    request.respondTypedApiValue(
      apiResponse(
        tokenResponse.toOAuth2TokenPayload(), 200, headers.mummyToApiHeaders()
      )
    )

proc oauth2TokenHandler*(
    config: OAuth2Config,
    consumeAuthorizationCode: OAuth2AuthorizationCodeConsumer,
    onError: OAuth2ErrorResponder = defaultOAuth2TokenErrorResponder,
): RequestHandler =
  ## Returns a Mummy handler for client-credentials and authorization-code tokens.
  return proc(request: Request) {.gcsafe.} =
    if request.httpMethod != "POST":
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
      request.respondTypedApiValue(onError(tokenResult.failure))
      return

    var headers: HttpHeaders
    headers["Cache-Control"] = "no-store"
    headers["Pragma"] = "no-cache"
    let tokenResponse = tokenResult.response
    request.respondTypedApiValue(
      apiResponse(
        tokenResponse.toOAuth2TokenPayload(), 200, headers.mummyToApiHeaders()
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
    if request.httpMethod != "GET":
      request.respondTypedApiValue(oauth2MethodNotAllowedResponse("GET"))
      return

    let user = currentUser(request.headers.mummyToApiHeaders())
    if user.isNone:
      request.redirect(loginUrl.appendQueryParam("next", request.uri))
      return

    let responseType = request.queryParams["response_type"]
    if responseType != "code":
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
      request.respondTypedApiValue(onError(authorizeResult.failure))
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
