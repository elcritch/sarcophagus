import std/json

import mummy

import ./bearer_tokens
import ./oauth2

type OAuth2ProtectedRequestHandler* =
  proc(request: Request, claims: BearerTokenClaims) {.gcsafe.}

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

proc validateOAuth2BearerRequest*(
    request: Request, config: OAuth2Config, requiredScopes: openArray[string] = []
): OAuth2ResourceResult {.gcsafe.} =
  validateOAuth2BearerToken(config, request.headers["Authorization"], requiredScopes)

proc requireOAuth2BearerAuth*(
    request: Request,
    config: OAuth2Config,
    requiredScopes: openArray[string] = [],
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2ErrorResponder,
): bool {.gcsafe.} =
  let validation = validateOAuth2BearerRequest(request, config, requiredScopes)
  if validation.ok:
    return true

  onError(request, validation.failure)
  false

proc withOAuth2BearerAuth*(
    wrapped: RequestHandler,
    config: OAuth2Config,
    requiredScopes: seq[string],
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2ErrorResponder,
): RequestHandler =
  let scopes = requiredScopes
  return proc(request: Request) {.gcsafe.} =
    if not requireOAuth2BearerAuth(request, config, scopes, onError):
      return
    wrapped(request)

proc withOAuth2BearerAuth*(
    wrapped: OAuth2ProtectedRequestHandler,
    config: OAuth2Config,
    requiredScopes: seq[string],
    onError: proc(request: Request, failure: OAuth2Failure) {.gcsafe.} =
      defaultOAuth2ErrorResponder,
): RequestHandler =
  let scopes = requiredScopes
  return proc(request: Request) {.gcsafe.} =
    let validation = validateOAuth2BearerRequest(request, config, scopes)
    if not validation.ok:
      onError(request, validation.failure)
      return
    wrapped(request, validation.claims)
