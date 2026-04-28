import std/json

import mummy
import mummy/routers

import ../oauth2
import ../core/oauth2
import ./oauth2_hashed_clients_core
import ./secret_hashing

export oauth2_hashed_clients_core
export secret_hashing

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

proc hashedOAuth2TokenHandler*(
    config: OAuth2Config,
    loadClient: HashedOAuth2ClientLoader,
    onAudit: HashedOAuth2AuditProc = noopHashedOAuth2Audit,
    policy = defaultSecretHashPolicy(),
    onError: OAuth2ErrorResponder = defaultOAuth2TokenErrorResponder,
): RequestHandler =
  ## Returns a Mummy `/oauth/token` handler backed by hashed client records.
  ##
  ## The handler accepts the same client-credentials inputs as
  ## `oauth2TokenHandler`: HTTP Basic auth, request-body form auth, and JSON
  ## request-body auth.
  return proc(request: Request) {.gcsafe.} =
    if request.httpMethod != "POST":
      var headers: HttpHeaders
      headers["Allow"] = "POST"
      request.respondJson(
        405, $(%*{"status": "error", "error": {"error": "invalid_request"}}), headers
      )
      return

    let tokenResult = issueHashedClientCredentialsToken(
      config,
      loadClient,
      request.headers["Authorization"],
      request.headers["Content-Type"],
      request.body,
      onAudit = onAudit,
      policy = policy,
    )

    if not tokenResult.ok:
      request.respondTypedApiValue(onError(tokenResult.failure))
      return

    var headers: HttpHeaders
    headers["Cache-Control"] = "no-store"
    headers["Pragma"] = "no-cache"
    request.respondJson(200, $tokenResult.response.toJson(), headers)

proc registerHashedOAuth2*(
    router: var Router,
    config: OAuth2Config,
    loadClient: HashedOAuth2ClientLoader,
    tokenPath = "/oauth/token",
    onAudit: HashedOAuth2AuditProc = noopHashedOAuth2Audit,
    policy = defaultSecretHashPolicy(),
) =
  ## Mounts a hashed-client OAuth2 token endpoint on `router`.
  router.post(
    tokenPath,
    hashedOAuth2TokenHandler(config, loadClient, onAudit = onAudit, policy = policy),
  )
