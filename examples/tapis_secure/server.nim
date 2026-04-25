import std/[json, options, os, strutils]

import mummy

import sarcophagus/[core/jwt_bearer_tokens, core/oauth2, tapis]

type
  HealthResponse = object
    status*: string

  MessageResponse = object
    status*: string
    message*: string

  Goto = object
    slug*: string
    url*: string
    title*: string
    visits*: int

  GotoList = object
    items*: seq[Goto]
    count*: int

proc seedGotos(): seq[Goto] {.gcsafe.} =
  @[
    Goto(
      slug: "docs",
      url: "https://github.com/elcritch/sarcophagus",
      title: "Sarcophagus docs",
      visits: 42,
    ),
    Goto(
      slug: "status",
      url: "https://status.example.test",
      title: "Status dashboard",
      visits: 7,
    ),
    Goto(
      slug: "runbook",
      url: "https://wiki.example.test/runbook",
      title: "Operations runbook",
      visits: 13,
    ),
  ]

proc oauthConfig(): OAuth2Config =
  let tokenConfig = initBearerTokenConfig(
    issuer = "goto-server",
    audience = "goto-api",
    keys = [SigningKey(kid: "v1", secret: "goto-signing-secret")],
  )

  initOAuth2Config(
    realm = "goto",
    tokenConfig = tokenConfig,
    clients = [
      initOAuth2Client(
        clientId = "goto-cli",
        clientSecret = "goto-secret",
        subject = "goto-cli",
        allowedScopes = ["goto:read", "goto:write"],
        defaultScopes = ["goto:read"],
      )
    ],
    accessTokenTtlSeconds = 900,
  )

proc health(): HealthResponse {.
    gcsafe, tapi(get, "/health", summary = "Health check", tags = ["system"])
.} =
  HealthResponse(status: "ok")

proc oauthToken(
    request: Request
): ApiResponse[JsonNode] {.
    gcsafe,
    tapi(
      post,
      "/oauth/token",
      summary = "Issue a client credentials token",
      tags = ["auth"],
    )
.} =
  let tokenResult = issueClientCredentialsToken(
    oauthConfig(),
    request.headers["Authorization"],
    request.headers["Content-Type"],
    request.body,
  )

  var headers: ApiHeaders = @[("Cache-Control", "no-store"), ("Pragma", "no-cache")]
  if not tokenResult.ok:
    if tokenResult.failure.wwwAuthenticate.len > 0:
      headers.add(("WWW-Authenticate", tokenResult.failure.wwwAuthenticate))
    return apiResponse(
      %*{"status": "error", "error": tokenResult.failure.toJson()},
      statusCode = tokenResult.failure.statusCode,
      headers = headers,
    )

  apiResponse(tokenResult.response.toJson(), headers = headers)

proc resolveGoto(
    slug: string, preview: Option[bool]
): Goto {.
    gcsafe, tapi(get, "/go/@slug", summary = "Resolve a goto slug", tags = ["goto"])
.} =
  for item in seedGotos():
    if item.slug == slug:
      if preview.get(false):
        return item
      return
        Goto(slug: item.slug, url: item.url, title: item.title, visits: item.visits + 1)

  raiseApiError(404, "goto not found", "goto_not_found", details = %*{"slug": slug})

proc listGotos(
    prefix: Option[string], limit: Option[int]
): GotoList {.
    gcsafe, tapi(get, "/admin/gotos", summary = "List goto links", tags = ["admin"])
.} =
  var items: seq[Goto]
  for item in seedGotos():
    if prefix.isSome() and not item.slug.startsWith(prefix.get()):
      continue
    items.add item

  if limit.isSome() and limit.get() < items.len:
    items.setLen(limit.get())

  GotoList(items: items, count: items.len)

proc inspectGoto(
    slug: string
): Goto {.
    gcsafe,
    tapi(get, "/admin/gotos/@slug", summary = "Inspect a goto link", tags = ["admin"])
.} =
  for item in seedGotos():
    if item.slug == slug:
      return item

  raiseApiError(404, "goto not found", "goto_not_found", details = %*{"slug": slug})

proc saveGoto(
    slug: string, url: string, title: Option[string]
): Goto {.
    gcsafe,
    tapi(get, "/admin/gotos/@slug/save", summary = "Save a goto link", tags = ["admin"])
.} =
  if not (url.startsWith("https://") or url.startsWith("http://")):
    raiseApiError(
      400, "goto url must start with http:// or https://", "invalid_goto_url"
    )

  Goto(slug: slug, url: url, title: title.get(slug), visits: 0)

proc deleteGoto(
    slug: string
): MessageResponse {.
    gcsafe,
    tapi(
      get, "/admin/gotos/@slug/delete", summary = "Delete a goto link", tags = ["admin"]
    )
.} =
  MessageResponse(status: "ok", message: "delete requested for " & slug)

proc brokenRoute(): MessageResponse {.
    gcsafe, tapi(get, "/broken", summary = "Example error response", tags = ["system"])
.} =
  raise newException(ValueError, "simulated validation failure")

proc parsePort(): Port =
  let rawPort =
    if paramCount() >= 1:
      paramStr(1)
    else:
      getEnv("TAPIS_SECURE_EXAMPLE_PORT", "9083")

  try:
    Port(parseInt(rawPort))
  except ValueError:
    raise newException(ValueError, "invalid port: " & rawPort)

when isMainModule:
  let host = getEnv("TAPIS_SECURE_EXAMPLE_HOST", "127.0.0.1")
  let port = parsePort()

  var apiConfig = defaultApiConfig()
  apiConfig.includeStackTraces =
    getEnv("TAPIS_SECURE_EXAMPLE_STACKTRACES", "") in ["1", "true", "yes"]

  let authConfig = oauthConfig()
  let readSecurity = oauth2(authConfig, ["goto:read"])
  let writeSecurity = oauth2(authConfig, ["goto:write"])
  let apiRouter =
    initApiRouter("Sarcophagus TAPIS Secure Goto Example", "1.0.0", apiConfig)

  apiRouter.add(health)
  apiRouter.add(oauthToken)
  apiRouter.add(resolveGoto)
  withSecurity(apiRouter, readSecurity):
    apiRouter.add(listGotos)
    apiRouter.add(inspectGoto)
    withSecurity(apiRouter, writeSecurity):
      apiRouter.add(saveGoto)
      apiRouter.add(deleteGoto)
  apiRouter.add(brokenRoute)
  apiRouter.mountOpenApi()

  let server = newServer(apiRouter.router, workerThreads = 1)
  echo "TAPIS secure goto example listening on http://", host, ":", port.int
  echo "OpenAPI document: http://", host, ":", port.int, "/swagger.json"
  server.serve(port, address = host)
