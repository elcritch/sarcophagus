import std/[json, os, strutils]

import mummy
import mummy/routers

import ../../src/sarcophagus/[bearer_tokens, mummy_oauth2, oauth2]

proc respondJson(request: Request, statusCode: int, body: JsonNode) =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "application/json; charset=utf-8"
  request.respond(statusCode, headers, $body)

proc healthHandler(request: Request) {.gcsafe.} =
  request.respondJson(200, %*{"status": "ok"})

proc readHandler(request: Request) {.gcsafe.} =
  request.respondJson(200, %*{"status": "ok", "message": "read access granted"})

proc writeHandler(request: Request) {.gcsafe.} =
  request.respondJson(200, %*{"status": "ok", "message": "write access granted"})

proc claimsHandler(request: Request, claims: BearerTokenClaims) {.gcsafe.} =
  request.respondJson(
    200,
    %*{
      "status": "ok",
      "subject": claims.subject,
      "scopes": claims.scopes,
      "issuer": claims.issuer,
    },
  )

proc buildConfig(): OAuth2Config =
  let tokenConfig = initBearerTokenConfig(
    issuer = "sarcophagus-example",
    audience = "example-api",
    keys = [SigningKey(kid: "v1", secret: "dev-secret-key")],
  )

  initOAuth2Config(
    realm = "example-api",
    tokenConfig = tokenConfig,
    clients = [
      initOAuth2Client(
        clientId = "reader-app",
        clientSecret = "reader-secret",
        subject = "reader-service",
        allowedScopes = ["sync:read"],
        defaultScopes = ["sync:read"],
      ),
      initOAuth2Client(
        clientId = "writer-app",
        clientSecret = "writer-secret",
        subject = "writer-service",
        allowedScopes = ["sync:read", "sync:write"],
        defaultScopes = ["sync:read", "sync:write"],
      ),
    ],
    accessTokenTtlSeconds = 3600,
  )

proc parsePort(): Port =
  let rawPort =
    if paramCount() >= 1:
      paramStr(1)
    else:
      getEnv("OAUTH2_EXAMPLE_PORT", "9081")

  try:
    Port(parseInt(rawPort))
  except ValueError:
    raise newException(ValueError, "invalid port: " & rawPort)

when isMainModule:
  let host = getEnv("OAUTH2_EXAMPLE_HOST", "127.0.0.1")
  let port = parsePort()
  let config = buildConfig()

  var router: Router
  router.get("/health", healthHandler)
  router.post("/oauth/token", oauth2TokenHandler(config))
  router.get("/api/read", withOAuth2(readHandler, config, ["sync:read"]))
  router.get("/api/write", withOAuth2(writeHandler, config, ["sync:write"]))
  router.get("/api/whoami", withOAuth2(claimsHandler, config, ["sync:read"]))
  router.get("/api/admin", withOAuth2(readHandler, config, ["sync:admin"]))

  let server = newServer(router, workerThreads = 1)
  echo "OAuth2 example server listening on http://", host, ":", port.int
  server.serve(port, address = host)
