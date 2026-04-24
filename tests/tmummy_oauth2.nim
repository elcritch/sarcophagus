import std/[httpclient, json, random, unittest]

import mummy
import mummy/routers

import ../src/sarcophagus/[bearer_tokens, mummy_oauth2, oauth2]

type ServerThreadArgs = object
  server: Server
  port: Port
  address: string

proc serveServer(args: ServerThreadArgs) {.thread.} =
  args.server.serve(args.port, address = args.address)

proc respondJson(request: Request, statusCode: int, body: JsonNode) =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "application/json; charset=utf-8"
  request.respond(statusCode, headers, $body)

proc claimsHandler(request: Request, claims: BearerTokenClaims) {.gcsafe.} =
  request.respondJson(200, %*{"subject": claims.subject, "scopes": claims.scopes})

proc testConfig(): OAuth2Config =
  let tokenConfig = initBearerTokenConfig(
    issuer = "sam-sync-server",
    audience = "sam-sync-api",
    keys = [SigningKey(kid: "v1", secret: "secret-a")],
  )

  initOAuth2Config(
    realm = "sam-sync",
    tokenConfig = tokenConfig,
    clients = [
      initOAuth2Client(
        clientId = "reader-app",
        clientSecret = "secret-reader",
        subject = "reader-service",
        allowedScopes = ["sync:read", "sync:write"],
        defaultScopes = ["sync:read"],
      )
    ],
    accessTokenTtlSeconds = 900,
  )

suite "mummy oauth2":
  test "token endpoint and protected resource work together":
    randomize()
    let config = testConfig()

    var router: Router
    router.post("/oauth/token", oauth2TokenHandler(config))
    router.get("/claims", withOAuth2BearerAuth(claimsHandler, config, @["sync:read"]))

    let server = newServer(router, workerThreads = 1)
    let portNumber = 20000 + rand(20000)
    let args =
      ServerThreadArgs(server: server, port: Port(portNumber), address: "127.0.0.1")

    var serverThread: Thread[ServerThreadArgs]
    createThread(serverThread, serveServer, args)
    defer:
      server.close()
      joinThread(serverThread)

    server.waitUntilReady()

    var client = newHttpClient(timeout = 5_000)
    defer:
      client.close()

    let baseUrl = "http://127.0.0.1:" & $portNumber

    let tokenResponse = client.request(
      baseUrl & "/oauth/token",
      httpMethod = HttpPost,
      headers = newHttpHeaders(
        {
          "Authorization": "Basic cmVhZGVyLWFwcDpzZWNyZXQtcmVhZGVy",
          "Content-Type": "application/x-www-form-urlencoded",
        }
      ),
      body = "grant_type=client_credentials&scope=sync%3Aread",
    )
    check tokenResponse.code.int == 200
    check tokenResponse.headers["Cache-Control"] == "no-store"
    check tokenResponse.headers["Pragma"] == "no-cache"
    let tokenBody = parseJson(tokenResponse.body)
    check tokenBody["token_type"].getStr() == "Bearer"

    let resourceResponse = client.request(
      baseUrl & "/claims",
      httpMethod = HttpGet,
      headers = newHttpHeaders(
        {"Authorization": "Bearer " & tokenBody["access_token"].getStr()}
      ),
    )
    check resourceResponse.code.int == 200
    let resourceBody = parseJson(resourceResponse.body)
    check resourceBody["subject"].getStr() == "reader-service"

    let unauthenticated = client.get(baseUrl & "/claims")
    check unauthenticated.code.int == 401
    check unauthenticated.headers["WWW-Authenticate"] == """Bearer realm="sam-sync""""

  test "token endpoint returns invalid_client failures":
    randomize()
    let config = testConfig()

    var router: Router
    router.post("/oauth/token", oauth2TokenHandler(config))

    let server = newServer(router, workerThreads = 1)
    let portNumber = 20000 + rand(20000)
    let args =
      ServerThreadArgs(server: server, port: Port(portNumber), address: "127.0.0.1")

    var serverThread: Thread[ServerThreadArgs]
    createThread(serverThread, serveServer, args)
    defer:
      server.close()
      joinThread(serverThread)

    server.waitUntilReady()

    var client = newHttpClient(timeout = 5_000)
    defer:
      client.close()

    let response = client.request(
      "http://127.0.0.1:" & $portNumber & "/oauth/token",
      httpMethod = HttpPost,
      headers = newHttpHeaders(
        {
          "Authorization": "Basic cmVhZGVyLWFwcDpiYWQ=",
          "Content-Type": "application/x-www-form-urlencoded",
        }
      ),
      body = "grant_type=client_credentials",
    )

    check response.code.int == 401
    check response.headers["Cache-Control"] == "no-store"
    check response.headers["Pragma"] == "no-cache"
    check response.headers["WWW-Authenticate"] == """Basic realm="sam-sync""""
    let body = parseJson(response.body)
    check body["error"]["error"].getStr() == "invalid_client"
