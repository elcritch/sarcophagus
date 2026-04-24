import std/[httpclient, json, random, unittest]

import mummy
import mummy/routers

import sarcophagus/[core/jwt_bearer_tokens, oauth2, core/oauth2]

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

proc okHandler(request: Request) {.gcsafe.} =
  request.respondJson(200, %*{"status": "ok"})

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
  test "protected api routes enforce bearer auth semantics":
    randomize()
    let config = testConfig()
    let tokenResponse = issueClientCredentialsToken(
      config,
      authorizationHeader = "Basic cmVhZGVyLWFwcDpzZWNyZXQtcmVhZGVy",
      contentType = "application/x-www-form-urlencoded",
      requestBody = "grant_type=client_credentials&scope=sync%3Aread",
    )
    check tokenResponse.ok

    var router: Router
    withOAuth2(config, ["sync:read"]):
      router.get("/protected", okHandler)
      router.get("/claims", claimsHandler)

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
    let accessToken = tokenResponse.response.accessToken

    let unauthenticated = client.get(baseUrl & "/protected")
    check unauthenticated.code.int == 401
    check unauthenticated.headers["WWW-Authenticate"] == """Bearer realm="sam-sync""""

    let malformed = client.request(
      baseUrl & "/protected",
      httpMethod = HttpGet,
      headers = newHttpHeaders({"Authorization": "Bearer"}),
    )
    check malformed.code.int == 400
    check malformed.headers["WWW-Authenticate"].len > 0
    check parseJson(malformed.body)["error"]["error"].getStr() == "invalid_request"

    let invalid = client.request(
      baseUrl & "/protected",
      httpMethod = HttpGet,
      headers =
        newHttpHeaders({"Authorization": "Bearer " & accessToken[0 .. ^2] & "x"}),
    )
    check invalid.code.int == 401
    check invalid.headers["WWW-Authenticate"].len > 0
    check parseJson(invalid.body)["error"]["error"].getStr() == "invalid_token"

    let authenticated = client.request(
      baseUrl & "/protected",
      httpMethod = HttpGet,
      headers = newHttpHeaders({"Authorization": "Bearer " & accessToken}),
    )
    check authenticated.code.int == 200
    check parseJson(authenticated.body)["status"].getStr() == "ok"

    let claimsResponse = client.request(
      baseUrl & "/claims",
      httpMethod = HttpGet,
      headers = newHttpHeaders({"Authorization": "Bearer " & accessToken}),
    )
    check claimsResponse.code.int == 200
    let claimsBody = parseJson(claimsResponse.body)
    check claimsBody["subject"].getStr() == "reader-service"
    check claimsBody["scopes"][0].getStr() == "sync:read"

  test "token endpoint and protected resource work together":
    randomize()
    let config = testConfig()

    var router: Router
    router.post("/oauth/token", oauth2TokenHandler(config))
    router.get("/claims", oauth2(claimsHandler, config, ["sync:read"]))

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

  test "token endpoint accepts json body without grant_type or scope":
    randomize()
    let config = testConfig()

    var router: Router
    router.post("/oauth/token", oauth2TokenHandler(config))
    router.get("/claims", oauth2(claimsHandler, config, {"sync": "read"}))

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
      headers = newHttpHeaders({"Content-Type": "application/json"}),
      body = """{"client_id":"reader-app","client_secret":"secret-reader"}""",
    )

    check tokenResponse.code.int == 200
    let tokenBody = parseJson(tokenResponse.body)
    check tokenBody["scope"].getStr() == "sync:read"

    let claimsResponse = client.request(
      baseUrl & "/claims",
      httpMethod = HttpGet,
      headers = newHttpHeaders(
        {"Authorization": "Bearer " & tokenBody["access_token"].getStr()}
      ),
    )
    check claimsResponse.code.int == 200
    let claimsBody = parseJson(claimsResponse.body)
    check claimsBody["subject"].getStr() == "reader-service"

  test "protected api routes return insufficient_scope for wrong scope":
    randomize()
    let config = testConfig()
    let tokenResponse = issueClientCredentialsToken(
      config,
      authorizationHeader = "Basic cmVhZGVyLWFwcDpzZWNyZXQtcmVhZGVy",
      contentType = "application/x-www-form-urlencoded",
      requestBody = "grant_type=client_credentials&scope=sync%3Aread",
    )
    check tokenResponse.ok

    var router: Router
    router.get("/write-only", oauth2(okHandler, config, ["sync:write"]))

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
      "http://127.0.0.1:" & $portNumber & "/write-only",
      httpMethod = HttpGet,
      headers = newHttpHeaders(
        {"Authorization": "Bearer " & tokenResponse.response.accessToken}
      ),
    )

    check response.code.int == 403
    check response.headers["WWW-Authenticate"].len > 0
    let body = parseJson(response.body)
    check body["error"]["error"].getStr() == "insufficient_scope"
