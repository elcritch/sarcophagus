import std/[httpclient, json, options, random, strutils, unittest]

import mummy
import mummy/routers

import sarcophagus/[core/jwt_bearer_tokens, core/typed_api, oauth2, core/oauth2]

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

proc typedStatusHandler(request: Request): ApiResponse[JsonNode] {.gcsafe.} =
  apiResponse(%*{"status": "typed", "path": request.path}, statusCode = 202)

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

proc userLoginConfig(): OAuth2Config =
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
        clientId = "browser-client",
        clientSecret = "",
        subject = "browser-client",
        allowedScopes = ["sync:read", "sync:write"],
        defaultScopes = ["sync:read"],
        redirectUris = ["http://client.example/callback"],
        requirePkce = true,
      )
    ],
    accessTokenTtlSeconds = 900,
  )

proc saveCallback(
    store: InMemoryOAuth2AuthorizationCodeStore
): OAuth2AuthorizationCodeSaver =
  result = proc(authorizationCode: OAuth2AuthorizationCode) {.gcsafe.} =
    store.save(authorizationCode)

proc consumeCallback(
    store: InMemoryOAuth2AuthorizationCodeStore
): OAuth2AuthorizationCodeConsumer =
  result = proc(code: string): Option[OAuth2AuthorizationCode] {.gcsafe.} =
    store.consume(code)

proc currentUser(request: Request): Option[OAuth2User] {.gcsafe.} =
  discard request
  some(OAuth2User(subject: "user-123", scopes: @["sync:read"]))

proc codeFromLocation(location: string): string =
  let marker = "code="
  let start = location.find(marker)
  if start < 0:
    return ""
  let valueStart = start + marker.len
  let nextParam = location.find("&", valueStart)
  if nextParam < 0:
    result = location[valueStart .. ^1]
  else:
    result = location[valueStart ..< nextParam]

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
    router.registerOAuth2(config)
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

  test "typed mummy handler shim calls request-aware typed handlers":
    randomize()

    var router: Router
    router.get("/typed-status", typedMummyHandler(typedStatusHandler))

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

    let response = client.get("http://127.0.0.1:" & $portNumber & "/typed-status")
    check response.code.int == 202
    check response.headers["Content-Type"] == jsonContentType
    let body = parseJson(response.body)
    check body["status"].getStr() == "typed"
    check body["path"].getStr() == "/typed-status"

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

  test "authorization-code endpoints issue user tokens for api routes":
    randomize()
    let config = userLoginConfig()
    let store = newInMemoryOAuth2AuthorizationCodeStore()
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"

    var router: Router
    router.registerOAuth2AuthorizationCode(
      config,
      store.saveCallback(),
      store.consumeCallback(),
      currentUser,
      loginUrl = "/login",
    )
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

    var client = newHttpClient(maxRedirects = 0, timeout = 5_000)
    defer:
      client.close()

    let baseUrl = "http://127.0.0.1:" & $portNumber
    let authorize = client.get(
      baseUrl & "/oauth/authorize?response_type=code&client_id=browser-client" &
        "&redirect_uri=http%3A%2F%2Fclient.example%2Fcallback&scope=sync%3Aread" &
        "&state=state-1&code_challenge=" & pkceS256Challenge(verifier) &
        "&code_challenge_method=S256"
    )
    check authorize.code.int == 302
    let location = authorize.headers["Location"]
    check location.startsWith("http://client.example/callback?")
    check location.find("state=state-1") >= 0
    let code = location.codeFromLocation()
    check code.len > 0

    let tokenResponse = client.request(
      baseUrl & "/oauth/token",
      httpMethod = HttpPost,
      headers = newHttpHeaders({"Content-Type": "application/x-www-form-urlencoded"}),
      body =
        "grant_type=authorization_code&client_id=browser-client&code=" & code &
        "&redirect_uri=http%3A%2F%2Fclient.example%2Fcallback" & "&code_verifier=" &
        verifier,
    )
    check tokenResponse.code.int == 200
    let tokenBody = parseJson(tokenResponse.body)

    let claimsResponse = client.request(
      baseUrl & "/claims",
      httpMethod = HttpGet,
      headers = newHttpHeaders(
        {"Authorization": "Bearer " & tokenBody["access_token"].getStr()}
      ),
    )
    check claimsResponse.code.int == 200
    check parseJson(claimsResponse.body)["subject"].getStr() == "user-123"
