import std/[httpclient, json, random, unittest]

import mummy
import mummy/routers

import sarcophagus/[bearer_auth, core/jwt_bearer_tokens]

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

proc okHandler(request: Request) {.gcsafe.} =
  request.respondJson(200, %*{"status": "ok"})

proc claimsHandler(request: Request, claims: BearerTokenClaims) {.gcsafe.} =
  request.respondJson(200, %*{"subject": claims.subject, "scopes": claims.scopes})

proc customAuthError(failure: TokenValidationFailure): BearerAuthApiError {.gcsafe.} =
  apiResponse(
    BearerAuthErrorResponse(
      status: "custom-error",
      error: BearerAuthFailurePayload(code: failure.code, message: failure.message),
    ),
    statusCode = 499,
  )

suite "mummy bearer auth":
  test "macro and proc forms both protect routes and pass claims through":
    randomize()
    let config = initBearerTokenConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = [SigningKey(kid: "v1", secret: "secret-a")],
    )
    let readToken = mintBearerToken(
      config,
      initBearerTokenSpec(
        subject = "client-1", scopes = ["sync:read"], ttlSeconds = 600
      ),
    )
    let writeOnlyToken = mintBearerToken(
      config,
      initBearerTokenSpec(
        subject = "client-2", scopes = ["sync:write"], ttlSeconds = 600
      ),
    )

    var router: Router
    router.get("/ok", okHandler)
    withBearerTokAuth(config, ["sync:read"]):
      router.get("/macro/protected", okHandler)
      router.get("/macro/claims", claimsHandler)
    router.get("/proc/protected", bearerTokAuth(okHandler, config, ["sync:read"]))
    router.get("/proc/claims", bearerTokAuth(claimsHandler, config, ["sync:read"]))

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

    var readHeaders = newHttpHeaders({"Authorization": "Bearer " & readToken})
    var writeHeaders = newHttpHeaders({"Authorization": "Bearer " & writeOnlyToken})

    for path in ["/macro/protected", "/proc/protected"]:
      let unauthenticated = client.get(baseUrl & path)
      check unauthenticated.code.int == 401
      let unauthBody = parseJson(unauthenticated.body)
      check unauthBody["error"]["code"].getStr() == "missing_token"

      let authenticated =
        client.request(baseUrl & path, httpMethod = HttpGet, headers = readHeaders)
      check authenticated.code.int == 200

      let outOfScope =
        client.request(baseUrl & path, httpMethod = HttpGet, headers = writeHeaders)
      check outOfScope.code.int == 403
      let outOfScopeBody = parseJson(outOfScope.body)
      check outOfScopeBody["error"]["code"].getStr() == "insufficient_scope"

    for path in ["/macro/claims", "/proc/claims"]:
      let claimsResponse =
        client.request(baseUrl & path, httpMethod = HttpGet, headers = readHeaders)
      check claimsResponse.code.int == 200
      let claimsBody = parseJson(claimsResponse.body)
      check claimsBody["subject"].getStr() == "client-1"
      check claimsBody["scopes"][0].getStr() == "sync:read"

  test "protected routes accept typed error responders":
    randomize()
    let config = initBearerTokenConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = [SigningKey(kid: "v1", secret: "secret-a")],
    )

    var router: Router
    router.get(
      "/protected",
      bearerTokAuth(okHandler, config, ["sync:read"], onError = customAuthError),
    )

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

    let response = client.get("http://127.0.0.1:" & $portNumber & "/protected")

    check response.code.int == 499
    let body = parseJson(response.body)
    check body["status"].getStr() == "custom-error"
    check body["error"]["code"].getStr() == "missing_token"
