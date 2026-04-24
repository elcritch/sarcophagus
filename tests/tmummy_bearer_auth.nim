import std/[httpclient, json, random, unittest]

import mummy
import mummy/routers

import sarcophagus/[bearer_tokens, mummy_bearer_auth]

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

suite "mummy bearer auth":
  test "middleware protects routes and passes claims through":
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

    let unauthenticated = client.get(baseUrl & "/protected")
    check unauthenticated.code.int == 401
    let unauthBody = parseJson(unauthenticated.body)
    check unauthBody["error"]["code"].getStr() == "missing_token"

    var readHeaders = newHttpHeaders({"Authorization": "Bearer " & readToken})
    let authenticated = client.request(
      baseUrl & "/protected", httpMethod = HttpGet, headers = readHeaders
    )
    check authenticated.code.int == 200

    let claimsResponse =
      client.request(baseUrl & "/claims", httpMethod = HttpGet, headers = readHeaders)
    check claimsResponse.code.int == 200
    let claimsBody = parseJson(claimsResponse.body)
    check claimsBody["subject"].getStr() == "client-1"
    check claimsBody["scopes"][0].getStr() == "sync:read"

    var writeHeaders = newHttpHeaders({"Authorization": "Bearer " & writeOnlyToken})
    let outOfScope = client.request(
      baseUrl & "/protected", httpMethod = HttpGet, headers = writeHeaders
    )
    check outOfScope.code.int == 403
    let outOfScopeBody = parseJson(outOfScope.body)
    check outOfScopeBody["error"]["code"].getStr() == "insufficient_scope"
