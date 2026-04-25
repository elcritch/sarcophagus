import std/[httpclient, json, options, random, unittest]

import mummy

import sarcophagus/[core/jwt_bearer_tokens, core/oauth2, tapis]

type
  ServerThreadArgs = object
    server: Server
    port: Port
    address: string

  ItemOut = object
    id*: int
    name*: string
    verbose*: bool

proc serveServer(args: ServerThreadArgs) {.thread.} =
  args.server.serve(args.port, address = args.address)

proc testConfig(): OAuth2Config =
  let tokenConfig = initBearerTokenConfig(
    issuer = "tapis-test-server",
    audience = "tapis-test-api",
    keys = [SigningKey(kid: "v1", secret: "secret-a")],
  )

  initOAuth2Config(
    realm = "tapis-test",
    tokenConfig = tokenConfig,
    clients = [
      initOAuth2Client(
        clientId = "reader-app",
        clientSecret = "secret-reader",
        subject = "reader-service",
        allowedScopes = ["items:read", "items:write"],
        defaultScopes = ["items:read"],
      )
    ],
    accessTokenTtlSeconds = 900,
  )

proc issueToken(config: OAuth2Config, scope: string): string =
  let token = issueClientCredentialsToken(
    config,
    authorizationHeader = "Basic cmVhZGVyLWFwcDpzZWNyZXQtcmVhZGVy",
    contentType = "application/x-www-form-urlencoded",
    requestBody = "grant_type=client_credentials&scope=" & scope,
  )
  doAssert token.ok
  token.response.accessToken

proc readItem(id: int, verbose: Option[bool]): ItemOut {.gcsafe.} =
  ItemOut(id: id, name: "secure-" & $id, verbose: verbose.get(false))

proc readAddedItem(
    id: int
): ItemOut {.tapi(get, "/added-items/@id", summary = "Read added item").} =
  ItemOut(id: id, name: "added-" & $id, verbose: false)

proc buildApi(config: OAuth2Config): ApiRouter =
  let readSecurity = oauth2(config, ["items:read"])
  let api = initApiRouter("TAPIS Security Test API", "1.0.0")
  api.get(
    "/secure-items/@id",
    readItem,
    summary = "Read secure item",
    tags = ["items"],
    security = readSecurity,
  )
  api.add(readAddedItem, security = readSecurity)
  api.mountOpenApi()
  api

proc withTestServer(
    body: proc(baseUrl: string, readToken, writeToken: string) {.gcsafe.}
) =
  randomize()
  let config = testConfig()
  let api = buildApi(config)
  let server = newServer(api.router, workerThreads = 1)
  let portNumber = 20000 + rand(20000)
  let args =
    ServerThreadArgs(server: server, port: Port(portNumber), address: "127.0.0.1")

  var serverThread: Thread[ServerThreadArgs]
  createThread(serverThread, serveServer, args)
  defer:
    server.close()
    joinThread(serverThread)

  server.waitUntilReady()
  body(
    "http://127.0.0.1:" & $portNumber,
    issueToken(config, "items:read"),
    issueToken(config, "items:write"),
  )

suite "typed mummy tapis security":
  test "protects direct typed routes with oauth2 security":
    withTestServer do(baseUrl: string, readToken, writeToken: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let unauthenticated = client.get(baseUrl & "/secure-items/7")
      check unauthenticated.code.int == 401
      check unauthenticated.headers["WWW-Authenticate"] ==
        """Bearer realm="tapis-test""""

      let outOfScope = client.request(
        baseUrl & "/secure-items/7",
        httpMethod = HttpGet,
        headers = newHttpHeaders({"Authorization": "Bearer " & writeToken}),
      )
      check outOfScope.code.int == 403
      check parseJson(outOfScope.body)["error"]["error"].getStr() == "insufficient_scope"

      let authenticated = client.request(
        baseUrl & "/secure-items/7?verbose=true",
        httpMethod = HttpGet,
        headers = newHttpHeaders({"Authorization": "Bearer " & readToken}),
      )
      check authenticated.code.int == 200

      let body = parseJson(authenticated.body)
      check body["id"].getInt() == 7
      check body["name"].getStr() == "secure-7"
      check body["verbose"].getBool() == true

  test "protects api.add pragma routes with oauth2 security":
    withTestServer do(baseUrl: string, readToken, writeToken: string):
      discard writeToken
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let unauthenticated = client.get(baseUrl & "/added-items/8")
      check unauthenticated.code.int == 401

      let authenticated = client.request(
        baseUrl & "/added-items/8",
        httpMethod = HttpGet,
        headers = newHttpHeaders({"Authorization": "Bearer " & readToken}),
      )
      check authenticated.code.int == 200

      let body = parseJson(authenticated.body)
      check body["id"].getInt() == 8
      check body["name"].getStr() == "added-8"

  test "emits oauth2 security metadata in openapi":
    withTestServer do(baseUrl: string, readToken, writeToken: string):
      discard readToken
      discard writeToken
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.get(baseUrl & "/swagger.json")
      check response.code.int == 200

      let spec = parseJson(response.body)
      let scheme = spec["components"]["securitySchemes"]["oauth2"]
      check scheme["type"].getStr() == "oauth2"
      check scheme["flows"]["clientCredentials"]["tokenUrl"].getStr() == "/oauth/token"
      check scheme["flows"]["clientCredentials"]["scopes"].hasKey("items:read")

      let operation = spec["paths"]["/secure-items/{id}"]["get"]
      check operation["security"][0]["oauth2"][0].getStr() == "items:read"
