import std/[httpclient, json, options, random, strutils, tables, unittest]

import mummy
import mummy/routers

import sarcophagus/[core/jwt_bearer_tokens, oauth2/core, oauth2/hashed_clients, tapis]

type ServerThreadArgs = object
  server: Server
  port: Port
  address: string

proc serveServer(args: ServerThreadArgs) {.thread.} =
  args.server.serve(args.port, address = args.address)

proc testConfig(): OAuth2Config =
  let tokenConfig = initBearerTokenConfig(
    issuer = "hashed-client-test",
    audience = "hashed-client-api",
    keys = [SigningKey(kid: "v1", secret: "secret-a")],
  )

  initOAuth2Config(
    realm = "hashed-clients",
    tokenConfig = tokenConfig,
    clients = [],
    accessTokenTtlSeconds = 900,
  )

proc upsertCallback(
    store: InMemoryHashedOAuth2ClientStore
): proc(client: HashedOAuth2Client) {.gcsafe.} =
  result = proc(client: HashedOAuth2Client) {.gcsafe.} =
    {.cast(gcsafe).}:
      store.upsert(client)

proc loadCallback(store: InMemoryHashedOAuth2ClientStore): HashedOAuth2ClientLoader =
  result = proc(clientId: string): Option[HashedOAuth2Client] {.gcsafe.} =
    {.cast(gcsafe).}:
      store.load(clientId)

proc auditCallback(store: InMemoryHashedOAuth2ClientStore): HashedOAuth2AuditProc =
  result = proc(event: HashedOAuth2AuditEvent) {.gcsafe.} =
    {.cast(gcsafe).}:
      store.audit(event)

suite "hashed oauth2 clients":
  test "seeds hashed clients and issues tokens":
    let config = testConfig()
    let store = newInMemoryHashedOAuth2ClientStore()
    let credentials = seedHashedOAuth2Client(
      store.upsertCallback(),
      clientId = "reader-app",
      clientSecret = "secret-reader",
      scopes = ["sync:read", "sync:write"],
      defaultScopes = ["sync:read"],
      subject = "reader-service",
    )

    check credentials.clientId == "reader-app"
    check credentials.clientSecret == "secret-reader"
    check store.clients["reader-app"].secretHash != "secret-reader"

    let result = issueHashedClientCredentialsToken(
      config,
      store.loadCallback(),
      authorizationHeader = "",
      contentType = "application/json",
      requestBody = """{"client_id":"reader-app","client_secret":"secret-reader"}""",
      onAudit = store.auditCallback(),
      now = 1_700_000_000,
    )

    check result.ok
    check result.response.tokenType == "Bearer"
    check result.response.scope == "sync:read"
    check store.auditEvents.len == 1
    check store.auditEvents[0].eventType == "token_minted"
    check store.auditEvents[0].clientId == "reader-app"

    let validation = validateOAuth2BearerToken(
      config,
      "Bearer " & result.response.accessToken,
      ["sync:read"],
      now = 1_700_000_010,
    )
    check validation.ok
    check validation.claims.subject == "reader-service"

  test "seeds fast hashed clients and verifies legacy pbkdf2 clients":
    let config = testConfig()
    let fastPolicy = fastSecretHashPolicy()
    let store = newInMemoryHashedOAuth2ClientStore()
    discard seedHashedOAuth2Client(
      store.upsertCallback(),
      clientId = "fast-reader",
      clientSecret = "secret-reader",
      scopes = ["sync:read"],
      policy = fastPolicy,
    )
    discard seedHashedOAuth2Client(
      store.upsertCallback(),
      clientId = "legacy-reader",
      clientSecret = "secret-reader",
      scopes = ["sync:read"],
    )

    check store.clients["fast-reader"].secretHash.startsWith(FastSecretHashPrefix & "$")
    check store.clients["legacy-reader"].secretHash.startsWith(SecretHashPrefix & "$")

    let fastResult = issueHashedClientCredentialsToken(
      config,
      store.loadCallback(),
      authorizationHeader = "",
      contentType = "application/json",
      requestBody = """{"client_id":"fast-reader","client_secret":"secret-reader"}""",
      policy = fastPolicy,
    )
    check fastResult.ok

    let legacyResult = issueHashedClientCredentialsToken(
      config,
      store.loadCallback(),
      authorizationHeader = "",
      contentType = "application/json",
      requestBody = """{"client_id":"legacy-reader","client_secret":"secret-reader"}""",
      policy = fastPolicy,
    )
    check legacyResult.ok

  test "rejects disabled clients and bad secrets":
    let config = testConfig()
    let store = newInMemoryHashedOAuth2ClientStore()
    discard seedHashedOAuth2Client(
      store.upsertCallback(),
      clientId = "disabled-app",
      clientSecret = "secret-reader",
      scopes = ["sync:read"],
      enabled = false,
    )

    let disabled = issueHashedClientCredentialsToken(
      config,
      store.loadCallback(),
      authorizationHeader = "",
      contentType = "application/json",
      requestBody = """{"client_id":"disabled-app","client_secret":"secret-reader"}""",
      onAudit = store.auditCallback(),
    )
    check not disabled.ok
    check disabled.failure.statusCode == 401
    check store.auditEvents[^1].reason == "disabled_client"

    store.clients["disabled-app"].enabled = true
    let badSecret = issueHashedClientCredentialsToken(
      config,
      store.loadCallback(),
      authorizationHeader = "",
      contentType = "application/json",
      requestBody = """{"client_id":"disabled-app","client_secret":"wrong"}""",
      onAudit = store.auditCallback(),
    )
    check not badSecret.ok
    check badSecret.failure.statusCode == 401
    check store.auditEvents[^1].reason == "invalid_client"

    let unknown = issueHashedClientCredentialsToken(
      config,
      store.loadCallback(),
      authorizationHeader = "",
      contentType = "application/json",
      requestBody = """{"client_id":"unknown-app","client_secret":"wrong"}""",
      onAudit = store.auditCallback(),
    )
    check not unknown.ok
    check unknown.failure.statusCode == 401
    check unknown.failure.error == "invalid_client"
    check store.auditEvents[^1].reason == "unknown_client"

  test "mummy token handler issues tokens from hashed client store":
    randomize()
    let config = testConfig()
    let store = newInMemoryHashedOAuth2ClientStore()
    discard seedHashedOAuth2Client(
      store.upsertCallback(),
      clientId = "reader-app",
      clientSecret = "secret-reader",
      scopes = ["sync:read"],
    )

    var router: Router
    router.registerHashedOAuth2(
      config, store.loadCallback(), onAudit = store.auditCallback()
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

    let response = client.request(
      "http://127.0.0.1:" & $portNumber & "/oauth/token",
      httpMethod = HttpPost,
      headers = newHttpHeaders({"Content-Type": "application/json"}),
      body = """{"client_id":"reader-app","client_secret":"secret-reader"}""",
    )

    check response.code.int == 200
    check response.headers["Cache-Control"] == "no-store"
    check response.headers["Pragma"] == "no-cache"
    check parseJson(response.body)["token_type"].getStr() == "Bearer"
    check store.auditEvents.len == 1

  test "typed api router token handler issues tokens from hashed client store":
    randomize()
    let config = testConfig()
    let store = newInMemoryHashedOAuth2ClientStore()
    discard seedHashedOAuth2Client(
      store.upsertCallback(),
      clientId = "typed-reader-app",
      clientSecret = "secret-reader",
      scopes = ["sync:read"],
    )

    let api = initApiRouter("Hashed OAuth2 Typed Test API", "1.0.0")
    api.registerHashedOAuth2(
      config,
      store.loadCallback(),
      tokenPath = "/typed/oauth/token",
      onAudit = store.auditCallback(),
    )

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

    var client = newHttpClient(timeout = 5_000)
    defer:
      client.close()

    let response = client.request(
      "http://127.0.0.1:" & $portNumber & "/typed/oauth/token",
      httpMethod = HttpPost,
      headers = newHttpHeaders({"Content-Type": "application/json"}),
      body = """{"client_id":"typed-reader-app","client_secret":"secret-reader"}""",
    )

    check response.code.int == 200
    check response.headers["Cache-Control"] == "no-store"
    check response.headers["Pragma"] == "no-cache"
    check parseJson(response.body)["token_type"].getStr() == "Bearer"
    check store.auditEvents.len == 1
