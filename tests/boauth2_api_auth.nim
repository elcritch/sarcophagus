import
  std/[
    httpclient, httpcore, json, monotimes, options, os, parseutils, random, strformat,
    times,
  ]

import mummy
import mummy/routers

import sarcophagus/[core/jwt_bearer_tokens, oauth2/core, oauth2, oauth2/hashed_clients]

type ServerThreadArgs = object
  server: Server
  port: Port
  address: string

type BenchCase = object
  name: string
  tokenPath: string
  clientId: string
  policy: SecretHashPolicy
  rounds: int

proc serveServer(args: ServerThreadArgs) {.thread.} =
  args.server.serve(args.port, address = args.address)

proc elapsedSeconds(start: MonoTime): float =
  (getMonoTime() - start).inNanoseconds().float / 1_000_000_000.0

proc nsPerOp(seconds: float, rounds: int): float =
  seconds * 1_000_000_000'f64 / float(rounds)

proc opsPerSecond(seconds: float, rounds: int): float =
  float(rounds) / seconds

proc report(label: string, rounds: int, seconds: float) =
  echo &"{label:<30} {rounds:>8} req  {seconds:>8.4f} s  " &
    &"{nsPerOp(seconds, rounds):>12.0f} ns/op  {opsPerSecond(seconds, rounds):>10.2f} req/s"

proc parseRounds(defaultRounds: int): int =
  result = defaultRounds
  if paramCount() == 0:
    return

  var parsed: int
  if parseInt(paramStr(1), parsed) == paramStr(1).len and parsed > 0:
    result = parsed
  else:
    raise newException(ValueError, "rounds must be a positive integer")

proc pbkdf2Policy(iterations: int): SecretHashPolicy =
  SecretHashPolicy(
    algorithm: secretHashPbkdf2Sha256,
    prefix: SecretHashPrefix,
    iterations: iterations,
    minIterations: min(iterations, SecretHashMinIterations),
    maxIterations: SecretHashMaxIterations,
    saltBytes: SecretHashSaltBytes,
  )

proc respondJson(request: Request, statusCode: int, body: string) =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "application/json; charset=utf-8"
  request.respond(statusCode, headers, body)

proc okHandler(request: Request) {.gcsafe.} =
  request.respondJson(200, """{"status":"ok"}""")

proc loadCallback(store: InMemoryHashedOAuth2ClientStore): HashedOAuth2ClientLoader =
  result = proc(clientId: string): Option[HashedOAuth2Client] {.gcsafe.} =
    {.cast(gcsafe).}:
      store.load(clientId)

proc upsertCallback(
    store: InMemoryHashedOAuth2ClientStore
): proc(client: HashedOAuth2Client) {.gcsafe.} =
  result = proc(client: HashedOAuth2Client) {.gcsafe.} =
    {.cast(gcsafe).}:
      store.upsert(client)

proc testConfig(): OAuth2Config =
  let tokenConfig = initBearerTokenConfig(
    issuer = "oauth2-benchmark",
    audience = "oauth2-benchmark-api",
    keys = [SigningKey(kid: "v1", secret: "benchmark-secret")],
  )

  initOAuth2Config(
    realm = "oauth2-benchmark",
    tokenConfig = tokenConfig,
    clients = [],
    accessTokenTtlSeconds = 900,
  )

proc buildRouter(
    config: OAuth2Config,
    store: InMemoryHashedOAuth2ClientStore,
    cases: openArray[BenchCase],
): Router =
  result.get("/no-auth", okHandler)
  result.get("/protected", oauth2(okHandler, config, ["sync:read"]))
  for benchCase in cases:
    result.registerHashedOAuth2(
      config,
      store.loadCallback(),
      tokenPath = benchCase.tokenPath,
      policy = benchCase.policy,
    )

proc withServer(router: Router, body: proc(baseUrl: string)) =
  let
    server = newServer(router, workerThreads = 1)
    portNumber = 20000 + rand(20000)
    args =
      ServerThreadArgs(server: server, port: Port(portNumber), address: "127.0.0.1")

  var serverThread: Thread[ServerThreadArgs]
  createThread(serverThread, serveServer, args)
  defer:
    server.close()
    joinThread(serverThread)

  server.waitUntilReady()
  body("http://127.0.0.1:" & $portNumber)

proc tokenRequestBody(clientId: string): string =
  &"""{{"client_id":"{clientId}","client_secret":"secret-reader"}}"""

proc issueAccessToken(baseUrl, tokenPath, clientId: string): string =
  var client = newHttpClient(timeout = 30_000)
  defer:
    client.close()

  let response = client.request(
    baseUrl & tokenPath,
    httpMethod = HttpPost,
    headers = newHttpHeaders({"Content-Type": "application/json"}),
    body = tokenRequestBody(clientId),
  )
  doAssert response.code.int == 200
  parseJson(response.body)["access_token"].getStr()

proc benchGet(label, url: string, headers: httpcore.HttpHeaders, rounds: int) =
  var client = newHttpClient(timeout = 30_000)
  defer:
    client.close()

  var totalLen = 0
  discard client.request(url, httpMethod = HttpGet, headers = headers)

  let started = getMonoTime()
  for _ in 0 ..< rounds:
    let response = client.request(url, httpMethod = HttpGet, headers = headers)
    doAssert response.code.int == 200
    totalLen += response.body.len
  report(label, rounds, elapsedSeconds(started))
  doAssert totalLen > 0

proc benchTokenIssue(label, url, clientId: string, rounds: int) =
  var client = newHttpClient(timeout = 30_000)
  defer:
    client.close()

  let
    headers = newHttpHeaders({"Content-Type": "application/json"})
    body = tokenRequestBody(clientId)

  var totalLen = 0
  discard client.request(url, httpMethod = HttpPost, headers = headers, body = body)

  let started = getMonoTime()
  for _ in 0 ..< rounds:
    let response =
      client.request(url, httpMethod = HttpPost, headers = headers, body = body)
    doAssert response.code.int == 200
    totalLen += response.body.len
  report(label, rounds, elapsedSeconds(started))
  doAssert totalLen > 0

when isMainModule:
  randomize()
  let
    resourceRounds = parseRounds(10_000)
    config = testConfig()
    store = newInMemoryHashedOAuth2ClientStore()
    cases = [
      BenchCase(
        name: "oauth2 token pbkdf2 120k",
        tokenPath: "/oauth/token-pbkdf2-120k",
        clientId: "reader-pbkdf2-120k",
        policy: pbkdf2Policy(SecretHashMinIterations),
        rounds: 10,
      ),
      BenchCase(
        name: "oauth2 token pbkdf2 600k",
        tokenPath: "/oauth/token-pbkdf2-600k",
        clientId: "reader-pbkdf2-600k",
        policy: defaultSecretHashPolicy(),
        rounds: 3,
      ),
      BenchCase(
        name: "oauth2 token pbkdf2 2m",
        tokenPath: "/oauth/token-pbkdf2-2m",
        clientId: "reader-pbkdf2-2m",
        policy: pbkdf2Policy(SecretHashMaxIterations),
        rounds: 1,
      ),
      BenchCase(
        name: "oauth2 token hmac fast",
        tokenPath: "/oauth/token-hmac-fast",
        clientId: "reader-hmac-fast",
        policy: fastSecretHashPolicy(),
        rounds: resourceRounds,
      ),
    ]

  for benchCase in cases:
    discard seedHashedOAuth2Client(
      store.upsertCallback(),
      clientId = benchCase.clientId,
      clientSecret = "secret-reader",
      scopes = ["sync:read"],
      defaultScopes = ["sync:read"],
      subject = "reader-service",
      policy = benchCase.policy,
    )

  echo "OAuth2 API auth benchmark"
  echo "Nim: ", NimVersion
  echo "Resource rounds: ", resourceRounds
  echo ""
  echo "Operation                         Rounds      Time        ns/op       req/s"
  echo "----------------------------------------------------------------------------"

  withServer(buildRouter(config, store, cases)) do(baseUrl: string):
    let
      accessToken =
        issueAccessToken(baseUrl, "/oauth/token-hmac-fast", "reader-hmac-fast")
      noAuthHeaders = newHttpHeaders()
      authHeaders = newHttpHeaders({"Authorization": "Bearer " & accessToken})

    benchGet("no auth endpoint", baseUrl & "/no-auth", noAuthHeaders, resourceRounds)
    benchGet(
      "oauth2 bearer endpoint", baseUrl & "/protected", authHeaders, resourceRounds
    )

    for benchCase in cases:
      benchTokenIssue(
        benchCase.name,
        baseUrl & benchCase.tokenPath,
        benchCase.clientId,
        benchCase.rounds,
      )
