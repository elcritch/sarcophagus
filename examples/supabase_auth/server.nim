import std/[json, os, strutils]

import mummy
import mummy/routers

import sarcophagus/oauth2/mummy_support
import sarcophagus/security/supabase_jwt
import sarcophagus/tapis

const
  defaultProjectUrl = "https://project-ref.supabase.co"
  defaultRealm = "supabase-example"

type
  HealthResponse = object
    status*: string
    supabaseProjectUrl*: string

  Report = object
    id*: int
    title*: string
    status*: string

  ReportList = object
    items*: seq[Report]
    count*: int

  MessageResponse = object
    status*: string
    message*: string

proc configuredProjectUrl(): string =
  let projectUrl = getEnv("SUPABASE_PROJECT_URL").strip()
  if projectUrl.len > 0: projectUrl else: defaultProjectUrl

proc requiredUserScopes(): seq[string] =
  @[claimScope("role", "authenticated")]

proc seedReports(): seq[Report] {.gcsafe.} =
  @[
    Report(id: 101, title: "Quarterly usage", status: "ready"),
    Report(id: 102, title: "Retention cohort", status: "draft"),
    Report(id: 103, title: "Billing export", status: "ready"),
  ]

proc health(): HealthResponse {.
    gcsafe, tapi(get, "/health", summary = "Health check", tags = ["system"])
.} =
  HealthResponse(status: "ok", supabaseProjectUrl: configuredProjectUrl())

proc listReports(): ReportList {.
    gcsafe,
    tapi(
      get, "/reports", summary = "List reports for signed-in users", tags = ["reports"]
    )
.} =
  let items = seedReports()
  ReportList(items: items, count: items.len)

proc syncReports(): MessageResponse {.
    gcsafe,
    tapi(get, "/reports/sync", summary = "Trigger a protected sync", tags = ["reports"])
.} =
  MessageResponse(status: "ok", message: "report sync accepted")

proc respondJson(request: Request, statusCode: int, body: JsonNode) =
  var headers: HttpHeaders
  headers["Content-Type"] = "application/json; charset=utf-8"
  request.respond(statusCode, headers, $body)

proc whoami(request: Request, claims: BearerTokenClaims) {.gcsafe.} =
  request.respondJson(
    200,
    %*{
      "issuer": claims.issuer,
      "subject": claims.subject,
      "audience": claims.audience,
      "role": claims.role,
      "client_id": claims.clientId,
      "user_id": claims.userId,
      "scopes": claims.scopes,
      "key_id": claims.keyId,
    },
  )

proc parsePort(): Port =
  let rawPort =
    if paramCount() >= 1:
      paramStr(1)
    else:
      getEnv("SUPABASE_AUTH_EXAMPLE_PORT", "9084")

  try:
    Port(parseInt(rawPort))
  except ValueError:
    raise newException(ValueError, "invalid port: " & rawPort)

when isMainModule:
  let host = getEnv("SUPABASE_AUTH_EXAMPLE_HOST", "127.0.0.1")
  let port = parsePort()
  let projectUrl = configuredProjectUrl()
  let verifier = initSupabaseJwtVerifierConfig(projectUrl)
  let scopes = requiredUserScopes()
  let userSecurity =
    jwtBearer(verifier, scopes, schemeName = "supabaseJwt", realm = defaultRealm)

  var apiConfig = defaultApiConfig()
  apiConfig.includeStackTraces =
    getEnv("SUPABASE_AUTH_EXAMPLE_STACKTRACES", "") in ["1", "true", "yes"]

  let apiRouter = initApiRouter("Sarcophagus Supabase Auth Example", "1.0.0", apiConfig)
  apiRouter.add(health)
  withSecurity(apiRouter, userSecurity):
    apiRouter.add(listReports)
    apiRouter.add(syncReports)
  apiRouter.mountOpenApi()

  apiRouter.router.get(
    "/whoami", mummy_support.oauth2(whoami, verifier, scopes, realm = defaultRealm)
  )

  let server = newServer(apiRouter.router, workerThreads = 1)
  echo "Supabase Auth example listening on http://", host, ":", port.int
  echo "Supabase project URL: ", projectUrl
  echo "OpenAPI document: http://", host, ":", port.int, "/swagger.json"
  server.serve(port, address = host)
