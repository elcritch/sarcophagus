import std/[httpclient, json, os, osproc, sequtils, strformat, strutils]

proc repoRoot(): string =
  currentSourcePath.parentDir().parentDir().parentDir()

proc compileServer(repoDir: string, serverBinary: string) =
  let serverSource = repoDir / "examples" / "tapis_secure" / "server.nim"
  let compileResult = execCmdEx(
    "nim c -o:" & quoteShell(serverBinary) & " " & quoteShell(serverSource),
    options = {poUsePath, poStdErrToStdOut},
  )
  if compileResult.exitCode != 0:
    echo compileResult.output
    quit("failed to compile examples/tapis_secure/server.nim", QuitFailure)

proc waitUntilReady(baseUrl: string) =
  var client = newHttpClient(timeout = 500)
  defer:
    client.close()

  for attempt in 0 ..< 30:
    try:
      let response = client.get(baseUrl & "/health")
      if response.code.int == 200:
        return
    except CatchableError:
      discard
    sleep(200)

  quit("secure example server did not become ready", QuitFailure)

proc printResponse(label: string, response: Response) =
  echo ""
  echo "== ", label
  echo "status: ", response.code.int
  if response.headers.hasKey("Content-Type"):
    echo "content-type: ", response.headers["Content-Type"]
  if response.headers.hasKey("WWW-Authenticate"):
    echo "www-authenticate: ", response.headers["WWW-Authenticate"]
  echo "body: ", response.body

proc requestToken(client: HttpClient, baseUrl, scope: string): string =
  let response = client.request(
    baseUrl & "/oauth/token",
    httpMethod = HttpPost,
    headers = newHttpHeaders(
      {
        "Authorization": "Basic Z290by1jbGk6Z290by1zZWNyZXQ=",
        "Content-Type": "application/x-www-form-urlencoded",
      }
    ),
    body = "grant_type=client_credentials&scope=" & scope,
  )
  printResponse("oauth2 client credentials token for " & scope, response)
  if response.code.int != 200:
    quit("failed to issue token for scope " & scope, QuitFailure)

  parseJson(response.body)["access_token"].getStr()

proc authedGet(client: HttpClient, url, token: string): Response =
  client.request(
    url,
    httpMethod = HttpGet,
    headers = newHttpHeaders({"Authorization": "Bearer " & token}),
  )

proc main() =
  let repoDir = repoRoot()
  let serverBinary = repoDir / "examples" / "tapis_secure" / "server_bin"
  let port = 9083
  let baseUrl = fmt"http://127.0.0.1:{port}"

  compileServer(repoDir, serverBinary)
  defer:
    if fileExists(serverBinary):
      removeFile(serverBinary)

  let serverProc = startProcess(
    serverBinary,
    workingDir = repoDir,
    args = [$port],
    options = {poParentStreams, poStdErrToStdOut},
  )
  defer:
    if serverProc.running():
      terminate(serverProc)
      discard serverProc.waitForExit(3_000)
    serverProc.close()

  waitUntilReady(baseUrl)

  var client = newHttpClient(timeout = 5_000)
  defer:
    client.close()

  echo "TAPIS secure goto runner talking to ", baseUrl

  let health = client.get(baseUrl & "/health")
  printResponse("public health route", health)

  let resolved = client.get(baseUrl & "/go/docs?preview=true")
  printResponse("public goto resolver", resolved)

  let unauthenticated = client.get(baseUrl & "/admin/gotos")
  printResponse("scoped route without bearer token", unauthenticated)

  let readToken = requestToken(client, baseUrl, "goto%3Aread")
  let writeToken = requestToken(client, baseUrl, "goto%3Awrite")

  let protectedList = authedGet(client, baseUrl & "/admin/gotos?limit=2", readToken)
  printResponse("read-scoped admin list", protectedList)

  let outOfScope = authedGet(
    client,
    baseUrl & "/admin/gotos/new/save?url=https%3A%2F%2Fexample.test%2Fnotes",
    readToken,
  )
  printResponse("write route with read-only token", outOfScope)

  let saved = authedGet(
    client,
    baseUrl &
      "/admin/gotos/new/save?url=https%3A%2F%2Fexample.test%2Fnotes&title=Notes",
    writeToken,
  )
  printResponse("write-scoped save", saved)

  let deleted = authedGet(client, baseUrl & "/admin/gotos/new/delete", writeToken)
  printResponse("write-scoped delete", deleted)

  let broken = client.get(baseUrl & "/broken")
  printResponse("exception converted to tapis error", broken)

  let swagger = client.get(baseUrl & "/swagger.json")
  let spec = parseJson(swagger.body)
  echo ""
  echo "== openapi"
  echo "title: ", spec["info"]["title"].getStr()
  echo "paths: ", spec["paths"].keys().toSeq().join(", ")
  echo "security schemes: ",
    spec["components"]["securitySchemes"].keys().toSeq().join(", ")
  echo "admin list security: ", $spec["paths"]["/admin/gotos"]["get"]["security"]

when isMainModule:
  main()
