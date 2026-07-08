import std/[httpclient, json, os, osproc, sequtils, strformat, strutils]

proc repoRoot(): string =
  currentSourcePath.parentDir().parentDir().parentDir()

proc compileServer(repoDir: string, serverBinary: string) =
  let serverSource = repoDir / "examples" / "supabase_auth" / "server.nim"
  let compileResult = execCmdEx(
    "nim c -o:" & quoteShell(serverBinary) & " " & quoteShell(serverSource),
    options = {poUsePath, poStdErrToStdOut},
  )
  if compileResult.exitCode != 0:
    echo compileResult.output
    quit("failed to compile examples/supabase_auth/server.nim", QuitFailure)

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

  quit("Supabase Auth example server did not become ready", QuitFailure)

proc printResponse(label: string, response: Response) =
  echo ""
  echo "== ", label
  echo "status: ", response.code.int
  if response.headers.hasKey("Content-Type"):
    echo "content-type: ", response.headers["Content-Type"]
  if response.headers.hasKey("WWW-Authenticate"):
    echo "www-authenticate: ", response.headers["WWW-Authenticate"]
  echo "body: ", response.body

proc bearerGet(client: HttpClient, url, token: string): Response =
  client.request(
    url,
    httpMethod = HttpGet,
    headers = newHttpHeaders({"Authorization": "Bearer " & token}),
  )

proc main() =
  let repoDir = repoRoot()
  let serverBinary = repoDir / "examples" / "supabase_auth" / "server_bin"
  let port = 9084
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

  echo "Supabase Auth example runner talking to ", baseUrl

  let health = client.get(baseUrl & "/health")
  printResponse("public health route", health)

  let unauthenticatedReports = client.get(baseUrl & "/reports")
  printResponse("protected reports without bearer token", unauthenticatedReports)

  let unauthenticatedWhoami = client.get(baseUrl & "/whoami")
  printResponse("protected claims route without bearer token", unauthenticatedWhoami)

  let accessToken = getEnv("SUPABASE_ACCESS_TOKEN").strip()
  if accessToken.len > 0:
    let reports = bearerGet(client, baseUrl & "/reports", accessToken)
    printResponse("reports with Supabase access token", reports)

    let whoami = bearerGet(client, baseUrl & "/whoami", accessToken)
    printResponse("claims with Supabase access token", whoami)
  else:
    echo ""
    echo "Set SUPABASE_PROJECT_URL and SUPABASE_ACCESS_TOKEN to exercise authenticated calls."

  let swagger = client.get(baseUrl & "/swagger.json")
  let spec = parseJson(swagger.body)
  echo ""
  echo "== openapi"
  echo "title: ", spec["info"]["title"].getStr()
  echo "paths: ", spec["paths"].keys().toSeq().join(", ")
  echo "security schemes: ",
    spec["components"]["securitySchemes"].keys().toSeq().join(", ")
  echo "reports security: ", $spec["paths"]["/reports"]["get"]["security"]

when isMainModule:
  main()
