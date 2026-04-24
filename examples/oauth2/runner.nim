import std/[base64, httpclient, json, os, osproc, strformat, strutils]

proc repoRoot(): string =
  currentSourcePath.parentDir().parentDir().parentDir()

proc basicAuthHeader(clientId: string, clientSecret: string): string =
  "Basic " & encode(clientId & ":" & clientSecret)

proc compileServer(repoDir: string, serverBinary: string) =
  let serverSource = repoDir / "examples" / "oauth2" / "server.nim"
  let compileResult = execCmdEx(
    "nim c -o:" & quoteShell(serverBinary) & " " & quoteShell(serverSource),
    options = {poUsePath, poStdErrToStdOut},
  )
  if compileResult.exitCode != 0:
    echo compileResult.output
    quit("failed to compile examples/oauth2/server.nim", QuitFailure)

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

  quit("example server did not become ready", QuitFailure)

proc printResponse(label: string, response: Response) =
  echo ""
  echo "== ", label
  echo "status: ", response.code.int
  if response.headers.hasKey("WWW-Authenticate"):
    echo "www-authenticate: ", response.headers["WWW-Authenticate"]
  echo "body: ", response.body

proc requestToken(
    client: HttpClient,
    baseUrl: string,
    clientId: string,
    clientSecret: string,
    scope: string,
): Response =
  client.request(
    baseUrl & "/oauth/token",
    httpMethod = HttpPost,
    headers = newHttpHeaders(
      {
        "Authorization": basicAuthHeader(clientId, clientSecret),
        "Content-Type": "application/x-www-form-urlencoded",
      }
    ),
    body = "grant_type=client_credentials&scope=" & scope,
  )

proc main() =
  let repoDir = repoRoot()
  let serverBinary = repoDir / "examples" / "oauth2" / "server_bin"
  let port = 9081
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

  echo "OAuth2 example runner talking to ", baseUrl

  let badClient =
    requestToken(client, baseUrl, "reader-app", "wrong-secret", "sync%3Aread")
  printResponse("bad client credentials", badClient)

  let readerTokenResponse =
    requestToken(client, baseUrl, "reader-app", "reader-secret", "sync%3Aread")
  printResponse("reader token", readerTokenResponse)
  let readerToken = parseJson(readerTokenResponse.body)["access_token"].getStr()

  let writerTokenResponse = requestToken(
    client, baseUrl, "writer-app", "writer-secret", "sync%3Aread+sync%3Awrite"
  )
  printResponse("writer token", writerTokenResponse)
  let writerToken = parseJson(writerTokenResponse.body)["access_token"].getStr()

  let readerRead = client.request(
    baseUrl & "/api/read",
    httpMethod = HttpGet,
    headers = newHttpHeaders({"Authorization": "Bearer " & readerToken}),
  )
  printResponse("reader token -> read api", readerRead)

  let readerWhoAmI = client.request(
    baseUrl & "/api/whoami",
    httpMethod = HttpGet,
    headers = newHttpHeaders({"Authorization": "Bearer " & readerToken}),
  )
  printResponse("reader token -> whoami api", readerWhoAmI)

  let writerWrite = client.request(
    baseUrl & "/api/write",
    httpMethod = HttpGet,
    headers = newHttpHeaders({"Authorization": "Bearer " & writerToken}),
  )
  printResponse("writer token -> write api", writerWrite)

  let missingToken = client.get(baseUrl & "/api/read")
  printResponse("missing token -> read api", missingToken)

  let malformedBearer = client.request(
    baseUrl & "/api/read",
    httpMethod = HttpGet,
    headers = newHttpHeaders({"Authorization": "Bearer"}),
  )
  printResponse("malformed bearer header", malformedBearer)

  let readerWrite = client.request(
    baseUrl & "/api/write",
    httpMethod = HttpGet,
    headers = newHttpHeaders({"Authorization": "Bearer " & readerToken}),
  )
  printResponse("reader token -> write api", readerWrite)

  let writerAdmin = client.request(
    baseUrl & "/api/admin",
    httpMethod = HttpGet,
    headers = newHttpHeaders({"Authorization": "Bearer " & writerToken}),
  )
  printResponse("writer token -> admin api", writerAdmin)

when isMainModule:
  main()
