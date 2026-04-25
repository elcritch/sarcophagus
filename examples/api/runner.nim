import std/[httpclient, json, os, osproc, sequtils, strformat, strutils]

when defined(feature.sarcophagus.cbor):
  import cborious/cbor2json

proc repoRoot(): string =
  currentSourcePath.parentDir().parentDir().parentDir()

proc compileServer(repoDir: string, serverBinary: string) =
  let serverSource = repoDir / "examples" / "api" / "server.nim"
  let compileResult = execCmdEx(
    "nim c -o:" & quoteShell(serverBinary) & " " & quoteShell(serverSource),
    options = {poUsePath, poStdErrToStdOut},
  )
  if compileResult.exitCode != 0:
    echo compileResult.output
    quit("failed to compile examples/api/server.nim", QuitFailure)

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
  if response.headers.hasKey("Content-Type"):
    echo "content-type: ", response.headers["Content-Type"]
  if response.headers.hasKey("Location"):
    echo "location: ", response.headers["Location"]
  echo "body: ", response.body

when defined(feature.sarcophagus.cbor):
  proc printCborResponse(label: string, response: Response) =
    echo ""
    echo "== ", label
    echo "status: ", response.code.int
    if response.headers.hasKey("Content-Type"):
      echo "content-type: ", response.headers["Content-Type"]
    echo "body as json: ", $toJsonNode(response.body)

proc main() =
  let repoDir = repoRoot()
  let serverBinary = repoDir / "examples" / "api" / "server_bin"
  let port = 9082
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

  echo "Typed API example runner talking to ", baseUrl

  let health = client.get(baseUrl & "/health")
  printResponse("health", health)

  let pets = client.get(baseUrl & "/pets?limit=2&status=petAvailable")
  printResponse("list pets with typed query params", pets)

  let pet = client.get(baseUrl & "/pets/1")
  printResponse("get pet with typed path param", pet)

  let created = client.request(
    baseUrl & "/pets",
    httpMethod = HttpPost,
    headers = newHttpHeaders({"Content-Type": "application/json"}),
    body = """{"name":"Hopper","species":"rabbit","age":2}""",
  )
  printResponse("create pet from json body", created)

  let updated = client.request(
    baseUrl & "/pets/55",
    httpMethod = HttpPut,
    headers = newHttpHeaders({"Content-Type": "application/json"}),
    body = """{"name":"Turing","species":"turtle","age":99}""",
  )
  printResponse("update pet from path params plus json body", updated)

  let notFound = client.get(baseUrl & "/pets/404")
  printResponse("typed api error", notFound)

  let invalidParam = client.get(baseUrl & "/pets/not-an-int")
  printResponse("invalid path param", invalidParam)

  let broken = client.get(baseUrl & "/broken")
  printResponse("exception converted to api error", broken)

  let swagger = client.get(baseUrl & "/swagger.json")
  let spec = parseJson(swagger.body)
  echo ""
  echo "== openapi"
  echo "title: ", spec["info"]["title"].getStr()
  echo "paths: ", spec["paths"].keys().toSeq().join(", ")

  when defined(feature.sarcophagus.cbor):
    let cborPets = client.request(
      baseUrl & "/pets/1",
      httpMethod = HttpGet,
      headers = newHttpHeaders({"Accept": "application/cbor"}),
    )
    printCborResponse("cbor response negotiation", cborPets)

when isMainModule:
  main()
