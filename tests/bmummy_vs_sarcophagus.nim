import
  std/
    [httpclient, monotimes, options, os, parseutils, random, strformat, strutils, times]

import mummy
import mummy/routers

import sarcophagus/tapis

type
  ServerThreadArgs = object
    server: Server
    port: Port
    address: string

  BenchItem = object
    id*: int
    name*: string
    verbose*: bool

proc serveServer(args: ServerThreadArgs) {.thread.} =
  args.server.serve(args.port, address = args.address)

proc elapsedSeconds(start: MonoTime): float =
  (getMonoTime() - start).inNanoseconds().float / 1_000_000_000.0

proc nsPerOp(seconds: float, rounds: int): float =
  seconds * 1_000_000_000'f64 / float(rounds)

proc opsPerSecond(seconds: float, rounds: int): float =
  float(rounds) / seconds

proc report(label: string, rounds: int, seconds: float) =
  echo &"{label:<24} {rounds:>8} req  {seconds:>8.4f} s  " &
    &"{nsPerOp(seconds, rounds):>12.0f} ns/op  {opsPerSecond(seconds, rounds):>10.2f} req/s"

proc parseRounds(): int =
  result = 10_000
  if paramCount() == 0:
    return

  var parsed: int
  if parseInt(paramStr(1), parsed) == paramStr(1).len and parsed > 0:
    result = parsed
  else:
    raise newException(ValueError, "rounds must be a positive integer")

proc mummyReadItem(request: Request) {.gcsafe.} =
  let
    id = parseInt(request.pathParams["id"])
    verbose = request.queryParams.getOrDefault("verbose", "false") == "true"
    name = "item-" & $id
    body = &"""{{"id":{id},"name":"{name}","verbose":{verbose}}}"""

  var headers: mummy.HttpHeaders
  headers["Content-Type"] = jsonContentType
  request.respond(200, headers, body)

proc sarcophagusReadItem(id: int, verbose: Option[bool]): BenchItem {.gcsafe.} =
  BenchItem(id: id, name: "item-" & $id, verbose: verbose.get(false))

proc buildMummyRouter(): Router =
  result.get("/items/@id", mummyReadItem)

proc buildSarcophagusRouter(): Router =
  let api = initApiRouter("Benchmark API", "1.0.0")
  api.get("/items/@id", sarcophagusReadItem)
  api.router

proc withServer(router: Router, body: proc(baseUrl: string) {.gcsafe.}) =
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

proc benchClient(label, baseUrl: string, rounds: int) =
  var client = newHttpClient(timeout = 30_000)
  defer:
    client.close()

  let url = baseUrl & "/items/42?verbose=true"
  var totalLen = 0
  discard client.getContent(url)

  let started = getMonoTime()
  for _ in 0 ..< rounds:
    totalLen += client.getContent(url).len
  report(label, rounds, elapsedSeconds(started))
  doAssert totalLen > 0

when isMainModule:
  randomize()
  let rounds = parseRounds()

  echo "Mummy vs Sarcophagus benchmark"
  echo "Nim: ", NimVersion
  echo "Rounds: ", rounds
  echo ""
  echo "Route                     Rounds      Time        ns/op       req/s"
  echo "--------------------------------------------------------------------"

  withServer(buildMummyRouter()) do(baseUrl: string):
    benchClient("mummy router", baseUrl, rounds)

  withServer(buildSarcophagusRouter()) do(baseUrl: string):
    benchClient("sarcophagus tapis", baseUrl, rounds)
