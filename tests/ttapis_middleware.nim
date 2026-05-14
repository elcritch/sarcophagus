import std/[httpclient, locks, net, options, random, strutils, unittest]

import mummy

import sarcophagus/tapis

type
  ServerThreadArgs = object
    server: Server
    port: Port
    address: string

  ItemOut = object
    id*: int
    name*: string
    verbose*: bool

  ItemBody = object
    name*: string

  RequestIdentityOut = object
    requestId*: string
    traceparent*: string

var middlewareEventsLock: Lock
var middlewareEventCount: int
var middlewareEvents: array[16, int]

initLock(middlewareEventsLock)

proc serveServer(args: ServerThreadArgs) {.thread.} =
  args.server.serve(args.port, address = args.address)

randomize()
var nextTestPort = 20000 + rand(20000)

proc allocateTestPort(): Port =
  result = Port(nextTestPort)
  inc nextTestPort
  if nextTestPort > 60000:
    nextTestPort = 20000

proc resetMiddlewareEvents() =
  withLock middlewareEventsLock:
    middlewareEventCount = 0

proc eventCode(event: string): int =
  case event
  of "before:outer": 1
  of "before:inner": 2
  of "after:inner": 3
  of "after:outer": 4
  else: 0

proc eventName(code: int): string =
  case code
  of 1: "before:outer"
  of 2: "before:inner"
  of 3: "after:inner"
  of 4: "after:outer"
  else: ""

proc recordMiddlewareEvent(event: string) {.gcsafe.} =
  withLock middlewareEventsLock:
    if middlewareEventCount < middlewareEvents.len:
      middlewareEvents[middlewareEventCount] = eventCode(event)
      inc middlewareEventCount

proc snapshotMiddlewareEvents(): seq[string] =
  withLock middlewareEventsLock:
    for index in 0 ..< middlewareEventCount:
      result.add(eventName(middlewareEvents[index]))

proc getFlatItem(id: int, verbose: Option[bool]): ItemOut {.gcsafe.} =
  ItemOut(id: id, name: "flat-" & $id, verbose: verbose.get(false))

proc createItem(body: ItemBody): ItemOut {.gcsafe.} =
  ItemOut(id: 1, name: body.name, verbose: false)

proc getRequestIdentity(): RequestIdentityOut {.gcsafe.} =
  RequestIdentityOut(requestId: currentRequestId(), traceparent: currentTraceparent())

proc namedMiddleware(name, headerName: string): ApiMiddleware =
  result.name = name
  result.before = proc(context: RouteContext): ApiMiddlewareResult {.gcsafe.} =
    recordMiddlewareEvent("before:" & name)
    context.setResponseHeader(headerName, "1")
    amContinue
  result.after = proc(context: RouteContext) {.gcsafe.} =
    discard context
    recordMiddlewareEvent("after:" & name)

proc buildMiddlewareApi(): ApiRouter =
  let api = initApiRouter("Middleware Test API", "1.0.0")
  withMiddleware(api, namedMiddleware("outer", "X-Middleware-Outer")):
    api.get(
      "/middleware-items/@id",
      getFlatItem,
      summary = "Get middleware item",
      middlewares = [namedMiddleware("inner", "X-Middleware-Inner")],
    )
  api

proc buildCorsApi(): ApiRouter =
  let api = initApiRouter("Cors Test API", "1.0.0")
  api.useCors(
    corsConfig(
      allowedOrigins = ["https://app.example"],
      allowedHeaders = ["Authorization", "Content-Type"],
      exposedHeaders = ["X-Request-ID"],
      allowCredentials = true,
      maxAgeSeconds = 600,
    )
  )
  api.get("/cors-items/@id", getFlatItem, summary = "Get cors item")
  api.post("/cors-items", createItem, summary = "Create cors item")
  api

proc buildRequestIdentityApi(): ApiRouter =
  let api = initApiRouter("Request Identity Test API", "1.0.0")
  api.useRequestIdentity()
  api.get("/request-identity", getRequestIdentity, summary = "Get request identity")
  api

proc withApiServer(api: ApiRouter, body: proc(baseUrl: string) {.gcsafe.}) =
  let server = newServer(api.router, workerThreads = 1)
  let port = allocateTestPort()
  let args = ServerThreadArgs(server: server, port: port, address: "127.0.0.1")

  var serverThread: Thread[ServerThreadArgs]
  createThread(serverThread, serveServer, args)
  defer:
    server.close()
    joinThread(serverThread)

  server.waitUntilReady()
  body("http://127.0.0.1:" & $port)

proc readRawHttpResponse(port: Port, request: string): string =
  var socket = newSocket()
  defer:
    socket.close()
  socket.connect("127.0.0.1", port)
  socket.send(request)
  while true:
    let chunk = socket.recv(4096)
    if chunk.len == 0:
      break
    result.add(chunk)

proc responseHeader(raw, name: string): string =
  let headerEnd = raw.find("\r\n\r\n")
  if headerEnd < 0:
    return ""
  for line in raw[0 ..< headerEnd].split("\r\n"):
    let colon = line.find(':')
    if colon > 0 and cmpIgnoreCase(line[0 ..< colon], name) == 0:
      return line[colon + 1 .. ^1].strip()

proc responseBody(raw: string): string =
  let headerEnd = raw.find("\r\n\r\n")
  if headerEnd >= 0:
    raw[headerEnd + 4 .. ^1]
  else:
    ""

proc portFromBaseUrl(baseUrl: string): Port =
  Port(parseInt(baseUrl.rsplit(":", 1)[1]))

suite "tapis middleware and cors":
  test "runs middleware hooks around typed routes":
    withApiServer(buildMiddlewareApi()) do(baseUrl: string):
      resetMiddlewareEvents()
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.get(baseUrl & "/middleware-items/14?verbose=true")
      check response.code.int == 200
      check response.headers["X-Middleware-Outer"] == "1"
      check response.headers["X-Middleware-Inner"] == "1"
      check snapshotMiddlewareEvents() ==
        @["before:outer", "before:inner", "after:inner", "after:outer"]

  test "adds cors headers on normal requests":
    withApiServer(buildCorsApi()) do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.request(
        baseUrl & "/cors-items/15",
        httpMethod = HttpGet,
        headers = newHttpHeaders({"Origin": "https://app.example"}),
      )
      check response.code.int == 200
      check response.headers["Access-Control-Allow-Origin"] == "https://app.example"
      check response.headers["Access-Control-Allow-Credentials"] == "true"
      check response.headers["Access-Control-Expose-Headers"] == "X-Request-ID"
      check response.headers["Vary"].contains("Origin")

  test "handles cors preflight automatically":
    withApiServer(buildCorsApi()) do(baseUrl: string):
      let port = portFromBaseUrl(baseUrl)
      let raw = readRawHttpResponse(
        port,
        "OPTIONS /cors-items HTTP/1.1\r\n" & "Host: 127.0.0.1\r\n" &
          "Origin: https://app.example\r\n" & "Access-Control-Request-Method: POST\r\n" &
          "Access-Control-Request-Headers: Authorization, Content-Type\r\n" &
          "Connection: close\r\n\r\n",
      )

      check raw.startsWith("HTTP/1.1 204")
      check responseHeader(raw, "Access-Control-Allow-Origin") == "https://app.example"
      check responseHeader(raw, "Access-Control-Allow-Credentials") == "true"
      check responseHeader(raw, "Access-Control-Allow-Methods").contains("POST")
      check responseHeader(raw, "Access-Control-Allow-Headers") ==
        "Authorization, Content-Type"
      check responseHeader(raw, "Access-Control-Max-Age") == "600"
      check responseHeader(raw, "Vary").contains("Origin")
      check responseBody(raw) == ""

  test "rejects disallowed cors preflight origins":
    withApiServer(buildCorsApi()) do(baseUrl: string):
      let port = portFromBaseUrl(baseUrl)
      let raw = readRawHttpResponse(
        port,
        "OPTIONS /cors-items HTTP/1.1\r\n" & "Host: 127.0.0.1\r\n" &
          "Origin: https://evil.example\r\n" & "Access-Control-Request-Method: POST\r\n" &
          "Connection: close\r\n\r\n",
      )

      check raw.startsWith("HTTP/1.1 403")

  test "propagates incoming x-request-id headers":
    withApiServer(buildRequestIdentityApi()) do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.request(
        baseUrl & "/request-identity",
        httpMethod = HttpGet,
        headers = newHttpHeaders({"X-Request-ID": "req-123"}),
      )
      check response.code.int == 200
      check response.headers["X-Request-ID"] == "req-123"
      check response.body.contains("\"requestId\":\"req-123\"")
      check response.body.contains("\"traceparent\":\"\"")

  test "derives request ids from traceparent and echoes trace headers":
    withApiServer(buildRequestIdentityApi()) do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
      let response = client.request(
        baseUrl & "/request-identity",
        httpMethod = HttpGet,
        headers = newHttpHeaders({"traceparent": traceparent}),
      )
      check response.code.int == 200
      check response.headers["traceparent"] == traceparent
      check response.headers["X-Request-ID"] == "4bf92f3577b34da6a3ce929d0e0e4736"
      check response.body.contains("\"requestId\":\"4bf92f3577b34da6a3ce929d0e0e4736\"")
      check response.body.contains("\"traceparent\":\"" & traceparent & "\"")

  test "generates request ids when the request does not provide one":
    withApiServer(buildRequestIdentityApi()) do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.get(baseUrl & "/request-identity")
      check response.code.int == 200
      let requestId = response.headers["X-Request-ID"]
      check requestId.len == 32
      check response.body.contains("\"requestId\":\"" & requestId & "\"")
