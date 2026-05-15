import std/[httpclient, json, net, options, random, strutils, times, unittest]

import mummy

import sarcophagus/tapis
import sarcophagus/cookies

type
  ServerThreadArgs = object
    server: Server
    port: Port
    address: string

  CookieEcho = object
    theme*: string
    count*: int
    session*: string

  LoginOut = object
    ok*: bool

proc testSessionConfig(): SessionCookieConfig =
  initSessionCookieConfig("sid", "session-secret", ttlSeconds = 600, secure = false)

randomize()
var nextTestPort = 22000 + rand(20000)

proc allocateTestPort(): Port =
  result = Port(nextTestPort)
  inc nextTestPort
  if nextTestPort > 60000:
    nextTestPort = 22000

proc serveServer(args: ServerThreadArgs) {.thread.} =
  args.server.serve(args.port, address = args.address)

proc cookieEcho(request: Request): CookieEcho {.gcsafe.} =
  let sessionConfig = testSessionConfig()
  let session = request.requestSessionValue(sessionConfig)
  CookieEcho(
    theme: request.parseRequestCookieValue("theme", string),
    count: request.parseRequestCookieValue("count", int),
    session:
      if session.isSome():
        session.get()
      else:
        "",
  )

proc login(): ApiResponse[LoginOut] {.gcsafe.} =
  let sessionConfig = testSessionConfig()
  apiResponse(
    LoginOut(ok: true),
    headers = @[sessionCookieHeader("user-123", sessionConfig, fromUnix(1_700_000_000))],
  )

proc buildApi(): ApiRouter =
  let api = initApiRouter("Cookie Test API", "1.0.0")
  api.get("/cookie-echo", cookieEcho, summary = "Echo cookie values")
  api.get("/login", login, summary = "Issue a session cookie")
  api

proc withTestServer(body: proc(baseUrl: string) {.gcsafe.}) =
  let api = buildApi()
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

proc cookieFromSetCookie(setCookie: string): string =
  let semi = setCookie.find(';')
  if semi < 0:
    setCookie
  else:
    setCookie[0 ..< semi]

suite "tapis cookies":
  test "parses typed cookies from requests":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.request(
        baseUrl & "/cookie-echo",
        httpMethod = HttpGet,
        headers = newHttpHeaders({"Cookie": "theme=moss; count=7; sid=ignored"}),
      )
      check response.code.int == 200
      let body = parseJson(response.body)
      check body["theme"].getStr() == "moss"
      check body["count"].getInt() == 7
      check body["session"].getStr() == ""

  test "issues and verifies signed session cookies":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let loginResponse = client.get(baseUrl & "/login")
      check loginResponse.code.int == 200
      let setCookie = loginResponse.headers["Set-Cookie"]
      check setCookie.startsWith("sid=")

      let response = client.request(
        baseUrl & "/cookie-echo",
        httpMethod = HttpGet,
        headers = newHttpHeaders(
          {"Cookie": "theme=fern; count=9; " & cookieFromSetCookie(setCookie)}
        ),
      )
      check response.code.int == 200
      let body = parseJson(response.body)
      check body["theme"].getStr() == "fern"
      check body["count"].getInt() == 9
      check body["session"].getStr() == "user-123"
