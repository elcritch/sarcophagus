import std/[httpclient, json, net, options, random, strutils, unittest]

import mummy

import sarcophagus/core/jwt_bearer_tokens
import sarcophagus/tapis
import sarcophagus/security/[browser_login, password_login]

type
  ServerThreadArgs = object
    server: Server
    port: Port
    address: string

  LoginBody = object
    username*: string
    password*: string

  LoginOut = object
    ok*: bool
    subject*: string

  MeOut = object
    subject*: string
    displayName*: string
    scopeCount*: int

proc serveServer(args: ServerThreadArgs) {.thread.} =
  args.server.serve(args.port, address = args.address)

randomize()
var nextTestPort = 24000 + rand(20000)

proc allocateTestPort(): Port =
  result = Port(nextTestPort)
  inc nextTestPort
  if nextTestPort > 60000:
    nextTestPort = 24000

proc testTokenConfig(): BearerTokenConfig =
  initBearerTokenConfig(
    issuer = "browser-login-tests",
    audience = "browser-login-tests",
    keys = [SigningKey(kid: "v1", secret: "browser-login-secret")],
  )

proc testLoginConfig(): PasswordLoginConfig =
  initPasswordLoginConfig(testTokenConfig(), sessionTtlSeconds = 900)

proc testCookieConfig(): BrowserLoginCookieConfig =
  initBrowserLoginCookieConfig("app_session", secure = false)

proc verifyBrowserUser(username, password: string): Option[PasswordLoginUser] =
  if username == "alice" and password == "correct horse battery staple":
    return some(
      initPasswordLoginUser(
        subject = "user-123",
        username = "alice",
        displayName = "Alice Example",
        scopes = ["items:read"],
      )
    )
  none(PasswordLoginUser)

proc loadBrowserUser(session: PasswordLoginSession): Option[PasswordLoginUser] =
  if session.subject == "user-123":
    return some(
      initPasswordLoginUser(
        subject = session.subject,
        username = "alice",
        displayName = "Alice Example",
        scopes = session.scopes,
      )
    )
  none(PasswordLoginUser)

proc loadMissingBrowserUser(session: PasswordLoginSession): Option[PasswordLoginUser] =
  discard session
  none(PasswordLoginUser)

proc login(body: LoginBody): ApiResponse[LoginOut] {.gcsafe.} =
  let loginResult = authenticateBrowserLogin(
    testLoginConfig(),
    testCookieConfig(),
    verifyBrowserUser,
    body.username,
    body.password,
  )
  browserLoginResponse(
    loginResult,
    LoginOut(ok: true, subject: loginResult.login.user.subject),
    statusCode = 200,
  )

proc me(): MeOut {.gcsafe.} =
  let user = requireBrowserLoginUser()
  let session = requireBrowserLoginSession()
  MeOut(
    subject: user.subject, displayName: user.displayName, scopeCount: session.scopes.len
  )

proc meHelper(): MeOut {.gcsafe.} =
  let user = loadCurrentBrowserLoginUser(loadBrowserUser)
  if user.isNone():
    raiseApiError(401, "Not logged in", "not_logged_in")
  let session = requireBrowserLoginSession()
  MeOut(
    subject: user.get().subject,
    displayName: user.get().displayName,
    scopeCount: session.scopes.len,
  )

proc logout(): ApiResponse[LoginOut] {.gcsafe.} =
  browserLogoutResponse(
    testCookieConfig(), LoginOut(ok: true, subject: ""), statusCode = 200
  )

proc buildBrowserLoginApi(): ApiRouter =
  let api = initApiRouter("Browser Login Test API", "1.0.0")
  api.post("/login", login, summary = "Login")
  api.get(
    "/me",
    me,
    summary = "Current browser user",
    middlewares = [
      browserLoginMiddleware(
        testLoginConfig(),
        testCookieConfig(),
        required = true,
        loadUser = loadBrowserUser,
      )
    ],
  )
  api.get(
    "/me-helper",
    meHelper,
    summary = "Current browser user via helper",
    middlewares =
      [browserLoginMiddleware(testLoginConfig(), testCookieConfig(), required = true)],
  )
  api.get(
    "/me-missing-user",
    me,
    summary = "Missing browser user",
    middlewares = [
      browserLoginMiddleware(
        testLoginConfig(),
        testCookieConfig(),
        required = true,
        loadUser = loadMissingBrowserUser,
      )
    ],
  )
  api.post("/logout", logout, summary = "Logout")
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

proc cookieFromSetCookie(setCookie: string): string =
  let semi = setCookie.find(';')
  if semi < 0:
    setCookie
  else:
    setCookie[0 ..< semi]

proc portFromBaseUrl(baseUrl: string): Port =
  let colon = baseUrl.rfind(':')
  Port(parseInt(baseUrl[colon + 1 .. ^1]))

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

suite "tapis browser login":
  test "issues login cookie and loads current user":
    withApiServer(buildBrowserLoginApi()) do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let loginResponse = client.request(
        baseUrl & "/login",
        httpMethod = HttpPost,
        headers = newHttpHeaders({"Content-Type": "application/json"}),
        body = """{"username":"alice","password":"correct horse battery staple"}""",
      )
      check loginResponse.code.int == 200
      let setCookie = loginResponse.headers["Set-Cookie"]
      check setCookie.startsWith("app_session=")

      let rawLogin = readRawHttpResponse(
        portFromBaseUrl(baseUrl),
        "POST /login HTTP/1.1\r\n" & "Host: 127.0.0.1\r\n" &
          "Content-Type: application/json\r\n" & "Content-Length: 62\r\n" &
          "Connection: close\r\n\r\n" &
          """{"username":"alice","password":"correct horse battery staple"}""",
      )
      let rawSetCookie = responseHeader(rawLogin, "Set-Cookie")
      check rawSetCookie.startsWith("app_session=")
      check rawSetCookie.contains("HttpOnly")
      check rawSetCookie.contains("Max-Age=900")

      let meResponse = client.request(
        baseUrl & "/me",
        httpMethod = HttpGet,
        headers = newHttpHeaders({"Cookie": cookieFromSetCookie(setCookie)}),
      )
      check meResponse.code.int == 200
      let meBody = parseJson(meResponse.body)
      check meBody["subject"].getStr() == "user-123"
      check meBody["displayName"].getStr() == "Alice Example"
      check meBody["scopeCount"].getInt() == 1

      let helperResponse = client.request(
        baseUrl & "/me-helper",
        httpMethod = HttpGet,
        headers = newHttpHeaders({"Cookie": cookieFromSetCookie(setCookie)}),
      )
      check helperResponse.code.int == 200
      let helperBody = parseJson(helperResponse.body)
      check helperBody["subject"].getStr() == "user-123"
      check helperBody["displayName"].getStr() == "Alice Example"

      let missingUserResponse = client.request(
        baseUrl & "/me-missing-user",
        httpMethod = HttpGet,
        headers = newHttpHeaders({"Cookie": cookieFromSetCookie(setCookie)}),
      )
      check missingUserResponse.code.int == 401
      let missingUserBody = parseJson(missingUserResponse.body)
      check missingUserBody["error"]["code"].getStr() == "not_logged_in"

  test "clears cookie on logout":
    withApiServer(buildBrowserLoginApi()) do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let logoutResponse = client.request(baseUrl & "/logout", httpMethod = HttpPost)
      check logoutResponse.code.int == 200
      let setCookie = logoutResponse.headers["Set-Cookie"]
      check setCookie.startsWith("app_session=")

      let rawLogout = readRawHttpResponse(
        portFromBaseUrl(baseUrl),
        "POST /logout HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
      )
      let rawSetCookie = responseHeader(rawLogout, "Set-Cookie")
      check rawSetCookie.startsWith("app_session=")
      check rawSetCookie.contains("Max-Age=0")
      check rawSetCookie.contains("Expires=Thu, 01 Jan 1970 00:00:00 GMT")

  test "required middleware rejects missing or invalid session":
    withApiServer(buildBrowserLoginApi()) do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let missingResponse = client.request(baseUrl & "/me", httpMethod = HttpGet)
      check missingResponse.code.int == 401
      let missingBody = parseJson(missingResponse.body)
      check missingBody["error"]["code"].getStr() == "not_logged_in"

      let invalidResponse = client.request(
        baseUrl & "/me",
        httpMethod = HttpGet,
        headers = newHttpHeaders({"Cookie": "app_session=not-a-real-token"}),
      )
      check invalidResponse.code.int == 401
      let invalidBody = parseJson(invalidResponse.body)
      check invalidBody["error"]["code"].getStr() == "invalid_token"
      let cleared = invalidResponse.headers["Set-Cookie"]
      check cleared.startsWith("app_session=")

      let rawInvalid = readRawHttpResponse(
        portFromBaseUrl(baseUrl),
        "GET /me HTTP/1.1\r\n" & "Host: 127.0.0.1\r\n" &
          "Cookie: app_session=not-a-real-token\r\n" & "Connection: close\r\n\r\n",
      )
      let rawSetCookie = responseHeader(rawInvalid, "Set-Cookie")
      check rawSetCookie.startsWith("app_session=")
      check rawSetCookie.contains("Max-Age=0")
