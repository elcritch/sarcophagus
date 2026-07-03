import std/[json, options, os, strutils, tables]

import mummy
import mummy/routers

import sarcophagus
import sarcophagus/core/jwt_bearer_tokens

type
  LoginBody = object
    username*: string
    password*: string

  NoteBody = object
    message*: string

  SessionOut = object
    signedIn*: bool
    subject*: string
    username*: string
    displayName*: string
    scopes*: seq[string]
    notes*: seq[string]

  NoteOut = object
    status*: string
    subject*: string
    noteCount*: int
    latestNote*: string

var accounts = initTable[string, PasswordLoginAccount]()
var notesBySubject = initTable[string, seq[string]]()

proc loginConfig(): PasswordLoginConfig =
  initPasswordLoginConfig(
    initBearerTokenConfig(
      issuer = "karax-browser-login-example",
      audience = "browser-session",
      keys = [SigningKey(kid: "session-v1", secret: "dev-browser-session-secret")],
    ),
    sessionTtlSeconds = 1800,
  )

proc cookieConfig(): BrowserLoginCookieConfig =
  initBrowserLoginCookieConfig("karax_browser_session", secure = false)

proc seedAccounts() =
  if accounts.len > 0:
    return

  accounts["alice"] = seedPasswordLoginAccount(
    username = "alice",
    password = "correct horse battery staple",
    subject = "alice",
    displayName = "Alice Example",
    scopes = ["profile:read", "notes:write"],
  )
  accounts["bob"] = seedPasswordLoginAccount(
    username = "bob",
    password = "hunter2 hunter2",
    subject = "bob",
    displayName = "Bob Example",
    scopes = ["profile:read", "notes:write"],
  )

  notesBySubject["alice"] =
    @[
      "Rotate the on-call checklist before Friday.",
      "Move the browser session cookie to Secure in production.",
    ]
  notesBySubject["bob"] = @["Inspect the login audit trail output."]

proc loadAccount(username: string): Option[PasswordLoginAccount] {.gcsafe.} =
  {.cast(gcsafe).}:
    let key = username.strip()
    if key in accounts:
      return some(accounts[key])
  none(PasswordLoginAccount)

proc loadUser(session: PasswordLoginSession): Option[PasswordLoginUser] {.gcsafe.} =
  {.cast(gcsafe).}:
    if session.subject in accounts:
      return some(accounts[session.subject].toPasswordLoginUser())
  none(PasswordLoginUser)

proc notesFor(subject: string): seq[string] {.gcsafe.} =
  {.cast(gcsafe).}:
    result = notesBySubject.getOrDefault(subject)

proc appendNote(subject, message: string): int {.gcsafe.} =
  {.cast(gcsafe).}:
    var notes = notesBySubject.getOrDefault(subject)
    notes.add(message)
    notesBySubject[subject] = notes
    result = notes.len

proc sessionOutFor(user: PasswordLoginUser): SessionOut =
  let session = requireBrowserLoginSession()
  SessionOut(
    signedIn: true,
    subject: user.subject,
    username: user.username,
    displayName: user.displayName,
    scopes: session.scopes,
    notes: notesFor(user.subject),
  )

proc login(request: Request, body: LoginBody): ApiResponse[SessionOut] {.gcsafe.} =
  let verifier = passwordLoginVerifier(loadAccount)
  let loginResult = authenticateBrowserLogin(
    loginConfig(),
    cookieConfig(),
    verifier,
    body.username,
    body.password,
    context = passwordLoginContext(request),
  )
  browserLoginResponse(loginResult, sessionOutFor(loginResult.login.user))

proc logout(): ApiResponse[SessionOut] {.gcsafe.} =
  browserLogoutResponse(
    cookieConfig(),
    SessionOut(
      signedIn: false,
      subject: "",
      username: "",
      displayName: "",
      scopes: @[],
      notes: @[],
    ),
  )

proc sessionInfo(): SessionOut {.gcsafe.} =
  let user = loadCurrentBrowserLoginUser(loadUser)
  if user.isNone():
    return SessionOut(
      signedIn: false,
      subject: "",
      username: "",
      displayName: "",
      scopes: @[],
      notes: @[],
    )
  sessionOutFor(user.get())

proc profile(): SessionOut {.gcsafe.} =
  sessionOutFor(requireBrowserLoginUser())

proc saveNote(body: NoteBody): ApiResponse[NoteOut] {.gcsafe.} =
  let user = requireBrowserLoginUser()
  let message = body.message.strip()
  if message.len == 0:
    raiseApiError(400, "Note message must not be empty", "invalid_request")

  let noteCount = appendNote(user.subject, message)
  apiResponse(
    NoteOut(
      status: "saved", subject: user.subject, noteCount: noteCount, latestNote: message
    ),
    statusCode = 201,
  )

proc appHtml(): string =
  """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Karax Browser Login</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <main id="ROOT"></main>
  <script src="/app.js"></script>
</body>
</html>
"""

proc styles(): string =
  """
:root {
  --bg: #f5efe3;
  --ink: #1f2937;
  --muted: #5b6472;
  --panel: rgba(255, 252, 247, 0.86);
  --line: rgba(31, 41, 55, 0.14);
  --accent: #b45309;
  --accent-deep: #7c2d12;
  --good: #166534;
  --bad: #991b1b;
  --shadow: 0 18px 48px rgba(54, 31, 0, 0.12);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  color: var(--ink);
  background:
    radial-gradient(circle at top left, rgba(245, 158, 11, 0.18), transparent 28%),
    radial-gradient(circle at top right, rgba(180, 83, 9, 0.14), transparent 24%),
    linear-gradient(180deg, #fbf7ef 0%, var(--bg) 100%);
  font: 16px/1.5 "Avenir Next", "Trebuchet MS", "Segoe UI", sans-serif;
}
#ROOT {
  width: min(1080px, calc(100vw - 32px));
  margin: 0 auto;
  padding: 28px 0 40px;
}
.shell {
  display: grid;
  gap: 18px;
}
.hero, .panel {
  background: var(--panel);
  backdrop-filter: blur(10px);
  border: 1px solid var(--line);
  border-radius: 22px;
  box-shadow: var(--shadow);
}
.hero {
  padding: 28px;
}
.hero h1, .panel h2 {
  margin: 0 0 10px;
  font-family: Georgia, "Times New Roman", serif;
  letter-spacing: 0.01em;
}
.hero p, .panel p {
  margin: 0 0 10px;
  color: var(--muted);
}
.grid {
  display: grid;
  grid-template-columns: 1.1fr 0.9fr;
  gap: 18px;
}
.panel {
  padding: 22px;
}
.stack {
  display: grid;
  gap: 12px;
}
label {
  display: grid;
  gap: 6px;
  color: var(--ink);
  font-weight: 600;
}
input, textarea {
  width: 100%;
  border: 1px solid rgba(31, 41, 55, 0.18);
  border-radius: 14px;
  background: rgba(255, 255, 255, 0.88);
  color: var(--ink);
  padding: 12px 14px;
  font: inherit;
}
textarea {
  min-height: 110px;
  resize: vertical;
}
.row {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}
button {
  appearance: none;
  border: 0;
  border-radius: 999px;
  padding: 11px 16px;
  font: inherit;
  font-weight: 700;
  cursor: pointer;
  color: white;
  background: linear-gradient(135deg, var(--accent), var(--accent-deep));
  box-shadow: 0 8px 18px rgba(124, 45, 18, 0.22);
}
button.alt {
  color: var(--ink);
  background: rgba(255, 255, 255, 0.76);
  border: 1px solid rgba(31, 41, 55, 0.12);
  box-shadow: none;
}
.pill {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 5px 10px;
  font-size: 0.92rem;
  font-weight: 700;
  background: rgba(22, 101, 52, 0.10);
  color: var(--good);
}
.pill.off {
  background: rgba(153, 27, 27, 0.10);
  color: var(--bad);
}
.code, .error {
  margin: 0;
  border-radius: 16px;
  padding: 14px;
  font: 14px/1.45 ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.code {
  background: #20150d;
  color: #fde7cf;
}
.error {
  background: #fff1f2;
  color: var(--bad);
}
ul {
  margin: 0;
  padding-left: 20px;
}
li + li {
  margin-top: 8px;
}
@media (max-width: 860px) {
  .grid { grid-template-columns: 1fr; }
  #ROOT { width: min(100vw - 20px, 1080px); padding-top: 18px; }
  .hero, .panel { padding: 18px; }
}
"""

proc respondHtml(request: Request, statusCode: int, body: string) =
  var headers: HttpHeaders
  headers["Content-Type"] = "text/html; charset=utf-8"
  request.respond(statusCode, headers, body)

proc respondCss(request: Request, body: string) =
  var headers: HttpHeaders
  headers["Content-Type"] = "text/css; charset=utf-8"
  request.respond(200, headers, body)

proc respondJs(request: Request, body: string) =
  var headers: HttpHeaders
  headers["Content-Type"] = "application/javascript; charset=utf-8"
  request.respond(200, headers, body)

proc appHandler(request: Request) {.gcsafe.} =
  request.respondHtml(200, appHtml())

proc stylesHandler(request: Request) {.gcsafe.} =
  request.respondCss(styles())

proc appJsHandler(request: Request) {.gcsafe.} =
  let path = currentSourcePath.parentDir() / "public" / "app.js"
  if not fileExists(path):
    request.respondJs(
      "document.getElementById('ROOT').innerHTML = " &
        "'Compile the Karax client first: nim js -o:examples/karax_browser_login/public/app.js examples/karax_browser_login/client.nim';"
    )
    return
  request.respondJs(readFile(path))

when isMainModule:
  seedAccounts()

  let api = initApiRouter("Karax Browser Login Example", "1.0.0")
  api.post("/api/login", login, summary = "Create browser login session")
  api.post("/api/logout", logout, summary = "Clear browser login session")
  api.get(
    "/api/session",
    sessionInfo,
    summary = "Current browser session",
    middlewares =
      [browserLoginMiddleware(loginConfig(), cookieConfig(), loadUser = loadUser)],
  )
  api.get(
    "/api/profile",
    profile,
    summary = "Protected browser profile",
    middlewares = [
      browserLoginMiddleware(
        loginConfig(), cookieConfig(), required = true, loadUser = loadUser
      )
    ],
  )
  api.post(
    "/api/notes",
    saveNote,
    summary = "Protected note writer",
    responseStatus = 201,
    middlewares = [
      browserLoginMiddleware(
        loginConfig(), cookieConfig(), required = true, loadUser = loadUser
      )
    ],
  )
  api.mountOpenApi()

  api.router.get("/", appHandler)
  api.router.get("/styles.css", stylesHandler)
  api.router.get("/app.js", appJsHandler)

  let host = getEnv("KARAX_BROWSER_LOGIN_HOST", "127.0.0.1")
  let port = Port(parseInt(getEnv("KARAX_BROWSER_LOGIN_PORT", "9085")))
  echo "Karax browser login example listening on http://", host, ":", port.int
  echo "Compile the Karax client before opening the page; see README.md."
  newServer(api.router, workerThreads = 1).serve(port, address = host)
