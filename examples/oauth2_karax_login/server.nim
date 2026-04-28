import std/[json, options, os, strutils]

import mummy
import mummy/routers

import sarcophagus/[core/jwt_bearer_tokens, core/oauth2, oauth2]

type CurrentUser = object
  subject: string
  displayName: string
  scopes: seq[string]

let authorizationStore = newInMemoryOAuth2AuthorizationCodeStore()

proc respondJson(request: Request, statusCode: int, body: JsonNode) =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "application/json; charset=utf-8"
  request.respond(statusCode, headers, $body)

proc respondHtml(request: Request, statusCode: int, body: string) =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "text/html; charset=utf-8"
  request.respond(statusCode, headers, body)

proc respondCss(request: Request, body: string) =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "text/css; charset=utf-8"
  request.respond(200, headers, body)

proc respondJs(request: Request, body: string) =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "application/javascript; charset=utf-8"
  request.respond(200, headers, body)

proc redirect(request: Request, location: string, headers: mummy.HttpHeaders = @[]) =
  var responseHeaders = headers
  responseHeaders["Location"] = location
  request.respond(302, responseHeaders)

proc decodeHexNibble(ch: char): int =
  case ch
  of '0' .. '9':
    ord(ch) - ord('0')
  of 'a' .. 'f':
    10 + ord(ch) - ord('a')
  of 'A' .. 'F':
    10 + ord(ch) - ord('A')
  else:
    -1

proc decodeFormComponent(input: string): string =
  var index = 0
  while index < input.len:
    case input[index]
    of '+':
      result.add(' ')
    of '%':
      if index + 2 < input.len:
        let hi = decodeHexNibble(input[index + 1])
        let lo = decodeHexNibble(input[index + 2])
        if hi >= 0 and lo >= 0:
          result.add(char((hi shl 4) or lo))
          index += 2
    else:
      result.add(input[index])
    inc index

proc formValue(body, key: string): string =
  for pair in body.split('&'):
    let parts = pair.split('=', maxsplit = 1)
    if parts.len == 2 and decodeFormComponent(parts[0]) == key:
      return decodeFormComponent(parts[1])

proc safeNext(value: string): string =
  if value.startsWith("/") and not value.startsWith("//"): value else: "/"

proc htmlEscape(value: string): string =
  for ch in value:
    case ch
    of '&':
      result.add("&amp;")
    of '<':
      result.add("&lt;")
    of '>':
      result.add("&gt;")
    of '"':
      result.add("&quot;")
    else:
      result.add(ch)

proc cookieValue(request: Request, name: string): string =
  for part in request.headers["Cookie"].split(';'):
    let pieces = part.strip().split('=', maxsplit = 1)
    if pieces.len == 2 and pieces[0] == name:
      return pieces[1]

proc sessionConfig(): BearerTokenConfig =
  initBearerTokenConfig(
    issuer = "karax-login-example",
    audience = "browser-session",
    keys = [SigningKey(kid: "session-v1", secret: "dev-session-signing-key")],
  )

proc oauthConfig(): OAuth2Config =
  let tokenConfig = initBearerTokenConfig(
    issuer = "karax-login-example",
    audience = "karax-api",
    keys = [SigningKey(kid: "oauth-v1", secret: "dev-oauth-signing-key")],
  )

  initOAuth2Config(
    realm = "karax-login",
    tokenConfig = tokenConfig,
    clients = [
      initOAuth2Client(
        clientId = "karax-browser",
        clientSecret = "",
        subject = "karax-browser",
        allowedScopes = ["profile:read", "notes:write"],
        defaultScopes = ["profile:read"],
        redirectUris = ["http://127.0.0.1:9084/callback"],
        requirePkce = true,
      )
    ],
    accessTokenTtlSeconds = 900,
  )

proc userFromSubject(subject: string): CurrentUser =
  case subject
  of "alice":
    CurrentUser(
      subject: "alice",
      displayName: "Alice Example",
      scopes: @["profile:read", "notes:write"],
    )
  else:
    CurrentUser(subject: subject, displayName: subject, scopes: @["profile:read"])

proc currentUserFromRequest(request: Request): Option[OAuth2User] {.gcsafe.} =
  let sessionToken = request.cookieValue("karax_session")
  if sessionToken.len == 0:
    return none(OAuth2User)

  let validation = validateBearerToken(
    sessionConfig(), sessionToken, requiredScopes = ["session:login"]
  )
  if not validation.ok:
    return none(OAuth2User)

  let user = userFromSubject(validation.claims.subject)
  some(
    OAuth2User(
      subject: user.subject, displayName: user.displayName, scopes: user.scopes
    )
  )

proc appHtml(): string =
  """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Karax OAuth2 Login</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <main id="ROOT"></main>
  <script src="/app.js"></script>
</body>
</html>
"""

proc loginHtml(next: string): string =
  """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <main class="shell">
    <section class="panel login">
      <h1>Sign in</h1>
      <p>This page sets an HttpOnly browser session cookie. The Karax app still needs an OAuth2 bearer token for JSON APIs.</p>
      <form method="post" action="/login">
        <input type="hidden" name="next" value="$1">
        <button type="submit" name="user" value="alice">Sign in as Alice</button>
        <button type="submit" name="user" value="bob">Sign in as Bob</button>
      </form>
    </section>
  </main>
	</body>
	</html>
	""" %
    [htmlEscape(next)]

proc styles(): string =
  """
* { box-sizing: border-box; }
body {
  margin: 0;
  font: 16px/1.45 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #1f2933;
  background: #f6f8fb;
}
.shell {
  width: min(960px, calc(100vw - 32px));
  margin: 40px auto;
}
header { margin-bottom: 24px; }
h1, h2 { margin: 0 0 10px; }
p { margin: 0 0 14px; }
.grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}
.panel {
  background: white;
  border: 1px solid #d9e2ec;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 16px;
  box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
}
.login { max-width: 620px; }
button {
  appearance: none;
  border: 1px solid #1d4ed8;
  border-radius: 6px;
  background: #2563eb;
  color: white;
  padding: 9px 13px;
  margin: 0 8px 8px 0;
  font-weight: 650;
  cursor: pointer;
}
button:hover { background: #1d4ed8; }
pre {
  overflow: auto;
  min-height: 96px;
  padding: 12px;
  border-radius: 6px;
  background: #101828;
  color: #d1fadf;
}
.token {
  overflow-wrap: anywhere;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.error pre { color: #fecaca; }
@media (max-width: 720px) {
  .grid { grid-template-columns: 1fr; }
  .shell { margin: 20px auto; }
}
"""

proc healthHandler(request: Request) {.gcsafe.} =
  request.respondJson(200, %*{"status": "ok"})

proc appHandler(request: Request) {.gcsafe.} =
  request.respondHtml(200, appHtml())

proc stylesHandler(request: Request) {.gcsafe.} =
  request.respondCss(styles())

proc appJsHandler(request: Request) {.gcsafe.} =
  let path = currentSourcePath.parentDir() / "public" / "app.js"
  if not fileExists(path):
    request.respondJs(
      "document.getElementById('ROOT').innerHTML = " &
        "'Compile the Karax client first: nim js -o:examples/oauth2_karax_login/public/app.js examples/oauth2_karax_login/client.nim';"
    )
    return
  request.respondJs(readFile(path))

proc loginGetHandler(request: Request) {.gcsafe.} =
  let next =
    if request.queryParams["next"].len > 0:
      safeNext(request.queryParams["next"])
    else:
      "/"
  request.respondHtml(200, loginHtml(next))

proc loginPostHandler(request: Request) {.gcsafe.} =
  let requestedUser = request.body.formValue("user")
  let subject = if requestedUser in ["alice", "bob"]: requestedUser else: "alice"
  let next =
    if request.body.formValue("next").len > 0:
      safeNext(request.body.formValue("next"))
    else:
      "/"
  let token = mintBearerToken(
    sessionConfig(), initBearerTokenSpec(subject, ["session:login"], ttlSeconds = 3600)
  )
  var headers: mummy.HttpHeaders
  headers["Set-Cookie"] =
    "karax_session=" & token & "; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600"
  request.redirect(next, headers)

proc logoutHandler(request: Request) {.gcsafe.} =
  var headers: mummy.HttpHeaders
  headers["Set-Cookie"] = "karax_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
  request.redirect("/", headers)

proc profileHandler(request: Request, claims: BearerTokenClaims) {.gcsafe.} =
  let user = userFromSubject(claims.subject)
  request.respondJson(
    200,
    %*{
      "subject": user.subject,
      "displayName": user.displayName,
      "tokenScopes": claims.scopes,
      "message": "This JSON response required an OAuth2 bearer token.",
    },
  )

proc writeNoteHandler(request: Request, claims: BearerTokenClaims) {.gcsafe.} =
  request.respondJson(
    200,
    %*{
      "status": "saved",
      "subject": claims.subject,
      "body": parseJson(request.body),
      "message": "Write scope accepted.",
    },
  )

proc adminHandler(request: Request) {.gcsafe.} =
  request.respondJson(200, %*{"status": "admin access granted"})

proc saveCallback(): OAuth2AuthorizationCodeSaver =
  result = proc(authorizationCode: OAuth2AuthorizationCode) {.gcsafe.} =
    {.cast(gcsafe).}:
      authorizationStore.save(authorizationCode)

proc consumeCallback(): OAuth2AuthorizationCodeConsumer =
  result = proc(code: string): Option[OAuth2AuthorizationCode] {.gcsafe.} =
    {.cast(gcsafe).}:
      authorizationStore.consume(code)

proc parsePort(): Port =
  let rawPort =
    if paramCount() >= 1:
      paramStr(1)
    else:
      getEnv("KARAX_OAUTH2_EXAMPLE_PORT", "9084")

  try:
    Port(parseInt(rawPort))
  except ValueError:
    raise newException(ValueError, "invalid port: " & rawPort)

when isMainModule:
  let host = getEnv("KARAX_OAUTH2_EXAMPLE_HOST", "127.0.0.1")
  let port = parsePort()
  let config = oauthConfig()

  var router: Router
  router.get("/health", healthHandler)
  router.get("/", appHandler)
  router.get("/callback", appHandler)
  router.get("/styles.css", stylesHandler)
  router.get("/app.js", appJsHandler)
  router.get("/login", loginGetHandler)
  router.post("/login", loginPostHandler)
  router.post("/logout", logoutHandler)
  router.registerOAuth2AuthorizationCode(
    config,
    saveCallback(),
    consumeCallback(),
    currentUserFromRequest,
    loginUrl = "/login",
  )
  router.get("/api/profile", oauth2(profileHandler, config, ["profile:read"]))
  router.post("/api/notes", oauth2(writeNoteHandler, config, ["notes:write"]))
  router.get("/api/admin", oauth2(adminHandler, config, ["admin:read"]))

  let server = newServer(router, workerThreads = 1)
  echo "Karax OAuth2 login example listening on http://", host, ":", port.int
  echo "Compile the Karax client before opening the page; see README.md."
  server.serve(port, address = host)
