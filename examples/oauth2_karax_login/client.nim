import std/[json, strutils]

import karax/[karax, karaxdsl, kajax, kdom, localstorage, vdom]

const
  ClientId = "karax-browser"
  RedirectUri = "http://127.0.0.1:9084/callback"
  RequestedScope = "profile:read notes:write"
  VerifierKey = "sarcophagus.pkce.verifier"
  StateKey = "sarcophagus.oauth.state"
  TokenKey = "sarcophagus.access_token"

type AppState = object
  accessToken: string
  status: string
  profile: string
  writeResult: string
  error: string

var app = AppState(status: "Signed out")

proc jsRandom(): float {.importjs: "Math.random()".}

proc randomToken(length: int): string =
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
  for _ in 0 ..< length:
    result.add alphabet[int(jsRandom() * float(alphabet.len))]

proc queryValue(name: string): string =
  let search = $window.location.search
  if search.len <= 1:
    return ""

  for pair in search[1 .. ^1].split('&'):
    let parts = pair.split('=', maxsplit = 1)
    if parts.len == 2 and $decodeURIComponent(parts[0].cstring) == name:
      return $decodeURIComponent(parts[1].cstring)

proc formEncode(key, value: string): string =
  $encodeURIComponent(key.cstring) & "=" & $encodeURIComponent(value.cstring)

proc authHeaders(): seq[(cstring, cstring)] =
  @[("Authorization".cstring, ("Bearer " & app.accessToken).cstring)]

proc startLogin() =
  let verifier = randomToken(64)
  let state = randomToken(32)
  setItem(VerifierKey, verifier.cstring)
  setItem(StateKey, state.cstring)

  let authorizeUrl =
    "/oauth/authorize?" & formEncode("response_type", "code") & "&" &
    formEncode("client_id", ClientId) & "&" & formEncode("redirect_uri", RedirectUri) &
    "&" & formEncode("scope", RequestedScope) & "&" & formEncode("state", state) & "&" &
    formEncode("code_challenge", verifier) & "&" &
    formEncode("code_challenge_method", "plain")
  window.location.href = authorizeUrl.cstring

proc clearSession() =
  app = AppState(status: "Signed out")
  removeItem(TokenKey)
  removeItem(VerifierKey)
  removeItem(StateKey)

proc loadProfile()

proc exchangeCode(code: string) =
  let returnedState = queryValue("state")
  if returnedState.len == 0 or returnedState != $getItem(StateKey):
    app.error = "OAuth state did not match"
    app.status = "Token exchange blocked"
    redraw()
    return

  let verifier = $getItem(VerifierKey)
  let body =
    formEncode("grant_type", "authorization_code") & "&" &
    formEncode("client_id", ClientId) & "&" & formEncode("code", code) & "&" &
    formEncode("redirect_uri", RedirectUri) & "&" & formEncode(
      "code_verifier", verifier
    )

  ajaxPost(
    "/oauth/token",
    @[("Content-Type".cstring, "application/x-www-form-urlencoded".cstring)],
    body.cstring,
    proc(status: int, response: cstring) =
      if status == 200:
        let payload = parseJson($response)
        app.accessToken = payload["access_token"].getStr()
        setItem(TokenKey, app.accessToken.cstring)
        removeItem(VerifierKey)
        removeItem(StateKey)
        app.status = "Signed in with OAuth2 bearer token"
        app.error = ""
        loadProfile()
      else:
        app.status = "Token exchange failed"
        app.error = $response,
  )

proc loadProfile() =
  if app.accessToken.len == 0:
    app.error = "No access token is available"
    return

  ajaxGet(
    "/api/profile",
    authHeaders(),
    proc(status: int, response: cstring) =
      if status == 200:
        app.profile = $response
        app.error = ""
      else:
        app.error = "Profile request failed: " & $response,
  )

proc writeNote() =
  if app.accessToken.len == 0:
    app.error = "Sign in before calling the write endpoint"
    return

  ajaxPost(
    "/api/notes",
    @[
      ("Authorization".cstring, ("Bearer " & app.accessToken).cstring),
      ("Content-Type".cstring, "application/json".cstring),
    ],
    """{"message":"Created from Karax with an OAuth2 bearer token"}""".cstring,
    proc(status: int, response: cstring) =
      if status == 200:
        app.writeResult = $response
        app.error = ""
      else:
        app.error = "Write request failed: " & $response,
  )

proc callAdmin() =
  ajaxGet(
    "/api/admin",
    authHeaders(),
    proc(status: int, response: cstring) =
      app.error = "Admin endpoint returned HTTP " & $status & ": " & $response,
  )

proc initApp() =
  if hasItem(TokenKey):
    app.accessToken = $getItem(TokenKey)
    app.status = "Signed in with stored access token"
    loadProfile()

  let code = queryValue("code")
  if code.len > 0:
    app.status = "Exchanging authorization code"
    exchangeCode(code)

proc tokenPreview(): string =
  if app.accessToken.len == 0:
    ""
  elif app.accessToken.len <= 32:
    app.accessToken
  else:
    app.accessToken[0 .. 31] & "..."

proc appView(): VNode =
  buildHtml(tdiv(class = "shell")):
    header:
      h1:
        text "Karax OAuth2 Login"
      p:
        text "Browser pages use a login cookie. JSON endpoints require bearer tokens."

    section(class = "panel"):
      h2:
        text "Session"
      p:
        strong:
          text "Status: "
        text app.status
      if app.accessToken.len == 0:
        button(
          onclick = proc(e: Event, n: VNode) =
            startLogin()
        ):
          text "Sign in as Alice"
      else:
        p(class = "token"):
          text tokenPreview()
        button(
          onclick = proc(e: Event, n: VNode) =
            loadProfile()
        ):
          text "Refresh profile"
        button(
          onclick = proc(e: Event, n: VNode) =
            writeNote()
        ):
          text "Write note"
        button(
          onclick = proc(e: Event, n: VNode) =
            callAdmin()
        ):
          text "Try admin"
        button(
          onclick = proc(e: Event, n: VNode) =
            clearSession()
        ):
          text "Clear token"

    section(class = "grid"):
      tdiv(class = "panel"):
        h2:
          text "Profile API"
        pre:
          text app.profile
      tdiv(class = "panel"):
        h2:
          text "Write API"
        pre:
          text app.writeResult

    if app.error.len > 0:
      section(class = "panel error"):
        h2:
          text "Last API Response"
        pre:
          text app.error

setRenderer(appView)
initApp()
