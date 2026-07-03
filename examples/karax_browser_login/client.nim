import std/[json, strutils]

import karax/[karax, karaxdsl, kajax, vdom]

type
  SessionState = object
    signedIn: bool
    subject: string
    username: string
    displayName: string
    scopes: seq[string]
    notes: seq[string]

  AppState = object
    username: string
    password: string
    noteDraft: string
    status: string
    session: SessionState
    profileJson: string
    noteResult: string
    error: string
    loading: bool

var app = AppState(
  username: "alice",
  password: "correct horse battery staple",
  status: "Checking browser session",
)

proc jsonHeaders(): seq[(cstring, cstring)] =
  @[("Content-Type".cstring, "application/json".cstring)]

proc prettyJson(input: string): string =
  try:
    input.parseJson().pretty()
  except CatchableError:
    input

proc loadSession()

proc loadProfile() =
  app.loading = true
  ajaxGet(
    "/api/profile",
    @[],
    proc(status: int, response: cstring) =
      app.loading = false
      if status == 200:
        app.profileJson = prettyJson($response)
        app.error = ""
        app.status = "Protected profile loaded through the browser session cookie"
      else:
        app.error = prettyJson($response)
        app.status = "Protected profile request failed",
  )

proc loadSession() =
  app.loading = true
  ajaxGet(
    "/api/session",
    @[],
    proc(status: int, response: cstring) =
      app.loading = false
      if status == 200:
        let payload = parseJson($response)
        app.session.signedIn = payload["signedIn"].getBool()
        app.session.subject = payload["subject"].getStr()
        app.session.username = payload["username"].getStr()
        app.session.displayName = payload["displayName"].getStr()
        app.session.scopes.setLen(0)
        for item in payload["scopes"].items():
          app.session.scopes.add(item.getStr())
        app.session.notes.setLen(0)
        for item in payload["notes"].items():
          app.session.notes.add(item.getStr())
        if app.session.signedIn:
          app.status = "Session cookie is active"
          app.error = ""
        else:
          app.status = "Signed out"
          app.profileJson = ""
      else:
        app.error = prettyJson($response)
        app.status = "Failed to load session",
  )

proc signIn() =
  app.loading = true
  let body = $(%*{"username": app.username, "password": app.password})
  ajaxPost(
    "/api/login",
    jsonHeaders(),
    body.cstring,
    proc(status: int, response: cstring) =
      app.loading = false
      if status == 200:
        app.error = ""
        app.status = "Signed in and browser cookie issued"
        app.profileJson = prettyJson($response)
        loadSession()
      else:
        app.error = prettyJson($response)
        app.status = "Login failed",
  )

proc signOut() =
  app.loading = true
  ajaxPost(
    "/api/logout",
    jsonHeaders(),
    "{}".cstring,
    proc(status: int, response: cstring) =
      discard response
      app.loading = false
      if status == 200:
        app.session = SessionState()
        app.profileJson = ""
        app.noteResult = ""
        app.error = ""
        app.status = "Signed out and session cookie cleared"
        loadSession()
      else:
        app.error = "Logout failed"
        app.status = "Logout failed",
  )

proc saveNote() =
  app.loading = true
  let message = app.noteDraft.strip()
  let body = $(%*{"message": message})
  ajaxPost(
    "/api/notes",
    jsonHeaders(),
    body.cstring,
    proc(status: int, response: cstring) =
      app.loading = false
      if status == 201:
        app.noteResult = prettyJson($response)
        app.error = ""
        app.status = "Protected note saved"
        app.noteDraft = ""
        loadSession()
      else:
        app.error = prettyJson($response)
        app.status = "Note save failed",
  )

proc sessionBadge(): string =
  if app.session.signedIn: "Signed in" else: "Signed out"

proc appView(): VNode =
  buildHtml(tdiv(class = "shell")):
    section(class = "hero"):
      tdiv(class = if app.session.signedIn: "pill" else: "pill off"):
        text sessionBadge()
      h1:
        text "Karax Browser Login"
      p:
        text "This page demonstrates Sarcophagus browser-session login with an HttpOnly cookie and same-origin Karax requests."
      p:
        text app.status

    tdiv(class = "grid"):
      section(class = "panel"):
        h2:
          text "Login Form"
        tdiv(class = "stack"):
          label:
            text "Username"
            input(
              value = app.username.cstring,
              placeholder = "alice",
              oninput = proc(e: Event, n: VNode) =
                app.username = $n.value,
            )
          label:
            text "Password"
            input(
              value = app.password.cstring,
              placeholder = "correct horse battery staple",
              oninput = proc(e: Event, n: VNode) =
                app.password = $n.value,
            )
          tdiv(class = "row"):
            button(
              disabled = app.loading,
              onclick = proc(e: Event, n: VNode) =
                signIn(),
            ):
              text "Sign in"
            button(
              class = "alt",
              disabled = app.loading,
              onclick = proc(e: Event, n: VNode) =
                loadSession(),
            ):
              text "Refresh session"
            button(
              class = "alt",
              disabled = app.loading,
              onclick = proc(e: Event, n: VNode) =
                signOut(),
            ):
              text "Sign out"
        p:
          text "Try alice / correct horse battery staple or bob / hunter2 hunter2."

      section(class = "panel"):
        h2:
          text "Session Snapshot"
        if app.session.signedIn:
          p:
            text app.session.displayName & " (" & app.session.subject & ")"
          p:
            text "Scopes: " & app.session.scopes.join(", ")
          if app.session.notes.len > 0:
            ul:
              for note in app.session.notes:
                li:
                  text note
        else:
          p:
            text "No browser session is active."

    tdiv(class = "grid"):
      section(class = "panel"):
        h2:
          text "Protected API"
        p:
          text "These routes only work when the browser sends the session cookie."
        tdiv(class = "row"):
          button(
            disabled = app.loading,
            onclick = proc(e: Event, n: VNode) =
              loadProfile(),
          ):
            text "Load profile"
        if app.profileJson.len > 0:
          pre(class = "code"):
            text app.profileJson

      section(class = "panel"):
        h2:
          text "Write Note"
        label:
          text "Note body"
          textarea(
            placeholder = "Write a protected note",
            value = app.noteDraft.cstring,
            oninput = proc(e: Event, n: VNode) =
              app.noteDraft = $n.value,
          )
        tdiv(class = "row"):
          button(
            disabled = app.loading,
            onclick = proc(e: Event, n: VNode) =
              saveNote(),
          ):
            text "Save note"
        if app.noteResult.len > 0:
          pre(class = "code"):
            text app.noteResult

    if app.error.len > 0:
      section(class = "panel"):
        h2:
          text "Last Error"
        pre(class = "error"):
          text app.error

setRenderer(appView)
loadSession()
