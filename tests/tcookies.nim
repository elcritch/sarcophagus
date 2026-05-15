import std/[options, strutils, times, unittest]

import mummy

import sarcophagus/cookies

suite "cookies":
  test "parses cookie headers and typed cookie values":
    let headers: ApiHeaders = @[("Cookie", "theme=moss; count=7; verbose=true")]

    check headers.headerCookieValue("theme") == "moss"
    check headers.parseHeaderCookieValue("count", int) == 7
    check headers.parseHeaderCookieValue("verbose", bool) == true
    check headers.parseHeaderCookieValue("missing", Option[int]).isNone()

  test "signs and verifies cookies":
    let config = initSignedCookieConfig("cookie-secret", "cookie-salt")
    let signed = signCookieValue("session", "user-123", config)

    check verifySignedCookieValue("session", signed, config).get() == "user-123"
    check verifySignedCookieValue("session", signed & "tampered", config).isNone()
    check verifySignedCookieValue(
      "session", signed.replace("user-123", "user-999"), config
    )
    .isNone()

  test "builds session cookies with secure defaults and expiry handling":
    let config = initSessionCookieConfig("sid", "session-secret", ttlSeconds = 600)
    let header = sessionCookieHeader("user-123", config, now = fromUnix(1_700_000_000))

    check header.name == "Set-Cookie"
    check header.value.startsWith("sid=")
    check "; Path=/" in header.value
    check "; Max-Age=600" in header.value
    check "; Expires=" in header.value
    check "; Secure" in header.value
    check "; HttpOnly" in header.value
    check "; SameSite=Lax" in header.value

    let cleared = clearSessionCookieHeader(config)
    check "; Max-Age=0" in cleared.value
    check "; Expires=Thu, 01 Jan 1970 00:00:00 GMT" in cleared.value

  test "appends set-cookie headers to mummy responses":
    var headers: HttpHeaders
    headers.addSetCookie("theme", "moss")
    headers.clearCookie("theme")

    check headers.toBase.len == 2
    check headers.toBase[0][0] == "Set-Cookie"
    check headers.toBase[0][1].startsWith("theme=moss")
    check headers.toBase[1][1].startsWith("theme=")
