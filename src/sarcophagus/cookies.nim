import std/[options, strutils, times]

import bearssl/[hash, hmac]
import mummy

import ./core/typed_api
import ./security/secret_hashing

export typed_api

type
  CookieSameSite* = enum
    cookieSameSiteDefault
    cookieSameSiteLax
    cookieSameSiteStrict
    cookieSameSiteNone

  CookieOptions* = object
    path*: string
    domain*: string
    secure*: bool
    httpOnly*: bool
    sameSite*: CookieSameSite
    maxAgeSeconds*: Option[int]
    expiresAt*: Option[Time]

  SignedCookieConfig* = object
    secret*: string
    salt*: string

  SessionCookieConfig* = object
    cookieName*: string
    signing*: SignedCookieConfig
    options*: CookieOptions
    ttlSeconds*: int

proc cookieOptions*(
    path = "/",
    domain = "",
    secure = true,
    httpOnly = true,
    sameSite = cookieSameSiteLax,
    maxAgeSeconds: Option[int] = none(int),
    expiresAt: Option[Time] = none(Time),
): CookieOptions =
  CookieOptions(
    path: path,
    domain: domain,
    secure: secure,
    httpOnly: httpOnly,
    sameSite: sameSite,
    maxAgeSeconds: maxAgeSeconds,
    expiresAt: expiresAt,
  )

proc initSignedCookieConfig*(
    secret: string, salt = "sarcophagus-cookie-v1"
): SignedCookieConfig =
  if secret.strip().len == 0:
    raise newException(ValueError, "cookie signing secret must not be empty")
  if salt.strip().len == 0:
    raise newException(ValueError, "cookie signing salt must not be empty")

  SignedCookieConfig(secret: secret, salt: salt)

proc initSessionCookieConfig*(
    cookieName, secret: string,
    ttlSeconds = 3600,
    path = "/",
    domain = "",
    secure = true,
    httpOnly = true,
    sameSite = cookieSameSiteLax,
    salt = "sarcophagus-session-v1",
): SessionCookieConfig =
  if cookieName.strip().len == 0:
    raise newException(ValueError, "session cookie name must not be empty")
  if ttlSeconds <= 0:
    raise newException(ValueError, "session cookie ttlSeconds must be positive")

  SessionCookieConfig(
    cookieName: cookieName.strip(),
    signing: initSignedCookieConfig(secret, salt),
    options: cookieOptions(
      path = path,
      domain = domain,
      secure = secure,
      httpOnly = httpOnly,
      sameSite = sameSite,
    ),
    ttlSeconds: ttlSeconds,
  )

proc isCookieNameChar(ch: char): bool =
  ch.isAlphaNumeric() or
    ch in {'!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~'}

proc requireValidCookieName(name: string) =
  if name.len == 0:
    raise newException(ValueError, "cookie name must not be empty")
  for ch in name:
    if not ch.isCookieNameChar():
      raise newException(ValueError, "cookie name contains invalid characters")

proc requireValidCookieValue(value: string) =
  for ch in value:
    if ch < ' ' or ch == ';' or ch == ',' or ch == '\x7f':
      raise newException(ValueError, "cookie value contains invalid characters")

proc formatCookieExpires(value: Time): string =
  value.utc.format("ddd, dd MMM yyyy HH:mm:ss 'GMT'")

proc sameSiteValue(value: CookieSameSite): string =
  case value
  of cookieSameSiteDefault: ""
  of cookieSameSiteLax: "Lax"
  of cookieSameSiteStrict: "Strict"
  of cookieSameSiteNone: "None"

proc parseCookieHeader*(rawHeader: string): ApiHeaders =
  for part in rawHeader.split(';'):
    let trimmed = part.strip()
    if trimmed.len == 0:
      continue
    let pieces = trimmed.split('=', maxsplit = 1)
    if pieces.len != 2:
      continue
    let name = pieces[0].strip()
    if name.len == 0:
      continue
    result.add((name, pieces[1].strip()))

proc parsedCookieValue(cookies: ApiHeaders, name: string): string =
  for cookie in cookies:
    if cookie.name == name:
      return cookie.value

proc headerCookieValue*(headers: ApiHeaders, name: string): string =
  for header in headers:
    if cmpIgnoreCase(header.name, "Cookie") != 0:
      continue
    return parseCookieHeader(header.value).parsedCookieValue(name)

proc requestCookieValue*(request: Request, name: string): string =
  parseCookieHeader(request.headers["Cookie"]).parsedCookieValue(name)

proc missingCookieValue[T](name: string, target: typedesc[T]): T =
  raiseApiError(400, "Missing required cookie '" & name & "'", "missing_cookie")

proc missingCookieValue[T](name: string, target: typedesc[Option[T]]): Option[T] =
  none(T)

proc parseHeaderCookieValue*[T](
    headers: ApiHeaders, name: string, target: typedesc[T]
): T =
  let raw = headers.headerCookieValue(name)
  if raw.len > 0:
    parseApiParam(raw, name, T)
  else:
    missingCookieValue(name, T)

proc parseRequestCookieValue*[T](
    request: Request, name: string, target: typedesc[T]
): T =
  let raw = request.requestCookieValue(name)
  if raw.len > 0:
    parseApiParam(raw, name, T)
  else:
    missingCookieValue(name, T)

proc parseRequestCookieValue*[T](request: Request, name: string): T =
  parseRequestCookieValue(request, name, T)

proc setCookieValue*(name, value: string, options = cookieOptions()): string =
  requireValidCookieName(name)
  requireValidCookieValue(value)
  if options.sameSite == cookieSameSiteNone and not options.secure:
    raise newException(ValueError, "SameSite=None cookies must be Secure")

  result = name & "=" & value
  if options.path.len > 0:
    result.add("; Path=" & options.path)
  if options.domain.len > 0:
    result.add("; Domain=" & options.domain)
  if options.maxAgeSeconds.isSome():
    result.add("; Max-Age=" & $options.maxAgeSeconds.get())
  if options.expiresAt.isSome():
    result.add("; Expires=" & formatCookieExpires(options.expiresAt.get()))
  if options.secure:
    result.add("; Secure")
  if options.httpOnly:
    result.add("; HttpOnly")
  let sameSite = options.sameSite.sameSiteValue()
  if sameSite.len > 0:
    result.add("; SameSite=" & sameSite)

proc setCookieHeader*(name, value: string, options = cookieOptions()): ApiHeader =
  ("Set-Cookie", setCookieValue(name, value, options))

proc clearCookieHeader*(name: string, options = cookieOptions()): ApiHeader =
  var cleared = options
  cleared.maxAgeSeconds = some(0)
  cleared.expiresAt = some(fromUnix(0))
  setCookieHeader(name, "", cleared)

proc addSetCookie*(
    headers: var ApiHeaders, name, value: string, options = cookieOptions()
) =
  headers.add(setCookieHeader(name, value, options))

proc clearCookie*(headers: var ApiHeaders, name: string, options = cookieOptions()) =
  headers.add(clearCookieHeader(name, options))

proc addSetCookie*(
    headers: var HttpHeaders, name, value: string, options = cookieOptions()
) =
  headers.toBase.add(setCookieHeader(name, value, options))

proc clearCookie*(headers: var HttpHeaders, name: string, options = cookieOptions()) =
  headers.toBase.add(clearCookieHeader(name, options))

proc hmacSha256Hex(key, data: string): string =
  var keyContext: HmacKeyContext
  let keyPtr =
    if key.len == 0:
      nil
    else:
      cast[pointer](unsafeAddr key[0])
  hmacKeyInit(keyContext, addr sha256Vtable, keyPtr, csize_t(key.len))

  var context: HmacContext
  hmacInit(context, keyContext, sha256SIZE)
  if data.len > 0:
    hmacUpdate(context, cast[pointer](unsafeAddr data[0]), csize_t(data.len))

  var digest: array[SecretHashDigestBytes, byte]
  discard hmacOut(context, addr digest[0])
  hexEncode(digest)

proc signedCookieSignature(name, value: string, config: SignedCookieConfig): string =
  hmacSha256Hex(config.secret, config.salt & "\n" & name & "\n" & value)

proc signCookieValue*(name, value: string, config: SignedCookieConfig): string =
  requireValidCookieName(name)
  requireValidCookieValue(value)
  value & "." & signedCookieSignature(name, value, config)

proc verifySignedCookieValue*(
    name, signedValue: string, config: SignedCookieConfig
): Option[string] =
  let separator = signedValue.rfind('.')
  if separator <= 0 or separator >= signedValue.high:
    return none(string)

  let
    value = signedValue[0 ..< separator]
    signature = signedValue[separator + 1 .. ^1]
  if not signature.isLowerHex():
    return none(string)
  if constantTimeEquals(signature, signedCookieSignature(name, value, config)):
    some(value)
  else:
    none(string)

proc signedCookieHeader*(
    name, value: string, config: SignedCookieConfig, options = cookieOptions()
): ApiHeader =
  setCookieHeader(name, signCookieValue(name, value, config), options)

proc verifiedSignedHeaderCookieValue*(
    headers: ApiHeaders, name: string, config: SignedCookieConfig
): Option[string] =
  let signedValue = headers.headerCookieValue(name)
  if signedValue.len == 0:
    none(string)
  else:
    verifySignedCookieValue(name, signedValue, config)

proc verifiedSignedRequestCookieValue*(
    request: Request, name: string, config: SignedCookieConfig
): Option[string] =
  let signedValue = request.requestCookieValue(name)
  if signedValue.len == 0:
    none(string)
  else:
    verifySignedCookieValue(name, signedValue, config)

proc sessionCookieHeader*(
    sessionValue: string, config: SessionCookieConfig, now = getTime()
): ApiHeader =
  var options = config.options
  options.maxAgeSeconds = some(config.ttlSeconds)
  options.expiresAt = some(fromUnix(now.toUnix + config.ttlSeconds.int64))
  signedCookieHeader(config.cookieName, sessionValue, config.signing, options)

proc clearSessionCookieHeader*(config: SessionCookieConfig): ApiHeader =
  clearCookieHeader(config.cookieName, config.options)

proc headerSessionValue*(
    headers: ApiHeaders, config: SessionCookieConfig
): Option[string] =
  verifiedSignedHeaderCookieValue(headers, config.cookieName, config.signing)

proc requestSessionValue*(
    request: Request, config: SessionCookieConfig
): Option[string] =
  verifiedSignedRequestCookieValue(request, config.cookieName, config.signing)
