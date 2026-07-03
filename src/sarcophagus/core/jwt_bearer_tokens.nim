import std/[base64, httpclient, json, locks, options, sets, strutils, tables, times]

import jwt
import chroniclers

type
  BearerTokenAlgorithm* = enum
    bearerTokenHS256
    bearerTokenRS256
    bearerTokenES256

  JwksFetcher* = proc(url: string): string

  SigningKey* = object
    kid*: string
    secret*: string
    publicKey*: string
    algorithm*: BearerTokenAlgorithm

  BearerTokenConfig* = object
    issuer*: string
    audience*: string
    activeKid*: string
    keys*: Table[string, string]
    keyAlgorithms*: Table[string, BearerTokenAlgorithm]

  JwtVerifierConfig* = object
    issuer: string
    audience: string
    keys: Table[string, string]
    keyAlgorithms: Table[string, BearerTokenAlgorithm]
    jwks: JwtJwksCache

  BearerTokenSpec* = object
    subject*: string
    scopes*: seq[string]
    tokenId*: string
    issuedAt*: int64
    notBefore*: int64
    expiresAt*: int64

  BearerTokenClaims* = object
    issuer*: string
    subject*: string
    audience*: string
    scopes*: seq[string]
    tokenId*: string
    keyId*: string
    issuedAt*: int64
    notBefore*: int64
    expiresAt*: int64

  TokenValidationFailure* = object
    statusCode*: int
    code*: string
    message*: string

  TokenValidationResult* = object
    ok*: bool
    claims*: BearerTokenClaims
    failure*: TokenValidationFailure

  JwtJwksCache = ref object
    lock: Lock
    url: string
    cacheMaxAgeSeconds: int64
    unknownKidRefreshCooldownSeconds: int64
    fetchedAt: int64
    lastUnknownKidRefreshAt: int64
    keys: Table[string, string]
    keyAlgorithms: Table[string, BearerTokenAlgorithm]
    fetcher: JwksFetcher

type
  TokenHeader = object
    algorithm: BearerTokenAlgorithm
    kid: string

  VerifierKeySet = object
    keys: Table[string, string]
    keyAlgorithms: Table[string, BearerTokenAlgorithm]

const
  jwtVerifierDefaultJwksCacheMaxAgeSeconds* = 600
  jwtVerifierDefaultJwksUnknownKidRefreshCooldownSeconds* = 60
  jwtVerifierDefaultJwksFetchTimeoutMs* = 5000
  neverFetchedJwksAt = int64.low

proc parseTokenHeader(token: string, fallbackKid: string): TokenHeader

proc nowUnix*(): int64 {.inline.} =
  getTime().toUnix()

proc tokenAlgorithmName*(algorithm: BearerTokenAlgorithm): string =
  case algorithm
  of bearerTokenHS256: "HS256"
  of bearerTokenRS256: "RS256"
  of bearerTokenES256: "ES256"

proc parseBearerTokenAlgorithm*(raw: string): BearerTokenAlgorithm =
  case raw.strip().toUpperAscii()
  of "HS256":
    bearerTokenHS256
  of "RS256":
    bearerTokenRS256
  of "ES256":
    bearerTokenES256
  else:
    raise newException(ValueError, "token algorithm is not allowed")

proc toJwtAlgorithm(algorithm: BearerTokenAlgorithm): SignatureAlgorithm =
  case algorithm
  of bearerTokenHS256: HS256
  of bearerTokenRS256: RS256
  of bearerTokenES256: ES256

proc initPublicSigningKey*(
    kid: string, publicKey: string, algorithm: BearerTokenAlgorithm
): SigningKey =
  ## Builds a public-key verifier entry for asymmetric bearer tokens.
  if algorithm == bearerTokenHS256:
    raise newException(ValueError, "public signing keys must use RS256 or ES256")
  SigningKey(kid: kid, publicKey: publicKey, algorithm: algorithm)

proc parseScopeList*(raw: string): seq[string] =
  var seen = initHashSet[string]()
  for part in raw.split({' ', '\t', '\n', '\r', ','}):
    let scope = part.strip()
    if scope.len == 0 or scope in seen:
      continue
    seen.incl(scope)
    result.add(scope)

proc scopeListToString*(scopes: openArray[string]): string =
  parseScopeList(scopes.join(" ")).join(" ")

proc hasAllScopes*(scopes: openArray[string], requiredScopes: openArray[string]): bool =
  var available = initHashSet[string]()
  for scope in scopes:
    available.incl(scope)

  for requiredScope in requiredScopes:
    if requiredScope notin available:
      return false
  true

proc parseSigningKeys*(raw: string): seq[SigningKey] =
  var seen = initHashSet[string]()
  for token in raw.split(','):
    let entry = token.strip()
    if entry.len == 0:
      continue

    let sep = entry.find(':')
    if sep <= 0 or sep >= entry.high:
      raise newException(ValueError, "signing key entries must use kid:secret")

    let kid = entry[0 ..< sep].strip()
    let secret = entry[sep + 1 .. ^1].strip()
    if kid.len == 0 or secret.len == 0:
      raise newException(
        ValueError, "signing key entries must include non-empty kid and secret"
      )
    if kid in seen:
      raise newException(ValueError, "duplicate signing key id: " & kid)

    seen.incl(kid)
    result.add(SigningKey(kid: kid, secret: secret))

  if result.len == 0:
    raise newException(ValueError, "at least one signing key is required")

proc keyMaterial(key: SigningKey): string =
  case key.algorithm
  of bearerTokenHS256:
    key.secret.strip()
  of bearerTokenRS256, bearerTokenES256:
    key.publicKey.strip()

proc addVerifierKey(config: var JwtVerifierConfig, key: SigningKey) =
  let kid = key.kid.strip()
  let material = key.keyMaterial()
  if kid.len == 0 or material.len == 0:
    raise newException(
      ValueError, "signing keys must include non-empty kid and key material"
    )
  if kid in config.keys:
    raise newException(ValueError, "duplicate signing key id: " & kid)
  config.keys[kid] = material
  config.keyAlgorithms[kid] = key.algorithm

proc defaultJwksFetcher(url: string): string =
  var client =
    newHttpClient(maxRedirects = 0, timeout = jwtVerifierDefaultJwksFetchTimeoutMs)
  try:
    client.getContent(url)
  finally:
    client.close()

proc initJwksCache(
    url: string,
    cacheMaxAgeSeconds: Positive,
    unknownKidRefreshCooldownSeconds: Natural,
    fetcher: JwksFetcher,
): JwtJwksCache =
  let trimmedUrl = url.strip()
  if trimmedUrl.len == 0:
    return nil
  if not trimmedUrl.startsWith("https://"):
    raise newException(ValueError, "jwksUrl must use https")

  let effectiveFetcher = if fetcher.isNil: defaultJwksFetcher else: fetcher
  new(result)
  initLock(result.lock)
  result.url = trimmedUrl
  result.cacheMaxAgeSeconds = int64(cacheMaxAgeSeconds)
  result.unknownKidRefreshCooldownSeconds = int64(unknownKidRefreshCooldownSeconds)
  result.fetchedAt = neverFetchedJwksAt
  result.lastUnknownKidRefreshAt = neverFetchedJwksAt
  result.keys = initTable[string, string]()
  result.keyAlgorithms = initTable[string, BearerTokenAlgorithm]()
  result.fetcher = effectiveFetcher

template warnRemoteJwksWithoutSsl(jwksUrl: static[string]) =
  when jwksUrl.strip().len > 0 and not defined(ssl):
    {.
      warning:
        "Remote JWKS verification was configured without -d:ssl; the default " &
        "HTTPS fetcher requires SSL support. Compile with -d:ssl or pass a " &
        "custom jwksFetcher that verifies TLS."
    .}

proc initJwtVerifierConfigImpl(
    issuer: string,
    audience: string,
    keys: openArray[SigningKey] = [],
    jwksUrl = "",
    jwksCacheMaxAgeSeconds: Positive = jwtVerifierDefaultJwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds: Natural =
      jwtVerifierDefaultJwksUnknownKidRefreshCooldownSeconds,
    jwksFetcher: JwksFetcher = nil,
): JwtVerifierConfig =
  ## Builds a validation-only JWT verifier config.
  if issuer.strip().len == 0:
    raise newException(ValueError, "issuer must not be empty")
  if audience.strip().len == 0:
    raise newException(ValueError, "audience must not be empty")
  if keys.len == 0 and jwksUrl.strip().len == 0:
    raise newException(ValueError, "at least one signing key or JWKS URL is required")

  result.issuer = issuer.strip()
  result.audience = audience.strip()
  result.keys = initTable[string, string]()
  result.keyAlgorithms = initTable[string, BearerTokenAlgorithm]()
  result.jwks = initJwksCache(
    jwksUrl, jwksCacheMaxAgeSeconds, jwksUnknownKidRefreshCooldownSeconds, jwksFetcher
  )

  for key in keys:
    result.addVerifierKey(key)

proc initJwtVerifierConfig*(
    issuer: string,
    audience: string,
    keys: openArray[SigningKey] = [],
    jwksUrl = "",
    jwksCacheMaxAgeSeconds: Positive = jwtVerifierDefaultJwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds: Natural =
      jwtVerifierDefaultJwksUnknownKidRefreshCooldownSeconds,
    jwksFetcher: JwksFetcher = nil,
): JwtVerifierConfig =
  ## Builds a validation-only JWT verifier config.
  initJwtVerifierConfigImpl(
    issuer, audience, keys, jwksUrl, jwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds, jwksFetcher,
  )

proc initJwtVerifierConfig*(
    issuer: string,
    audience: string,
    jwksUrl: static[string],
    keys: openArray[SigningKey] = [],
    jwksCacheMaxAgeSeconds: Positive = jwtVerifierDefaultJwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds: Natural =
      jwtVerifierDefaultJwksUnknownKidRefreshCooldownSeconds,
): JwtVerifierConfig =
  ## Builds a validation-only JWT verifier config.
  warnRemoteJwksWithoutSsl(jwksUrl)
  initJwtVerifierConfigImpl(
    issuer, audience, keys, jwksUrl, jwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds, nil,
  )

proc initJwtVerifierConfig*(
    issuer: string,
    audience: string,
    keys: openArray[SigningKey],
    jwksUrl: static[string],
    jwksCacheMaxAgeSeconds: Positive = jwtVerifierDefaultJwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds: Natural =
      jwtVerifierDefaultJwksUnknownKidRefreshCooldownSeconds,
): JwtVerifierConfig =
  ## Builds a validation-only JWT verifier config.
  warnRemoteJwksWithoutSsl(jwksUrl)
  initJwtVerifierConfigImpl(
    issuer, audience, keys, jwksUrl, jwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds, nil,
  )

proc issuer*(config: JwtVerifierConfig): lent string =
  config.issuer

proc audience*(config: JwtVerifierConfig): lent string =
  config.audience

proc jwksUrl*(config: JwtVerifierConfig): string =
  if config.jwks.isNil:
    return ""
  config.jwks.url

proc jwksFetchedAt*(config: JwtVerifierConfig): int64 =
  if config.jwks.isNil:
    return 0
  withLock config.jwks.lock:
    if config.jwks.fetchedAt == neverFetchedJwksAt:
      return 0
    result = config.jwks.fetchedAt

proc jwksCacheMaxAgeSeconds*(config: JwtVerifierConfig): int64 =
  if config.jwks.isNil:
    return 0
  withLock config.jwks.lock:
    result = config.jwks.cacheMaxAgeSeconds

proc jwksUnknownKidRefreshCooldownSeconds*(config: JwtVerifierConfig): int64 =
  if config.jwks.isNil:
    return 0
  withLock config.jwks.lock:
    result = config.jwks.unknownKidRefreshCooldownSeconds

proc len*(config: JwtVerifierConfig): int =
  var kids = initHashSet[string]()
  for kid in config.keys.keys:
    kids.incl(kid)
  if not config.jwks.isNil:
    withLock config.jwks.lock:
      for kid in config.jwks.keys.keys:
        kids.incl(kid)
  kids.len

proc contains*(config: JwtVerifierConfig, kid: string): bool =
  let trimmedKid = kid.strip()
  if trimmedKid in config.keys:
    return true
  if config.jwks.isNil:
    return false
  withLock config.jwks.lock:
    result = trimmedKid in config.jwks.keys

proc initBearerTokenConfig*(
    issuer: string, audience: string, keys: openArray[SigningKey], activeKid = ""
): BearerTokenConfig =
  let verifier = initJwtVerifierConfig(issuer, audience, keys)
  result.issuer = verifier.issuer
  result.audience = verifier.audience
  result.keys = verifier.keys
  result.keyAlgorithms = verifier.keyAlgorithms

  result.activeKid =
    if activeKid.strip().len > 0:
      activeKid.strip()
    else:
      keys[0].kid.strip()

  if result.activeKid notin result.keys:
    raise newException(ValueError, "activeKid does not reference a configured key")

proc initBearerTokenSpec*(
    subject: string,
    scopes: openArray[string],
    ttlSeconds: int,
    tokenId = "",
    issuedAt = nowUnix(),
    notBefore = int64.low,
): BearerTokenSpec =
  if ttlSeconds <= 0:
    raise newException(ValueError, "ttlSeconds must be positive")

  let effectiveSubject = subject.strip()
  if effectiveSubject.len == 0:
    raise newException(ValueError, "subject must not be empty")

  let effectiveNotBefore = if notBefore == int64.low: issuedAt else: notBefore

  if effectiveNotBefore > issuedAt + int64(ttlSeconds):
    raise newException(ValueError, "notBefore must not exceed expiresAt")

  BearerTokenSpec(
    subject: effectiveSubject,
    scopes: parseScopeList(scopes.join(" ")),
    tokenId: tokenId.strip(),
    issuedAt: issuedAt,
    notBefore: effectiveNotBefore,
    expiresAt: issuedAt + int64(ttlSeconds),
  )

proc base64UrlEncodeBytes(bytes: openArray[byte]): string =
  var raw = newString(bytes.len)
  for idx, value in bytes:
    raw[idx] = char(value)

  result = encode(raw)
  result = result.replace('+', '-')
  result = result.replace('/', '_')
  result = result.replace("=", "")

proc base64UrlEncode(input: string): string =
  result = encode(input)
  result = result.replace('+', '-')
  result = result.replace('/', '_')
  result = result.replace("=", "")

proc base64UrlDecode(input: string): string =
  var normalized = input
  normalized = normalized.replace('-', '+')
  normalized = normalized.replace('_', '/')
  while normalized.len mod 4 != 0:
    normalized.add('=')
  decode(normalized)

proc derByte(value: int): string =
  result = newString(1)
  result[0] = char(value)

proc derLength(length: int): string =
  if length < 0:
    raise newException(ValueError, "DER length must not be negative")
  if length < 128:
    return derByte(length)

  var value = length
  var bytes = ""
  while value > 0:
    bytes = derByte(value and 0xff) & bytes
    value = value shr 8
  derByte(0x80 or bytes.len) & bytes

proc derValue(tag: int, content: string): string =
  derByte(tag) & derLength(content.len) & content

proc derSequence(parts: varargs[string]): string =
  var content = ""
  for part in parts:
    content.add(part)
  derValue(0x30, content)

proc stripLeadingZeroBytes(bytes: string): string =
  if bytes.len == 0:
    return ""
  var start = 0
  while start < bytes.high and bytes[start] == char(0):
    inc start
  bytes[start .. ^1]

proc derInteger(rawBytes: string): string =
  var bytes = stripLeadingZeroBytes(rawBytes)
  if bytes.len == 0:
    bytes = "\0"
  if (ord(bytes[0]) and 0x80) != 0:
    bytes = "\0" & bytes
  derValue(0x02, bytes)

proc derBitString(bytes: string): string =
  derValue(0x03, "\0" & bytes)

proc publicKeyPemFromDer(der: string): string =
  let encoded = encode(der)
  result = "-----BEGIN PUBLIC KEY-----\n"
  var offset = 0
  while offset < encoded.len:
    let nextOffset = min(offset + 64, encoded.len)
    result.add(encoded[offset ..< nextOffset])
    result.add('\n')
    offset = nextOffset
  result.add("-----END PUBLIC KEY-----")

proc jwkString(jwk: JsonNode, key: string): string =
  if jwk.kind != JObject or not jwk.hasKey(key) or jwk[key].kind != JString:
    raise newException(ValueError, "jwk " & key & " must be a string")
  jwk[key].getStr()

proc optionalJwkString(jwk: JsonNode, key: string): string =
  if jwk.kind != JObject or not jwk.hasKey(key):
    return ""
  if jwk[key].kind != JString:
    raise newException(ValueError, "jwk " & key & " must be a string")
  jwk[key].getStr()

proc jwkAllowsVerification(jwk: JsonNode): bool =
  let keyUse = optionalJwkString(jwk, "use")
  if keyUse.len > 0 and keyUse != "sig":
    return false

  if not jwk.hasKey("key_ops"):
    return true
  if jwk["key_ops"].kind != JArray:
    raise newException(ValueError, "jwk key_ops must be an array")

  for item in jwk["key_ops"]:
    if item.kind != JString:
      raise newException(ValueError, "jwk key_ops entries must be strings")
    if item.getStr() == "verify":
      return true
  false

proc jwkAlgorithm(jwk: JsonNode): Option[BearerTokenAlgorithm] =
  let rawAlgorithm = optionalJwkString(jwk, "alg")
  if rawAlgorithm.len > 0:
    try:
      let algorithm = parseBearerTokenAlgorithm(rawAlgorithm)
      if algorithm in {bearerTokenRS256, bearerTokenES256}:
        return some(algorithm)
      return none(BearerTokenAlgorithm)
    except ValueError:
      return none(BearerTokenAlgorithm)

  case optionalJwkString(jwk, "kty")
  of "RSA":
    some(bearerTokenRS256)
  of "EC":
    if optionalJwkString(jwk, "crv") == "P-256":
      some(bearerTokenES256)
    else:
      none(BearerTokenAlgorithm)
  else:
    none(BearerTokenAlgorithm)

proc rsaJwkPublicKeyPem(jwk: JsonNode): string =
  if jwkString(jwk, "kty") != "RSA":
    raise newException(ValueError, "RS256 jwk must use RSA kty")

  let modulus = base64UrlDecode(jwkString(jwk, "n"))
  let exponent = base64UrlDecode(jwkString(jwk, "e"))
  if modulus.len == 0 or exponent.len == 0:
    raise newException(ValueError, "RSA jwk modulus and exponent must not be empty")

  const
    rsaEncryption = "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"
    derNull = "\x05\x00"
  let algorithmIdentifier = derSequence(rsaEncryption, derNull)
  let rsaPublicKey = derSequence(derInteger(modulus), derInteger(exponent))
  publicKeyPemFromDer(derSequence(algorithmIdentifier, derBitString(rsaPublicKey)))

proc ecP256JwkPublicKeyPem(jwk: JsonNode): string =
  if jwkString(jwk, "kty") != "EC":
    raise newException(ValueError, "ES256 jwk must use EC kty")
  if jwkString(jwk, "crv") != "P-256":
    raise newException(ValueError, "ES256 jwk must use P-256 crv")

  let x = base64UrlDecode(jwkString(jwk, "x"))
  let y = base64UrlDecode(jwkString(jwk, "y"))
  if x.len != 32 or y.len != 32:
    raise newException(ValueError, "P-256 jwk coordinates must be 32 bytes")

  const
    ecPublicKey = "\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01"
    prime256v1 = "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07"
  let algorithmIdentifier = derSequence(ecPublicKey, prime256v1)
  let publicPoint = "\x04" & x & y
  publicKeyPemFromDer(derSequence(algorithmIdentifier, derBitString(publicPoint)))

proc signingKeyFromJwk(jwk: JsonNode): Option[SigningKey] =
  if jwk.kind != JObject:
    raise newException(ValueError, "jwks keys must be objects")
  if not jwkAllowsVerification(jwk):
    return none(SigningKey)

  let algorithm = jwkAlgorithm(jwk)
  if algorithm.isNone():
    return none(SigningKey)

  let kid = jwkString(jwk, "kid").strip()
  if kid.len == 0:
    raise newException(ValueError, "jwk kid must not be empty")

  case algorithm.get()
  of bearerTokenRS256:
    some(initPublicSigningKey(kid, rsaJwkPublicKeyPem(jwk), bearerTokenRS256))
  of bearerTokenES256:
    some(initPublicSigningKey(kid, ecP256JwkPublicKeyPem(jwk), bearerTokenES256))
  of bearerTokenHS256:
    none(SigningKey)

proc parseJwksSigningKeys*(jwksJson: string): seq[SigningKey] =
  ## Parses supported public signing keys from a JWKS document.
  let root = parseJson(jwksJson)
  if root.kind != JObject or not root.hasKey("keys") or root["keys"].kind != JArray:
    raise newException(ValueError, "jwks must contain a keys array")

  var seen = initHashSet[string]()
  for jwk in root["keys"]:
    let key = signingKeyFromJwk(jwk)
    if key.isSome():
      let kid = key.get().kid
      if kid in seen:
        raise newException(ValueError, "duplicate jwk key id: " & kid)
      seen.incl(kid)
      result.add(key.get())

proc verifierKeysFromJwks(jwksJson: string): VerifierKeySet =
  result.keys = initTable[string, string]()
  result.keyAlgorithms = initTable[string, BearerTokenAlgorithm]()
  for key in parseJwksSigningKeys(jwksJson):
    let kid = key.kid.strip()
    result.keys[kid] = key.keyMaterial()
    result.keyAlgorithms[kid] = key.algorithm

proc loadJwks(cache: JwtJwksCache, keySet: VerifierKeySet, now: int64) =
  withLock cache.lock:
    cache.keys = keySet.keys
    cache.keyAlgorithms = keySet.keyAlgorithms
    cache.fetchedAt = now

proc jwksNeedsRefresh(cache: JwtJwksCache, now: int64): bool =
  withLock cache.lock:
    result =
      cache.fetchedAt == neverFetchedJwksAt or
      now - cache.fetchedAt >= cache.cacheMaxAgeSeconds

proc shouldRefreshUnknownKid(cache: JwtJwksCache, now: int64): bool =
  withLock cache.lock:
    result =
      cache.lastUnknownKidRefreshAt == neverFetchedJwksAt or
      cache.unknownKidRefreshCooldownSeconds == 0 or
      now - cache.lastUnknownKidRefreshAt >= cache.unknownKidRefreshCooldownSeconds
    if result:
      cache.lastUnknownKidRefreshAt = now

proc refreshJwksCache(cache: JwtJwksCache, now: int64): bool =
  if cache.isNil:
    return true
  try:
    let keySet = verifierKeysFromJwks(cache.fetcher(cache.url))
    cache.loadJwks(keySet, now)
    var cacheMaxAgeSeconds: int64
    withLock cache.lock:
      cacheMaxAgeSeconds = cache.cacheMaxAgeSeconds
    debug "jwks refreshed",
      jwksUrl = cache.url,
      keyCount = keySet.keys.len,
      cacheMaxAgeSeconds = cacheMaxAgeSeconds
    true
  except CatchableError as e:
    notice "jwks refresh failed", jwksUrl = cache.url, message = e.msg
    false

proc refreshJwks*(config: JwtVerifierConfig, now = nowUnix()): bool =
  ## Refreshes a configured JWKS cache immediately.
  if config.jwks.isNil:
    raise newException(ValueError, "JwtVerifierConfig has no JWKS URL")
  config.jwks.refreshJwksCache(now)

proc effectiveVerifierKeys(config: JwtVerifierConfig): VerifierKeySet =
  result.keys = config.keys
  result.keyAlgorithms = config.keyAlgorithms
  if config.jwks.isNil:
    return

  withLock config.jwks.lock:
    for kid, material in config.jwks.keys:
      if kid notin result.keys:
        result.keys[kid] = material
        result.keyAlgorithms[kid] = config.jwks.keyAlgorithms[kid]

proc effectiveVerifierKeys(
    config: JwtVerifierConfig, token: string, now: int64
): VerifierKeySet =
  if config.jwks.isNil:
    return config.effectiveVerifierKeys()

  var attemptedRefresh = false
  if config.jwks.jwksNeedsRefresh(now):
    attemptedRefresh = true
    discard config.jwks.refreshJwksCache(now)

  result = config.effectiveVerifierKeys()
  try:
    let header = parseTokenHeader(token.strip(), "")
    if header.kid.len > 0 and header.kid notin result.keys and not attemptedRefresh:
      if config.jwks.shouldRefreshUnknownKid(now):
        discard config.jwks.refreshJwksCache(now)
        result = config.effectiveVerifierKeys()
  except CatchableError:
    discard

proc hmacSha256(message: string, secret: string): seq[byte] =
  signString(message, secret, HS256)

proc looksLikePemKey(value: string): bool =
  let normalized = value.strip().toUpperAscii()
  normalized.startsWith("-----BEGIN ") and " KEY-----" in normalized

proc keyAlgorithm(
    keys: Table[string, string],
    keyAlgorithms: Table[string, BearerTokenAlgorithm],
    kid: string,
): Option[BearerTokenAlgorithm] =
  if kid in keyAlgorithms:
    return some(keyAlgorithms[kid])
  if kid in keys and keys[kid].looksLikePemKey():
    return none(BearerTokenAlgorithm)
  some(bearerTokenHS256)

proc keyAlgorithm(
    config: BearerTokenConfig, kid: string
): Option[BearerTokenAlgorithm] =
  keyAlgorithm(config.keys, config.keyAlgorithms, kid)

proc constantTimeEquals(lhs: string, rhs: string): bool =
  var diff = lhs.len xor rhs.len
  let compareLen = min(lhs.len, rhs.len)
  for idx in 0 ..< compareLen:
    diff = diff or (ord(lhs[idx]) xor ord(rhs[idx]))
  diff == 0

proc failure(statusCode: int, code: string, message: string): TokenValidationResult =
  if statusCode == 403:
    notice "bearer token rejected",
      statusCode = statusCode, code = code, message = message
  else:
    debug "bearer token rejected",
      statusCode = statusCode, code = code, message = message
  TokenValidationResult(
    ok: false,
    failure:
      TokenValidationFailure(statusCode: statusCode, code: code, message: message),
  )

proc success(claims: BearerTokenClaims): TokenValidationResult =
  debug "bearer token accepted",
    subject = claims.subject,
    keyId = claims.keyId,
    scopeCount = claims.scopes.len,
    expiresAt = claims.expiresAt
  TokenValidationResult(ok: true, claims: claims)

proc jsonStringClaim(payload: JsonNode, key: string): Option[string] =
  if payload.kind != JObject or not payload.hasKey(key):
    return none(string)

  let node = payload[key]
  if node.kind != JString:
    return none(string)
  some(node.getStr())

proc jsonIntClaim(payload: JsonNode, key: string): Option[int64] =
  if payload.kind != JObject or not payload.hasKey(key):
    return none(int64)

  let node = payload[key]
  if node.kind != JInt:
    return none(int64)
  some(int64(node.getInt()))

proc payloadMatchesAudience(payload: JsonNode, expected: string): bool =
  if payload.kind != JObject or not payload.hasKey("aud"):
    return false

  let node = payload["aud"]
  case node.kind
  of JString:
    node.getStr() == expected
  of JArray:
    for item in node:
      if item.kind == JString and item.getStr() == expected:
        return true
    false
  else:
    false

proc parseScopeClaim(payload: JsonNode): seq[string] =
  if payload.kind != JObject or not payload.hasKey("scope"):
    return @[]

  let node = payload["scope"]
  case node.kind
  of JString:
    parseScopeList(node.getStr())
  of JArray:
    var rawScopes: seq[string] = @[]
    for item in node:
      if item.kind != JString:
        raise newException(ValueError, "token scope entries must be strings")
      rawScopes.add(item.getStr())
    parseScopeList(rawScopes.join(" "))
  else:
    raise newException(ValueError, "token scope claim must be a string or array")

proc base64UrlDecodeBytes(input: string): seq[byte] =
  let decoded = base64UrlDecode(input)
  result = newSeq[byte](decoded.len)
  for idx, value in decoded:
    result[idx] = byte(value)

proc parseTokenHeader(token: string, fallbackKid: string): TokenHeader =
  let parts = token.split('.')
  if parts.len != 3:
    raise newException(ValueError, "malformed bearer token")

  let headerJson = parseJson(base64UrlDecode(parts[0]))
  if headerJson.kind != JObject:
    raise newException(ValueError, "invalid token header")

  if not headerJson.hasKey("alg"):
    raise newException(ValueError, "token header missing alg")
  if headerJson["alg"].kind != JString:
    raise newException(ValueError, "token algorithm is not allowed")
  result.algorithm = parseBearerTokenAlgorithm(headerJson["alg"].getStr())

  if headerJson.hasKey("typ"):
    if headerJson["typ"].kind != JString or headerJson["typ"].getStr() != "JWT":
      raise newException(ValueError, "token typ must be JWT")

  result.kid = fallbackKid
  if headerJson.hasKey("kid"):
    if headerJson["kid"].kind != JString:
      raise newException(ValueError, "token kid must be a string")
    let kid = headerJson["kid"].getStr().strip()
    if kid.len == 0:
      raise newException(ValueError, "token kid is empty")
    result.kid = kid

proc verifySignature(
    key: string,
    algorithm: BearerTokenAlgorithm,
    signingInput: string,
    signaturePart: string,
): bool =
  case algorithm
  of bearerTokenHS256:
    let expectedSignature = base64UrlEncodeBytes(hmacSha256(signingInput, key))
    constantTimeEquals(expectedSignature, signaturePart)
  of bearerTokenRS256, bearerTokenES256:
    let signature = base64UrlDecodeBytes(signaturePart)
    if signature.len == 0:
      return false
    verifySignature(signingInput, signature, key, algorithm.toJwtAlgorithm())

proc mintBearerToken*(config: BearerTokenConfig, spec: BearerTokenSpec): string =
  if config.activeKid.len == 0 or config.activeKid notin config.keys:
    raise newException(ValueError, "activeKid does not reference a configured key")
  let activeAlgorithm = config.keyAlgorithm(config.activeKid)
  if activeAlgorithm.isNone() or activeAlgorithm.get() != bearerTokenHS256:
    raise newException(ValueError, "activeKid must reference an HS256 signing key")
  if spec.subject.strip().len == 0:
    raise newException(ValueError, "subject must not be empty")
  if spec.expiresAt <= spec.notBefore:
    raise newException(ValueError, "expiresAt must be greater than notBefore")

  let headerJson =
    %*{
      "alg": tokenAlgorithmName(bearerTokenHS256), "typ": "JWT", "kid": config.activeKid
    }

  var claimsJson =
    %*{
      "iss": config.issuer,
      "sub": spec.subject.strip(),
      "aud": config.audience,
      "iat": spec.issuedAt,
      "nbf": spec.notBefore,
      "exp": spec.expiresAt,
      "scope": scopeListToString(spec.scopes),
    }
  if spec.tokenId.strip().len > 0:
    claimsJson["jti"] = newJString(spec.tokenId.strip())

  let headerPart = base64UrlEncode($headerJson)
  let claimsPart = base64UrlEncode($claimsJson)
  let signingInput = headerPart & "." & claimsPart
  let signature = hmacSha256(signingInput, config.keys[config.activeKid])
  let signaturePart = base64UrlEncodeBytes(signature)

  info "bearer token minted",
    subject = spec.subject.strip(),
    keyId = config.activeKid,
    scopeCount = spec.scopes.len,
    ttlSeconds = spec.expiresAt - spec.issuedAt,
    hasTokenId = spec.tokenId.strip().len > 0

  signingInput & "." & signaturePart

proc validateBearerTokenInternal(
    issuer: string,
    audience: string,
    keys: Table[string, string],
    keyAlgorithms: Table[string, BearerTokenAlgorithm],
    fallbackKid: string,
    token: string,
    requiredScopes: openArray[string] = [],
    now = nowUnix(),
): TokenValidationResult =
  let trimmedToken = token.strip()
  trace "validating bearer token",
    tokenPresent = trimmedToken.len > 0, requiredScopeCount = requiredScopes.len
  if trimmedToken.len == 0:
    return failure(401, "missing_token", "Missing bearer token")

  try:
    let tokenParts = trimmedToken.split('.')
    if tokenParts.len != 3:
      return failure(401, "invalid_token", "Malformed bearer token")

    let header = parseTokenHeader(trimmedToken, fallbackKid)
    if header.kid.len == 0:
      return failure(401, "invalid_token", "Token key id is missing")
    if header.kid notin keys:
      return failure(401, "invalid_token", "Unknown token key id")
    let configuredAlgorithm = keyAlgorithm(keys, keyAlgorithms, header.kid)
    if configuredAlgorithm.isNone():
      return failure(401, "invalid_token", "Token key algorithm is not configured")
    if header.algorithm != configuredAlgorithm.get():
      return failure(401, "invalid_token", "Token algorithm does not match key")

    let signingInput = tokenParts[0] & "." & tokenParts[1]
    if not verifySignature(
      keys[header.kid], header.algorithm, signingInput, tokenParts[2]
    ):
      return failure(401, "invalid_token", "Token signature is invalid")

    let payload = parseJson(base64UrlDecode(tokenParts[1]))
    if payload.kind != JObject:
      return failure(401, "invalid_token", "Token payload is invalid")

    let iss = jsonStringClaim(payload, "iss")
    if iss.isNone() or iss.get() != issuer:
      return failure(401, "invalid_token", "Token issuer is invalid")

    let sub = jsonStringClaim(payload, "sub")
    if sub.isNone() or sub.get().strip().len == 0:
      return failure(401, "invalid_token", "Token subject is invalid")

    if not payloadMatchesAudience(payload, audience):
      return failure(401, "invalid_token", "Token audience is invalid")

    let iat = jsonIntClaim(payload, "iat")
    if iat.isNone():
      if payload.hasKey("iat"):
        return failure(401, "invalid_token", "Token issued-at is invalid")
      return failure(401, "invalid_token", "Token is missing iat")
    if iat.get() > now:
      return failure(401, "invalid_token", "Token issued-at is in the future")

    let nbf = jsonIntClaim(payload, "nbf")
    if nbf.isNone() and payload.hasKey("nbf"):
      return failure(401, "invalid_token", "Token not-before is invalid")
    if nbf.isSome() and now < nbf.get():
      return failure(401, "invalid_token", "Token is not valid yet")

    let exp = jsonIntClaim(payload, "exp")
    if exp.isNone():
      if payload.hasKey("exp"):
        return failure(401, "invalid_token", "Token expiration is invalid")
      return failure(401, "invalid_token", "Token is missing exp")
    if now >= exp.get():
      return failure(401, "invalid_token", "Token is expired")

    let tokenId = jsonStringClaim(payload, "jti").get("")
    let tokenScopes = parseScopeClaim(payload)
    if not hasAllScopes(tokenScopes, requiredScopes):
      return failure(403, "insufficient_scope", "Token scope is insufficient")

    return success(
      BearerTokenClaims(
        issuer: iss.get(),
        subject: sub.get().strip(),
        audience: audience,
        scopes: tokenScopes,
        tokenId: tokenId,
        keyId: header.kid,
        issuedAt: iat.get(),
        notBefore: nbf.get(iat.get()),
        expiresAt: exp.get(),
      )
    )
  except CatchableError as e:
    failure(401, "invalid_token", e.msg)

proc validateBearerToken*(
    config: JwtVerifierConfig,
    token: string,
    requiredScopes: openArray[string] = [],
    now = nowUnix(),
): TokenValidationResult =
  let verifierKeys = config.effectiveVerifierKeys(token, now)
  validateBearerTokenInternal(
    config.issuer, config.audience, verifierKeys.keys, verifierKeys.keyAlgorithms, "",
    token, requiredScopes, now,
  )

proc validateBearerToken*(
    config: BearerTokenConfig,
    token: string,
    requiredScopes: openArray[string] = [],
    now = nowUnix(),
): TokenValidationResult =
  validateBearerTokenInternal(
    config.issuer, config.audience, config.keys, config.keyAlgorithms, config.activeKid,
    token, requiredScopes, now,
  )

proc bearerTokenFromAuthorizationHeader*(authorizationHeader: string): string =
  let trimmedHeader = authorizationHeader.strip()
  if trimmedHeader.len == 0:
    return ""

  let separator = trimmedHeader.find({' ', '\t'})
  if separator <= 0 or separator >= trimmedHeader.high:
    return ""

  let scheme = trimmedHeader[0 ..< separator]
  if scheme.toLowerAscii() != "bearer":
    return ""

  trimmedHeader[separator + 1 .. ^1].strip()
