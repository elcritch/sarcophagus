import std/[base64, json, options, sets, strutils, tables, times]

import jwt

type
  SigningKey* = object
    kid*: string
    secret*: string

  BearerTokenConfig* = object
    issuer*: string
    audience*: string
    activeKid*: string
    keys*: Table[string, string]

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

proc nowUnix*(): int64 {.inline.} =
  getTime().toUnix()

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

proc initBearerTokenConfig*(
    issuer: string, audience: string, keys: openArray[SigningKey], activeKid = ""
): BearerTokenConfig =
  if issuer.strip().len == 0:
    raise newException(ValueError, "issuer must not be empty")
  if audience.strip().len == 0:
    raise newException(ValueError, "audience must not be empty")
  if keys.len == 0:
    raise newException(ValueError, "at least one signing key is required")

  result.issuer = issuer.strip()
  result.audience = audience.strip()
  result.keys = initTable[string, string]()

  for key in keys:
    let kid = key.kid.strip()
    let secret = key.secret.strip()
    if kid.len == 0 or secret.len == 0:
      raise
        newException(ValueError, "signing keys must include non-empty kid and secret")
    if kid in result.keys:
      raise newException(ValueError, "duplicate signing key id: " & kid)
    result.keys[kid] = secret

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

proc hmacSha256(message: string, secret: string): seq[byte] =
  signString(message, secret, HS256)

proc constantTimeEquals(lhs: string, rhs: string): bool =
  var diff = lhs.len xor rhs.len
  let compareLen = min(lhs.len, rhs.len)
  for idx in 0 ..< compareLen:
    diff = diff or (ord(lhs[idx]) xor ord(rhs[idx]))
  diff == 0

proc failure(statusCode: int, code: string, message: string): TokenValidationResult =
  TokenValidationResult(
    ok: false,
    failure:
      TokenValidationFailure(statusCode: statusCode, code: code, message: message),
  )

proc success(claims: BearerTokenClaims): TokenValidationResult =
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

proc extractKid(token: string, fallbackKid: string): string =
  let parts = token.split('.')
  if parts.len != 3:
    raise newException(ValueError, "malformed bearer token")

  let headerJson = parseJson(base64UrlDecode(parts[0]))
  if headerJson.kind != JObject:
    raise newException(ValueError, "invalid token header")

  if not headerJson.hasKey("alg"):
    raise newException(ValueError, "token header missing alg")
  if headerJson["alg"].kind != JString or headerJson["alg"].getStr() != "HS256":
    raise newException(ValueError, "token algorithm is not allowed")

  if headerJson.hasKey("typ"):
    if headerJson["typ"].kind != JString or headerJson["typ"].getStr() != "JWT":
      raise newException(ValueError, "token typ must be JWT")

  if headerJson.hasKey("kid"):
    if headerJson["kid"].kind != JString:
      raise newException(ValueError, "token kid must be a string")
    let kid = headerJson["kid"].getStr().strip()
    if kid.len == 0:
      raise newException(ValueError, "token kid is empty")
    return kid

  fallbackKid

proc mintBearerToken*(config: BearerTokenConfig, spec: BearerTokenSpec): string =
  if config.activeKid.len == 0 or config.activeKid notin config.keys:
    raise newException(ValueError, "activeKid does not reference a configured key")
  if spec.subject.strip().len == 0:
    raise newException(ValueError, "subject must not be empty")
  if spec.expiresAt <= spec.notBefore:
    raise newException(ValueError, "expiresAt must be greater than notBefore")

  let headerJson = %*{"alg": "HS256", "typ": "JWT", "kid": config.activeKid}

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

  signingInput & "." & signaturePart

proc validateBearerToken*(
    config: BearerTokenConfig,
    token: string,
    requiredScopes: openArray[string] = [],
    now = nowUnix(),
): TokenValidationResult =
  let trimmedToken = token.strip()
  if trimmedToken.len == 0:
    return failure(401, "missing_token", "Missing bearer token")

  try:
    let tokenParts = trimmedToken.split('.')
    if tokenParts.len != 3:
      return failure(401, "invalid_token", "Malformed bearer token")

    let kid = extractKid(trimmedToken, config.activeKid)
    if kid notin config.keys:
      return failure(401, "invalid_token", "Unknown token key id")

    let signingInput = tokenParts[0] & "." & tokenParts[1]
    let expectedSignature =
      base64UrlEncodeBytes(hmacSha256(signingInput, config.keys[kid]))
    if not constantTimeEquals(expectedSignature, tokenParts[2]):
      return failure(401, "invalid_token", "Token signature is invalid")

    let payload = parseJson(base64UrlDecode(tokenParts[1]))
    if payload.kind != JObject:
      return failure(401, "invalid_token", "Token payload is invalid")

    let iss = jsonStringClaim(payload, "iss")
    if iss.isNone() or iss.get() != config.issuer:
      return failure(401, "invalid_token", "Token issuer is invalid")

    let sub = jsonStringClaim(payload, "sub")
    if sub.isNone() or sub.get().strip().len == 0:
      return failure(401, "invalid_token", "Token subject is invalid")

    if not payloadMatchesAudience(payload, config.audience):
      return failure(401, "invalid_token", "Token audience is invalid")

    let nbf = jsonIntClaim(payload, "nbf")
    if nbf.isSome() and now < nbf.get():
      return failure(401, "invalid_token", "Token is not valid yet")

    let exp = jsonIntClaim(payload, "exp")
    if exp.isNone():
      return failure(401, "invalid_token", "Token is missing exp")
    if now >= exp.get():
      return failure(401, "invalid_token", "Token is expired")

    let iat =
      if payload.hasKey("iat"):
        jsonIntClaim(payload, "iat").get(0)
      else:
        0'i64
    let tokenId = jsonStringClaim(payload, "jti").get("")
    let tokenScopes = parseScopeClaim(payload)
    if not hasAllScopes(tokenScopes, requiredScopes):
      return failure(403, "insufficient_scope", "Token scope is insufficient")

    return success(
      BearerTokenClaims(
        issuer: iss.get(),
        subject: sub.get().strip(),
        audience: config.audience,
        scopes: tokenScopes,
        tokenId: tokenId,
        keyId: kid,
        issuedAt: iat,
        notBefore: nbf.get(iat),
        expiresAt: exp.get(),
      )
    )
  except CatchableError as e:
    failure(401, "invalid_token", e.msg)

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
