import std/[base64, json, strutils, tables]

import ./jwt_bearer_tokens

type
  OAuth2ClientAuthMethod* = enum
    oauth2ClientAuthNone
    oauth2ClientAuthBasic
    oauth2ClientAuthRequestBody

  OAuth2Client* = object
    clientId*: string
    clientSecret*: string
    subject*: string
    allowedScopes*: seq[string]
    defaultScopes*: seq[string]
    accessTokenTtlSeconds*: int

  OAuth2Config* = object
    realm*: string
    tokenConfig*: BearerTokenConfig
    clients*: Table[string, OAuth2Client]
    accessTokenTtlSeconds*: int

  OAuth2TokenResponse* = object
    accessToken*: string
    tokenType*: string
    expiresIn*: int
    scope*: string

  OAuth2Failure* = object
    statusCode*: int
    error*: string
    errorDescription*: string
    errorUri*: string
    wwwAuthenticate*: string

  OAuth2TokenResult* = object
    ok*: bool
    response*: OAuth2TokenResponse
    failure*: OAuth2Failure

  OAuth2ResourceResult* = object
    ok*: bool
    claims*: BearerTokenClaims
    failure*: OAuth2Failure

  OAuth2ScopeClaim* = tuple[name: string, value: string]

type ParsedAuthorizationHeader = object
  present: bool
  malformed: bool
  scheme: string
  credentials: string

proc constantTimeEquals(lhs: string, rhs: string): bool =
  var diff = lhs.len xor rhs.len
  let compareLen = min(lhs.len, rhs.len)
  for idx in 0 ..< compareLen:
    diff = diff or (ord(lhs[idx]) xor ord(rhs[idx]))
  diff == 0

proc decodeHexNibble(c: char): int =
  case c
  of '0' .. '9':
    ord(c) - ord('0')
  of 'a' .. 'f':
    10 + ord(c) - ord('a')
  of 'A' .. 'F':
    10 + ord(c) - ord('A')
  else:
    -1

proc decodeFormComponent(input: string): string =
  result = newStringOfCap(input.len)
  var idx = 0
  while idx < input.len:
    case input[idx]
    of '+':
      result.add(' ')
    of '%':
      if idx + 2 >= input.len:
        raise newException(ValueError, "invalid percent encoding")
      let hi = decodeHexNibble(input[idx + 1])
      let lo = decodeHexNibble(input[idx + 2])
      if hi < 0 or lo < 0:
        raise newException(ValueError, "invalid percent encoding")
      result.add(char((hi shl 4) or lo))
      idx += 2
    else:
      result.add(input[idx])
    inc idx

proc sanitizeHeaderValue(input: string): string =
  for ch in input:
    if ch == '"' or ch == '\\':
      result.add('\\')
      result.add(ch)
    elif ch >= ' ' and ch <= '~':
      result.add(ch)

proc parseAuthorizationHeader(header: string): ParsedAuthorizationHeader =
  let trimmed = header.strip()
  if trimmed.len == 0:
    return

  result.present = true
  let separator = trimmed.find({' ', '\t'})
  if separator <= 0:
    result.malformed = true
    return

  result.scheme = trimmed[0 ..< separator].toLowerAscii()
  result.credentials = trimmed[separator + 1 .. ^1].strip()
  if result.credentials.len == 0:
    result.malformed = true

proc buildChallenge(
    scheme: string,
    realm: string,
    error = "",
    errorDescription = "",
    errorUri = "",
    scope = "",
): string =
  result = scheme & " realm=\"" & sanitizeHeaderValue(realm) & "\""

  if error.len > 0:
    result.add(", error=\"" & sanitizeHeaderValue(error) & "\"")
  if errorDescription.len > 0:
    result.add(", error_description=\"" & sanitizeHeaderValue(errorDescription) & "\"")
  if errorUri.len > 0:
    result.add(", error_uri=\"" & sanitizeHeaderValue(errorUri) & "\"")
  if scope.len > 0:
    result.add(", scope=\"" & sanitizeHeaderValue(scope) & "\"")

proc tokenFailure(
    statusCode: int,
    error: string,
    errorDescription: string,
    wwwAuthenticate = "",
    errorUri = "",
): OAuth2TokenResult =
  OAuth2TokenResult(
    ok: false,
    failure: OAuth2Failure(
      statusCode: statusCode,
      error: error,
      errorDescription: errorDescription,
      errorUri: errorUri,
      wwwAuthenticate: wwwAuthenticate,
    ),
  )

proc tokenSuccess(response: OAuth2TokenResponse): OAuth2TokenResult =
  OAuth2TokenResult(ok: true, response: response)

proc resourceFailure(
    statusCode: int,
    error: string,
    errorDescription: string,
    wwwAuthenticate: string,
    errorUri = "",
): OAuth2ResourceResult =
  OAuth2ResourceResult(
    ok: false,
    failure: OAuth2Failure(
      statusCode: statusCode,
      error: error,
      errorDescription: errorDescription,
      errorUri: errorUri,
      wwwAuthenticate: wwwAuthenticate,
    ),
  )

proc resourceSuccess(claims: BearerTokenClaims): OAuth2ResourceResult =
  OAuth2ResourceResult(ok: true, claims: claims)

proc parseRequestParams(body: string): Table[string, string] =
  result = initTable[string, string]()
  if body.len == 0:
    return

  for pair in body.split('&'):
    if pair.len == 0:
      continue

    let parts = pair.split('=', maxsplit = 1)
    let key = decodeFormComponent(parts[0]).strip()
    if key.len == 0:
      continue

    let value =
      if parts.len == 2:
        decodeFormComponent(parts[1])
      else:
        ""

    if value.len == 0:
      continue
    if key in result:
      raise newException(ValueError, "duplicate parameter: " & key)
    result[key] = value

proc parseJsonRequestParams(body: string): Table[string, string] =
  result = initTable[string, string]()
  if body.strip().len == 0:
    return

  let payload =
    try:
      parseJson(body)
    except CatchableError as e:
      raise newException(ValueError, "invalid json request body: " & e.msg)

  if payload.kind != JObject:
    raise newException(ValueError, "json request body must be an object")

  for key, value in payload:
    case value.kind
    of JString:
      result[key] = value.getStr()
    of JNull:
      discard
    else:
      raise newException(ValueError, "json request parameters must be strings or null")

proc parseBasicCredentials(
    authorizationHeader: ParsedAuthorizationHeader
): tuple[clientId: string, clientSecret: string] =
  let decoded =
    try:
      decode(authorizationHeader.credentials)
    except CatchableError:
      raise newException(ValueError, "invalid basic authorization encoding")

  let separator = decoded.find(':')
  if separator < 0:
    raise newException(ValueError, "invalid basic authorization credentials")

  (
    decodeFormComponent(decoded[0 ..< separator]),
    decodeFormComponent(decoded[separator + 1 .. ^1]),
  )

proc validateRequestedScopes(
    client: OAuth2Client, requestedScopes: openArray[string]
): bool =
  hasAllScopes(client.allowedScopes, requestedScopes)

proc resolveRequestedScopes(
    client: OAuth2Client, requestedScopeParam: string
): seq[string] =
  if requestedScopeParam.len > 0:
    return parseScopeList(requestedScopeParam)

  if client.defaultScopes.len > 0:
    return client.defaultScopes

  client.allowedScopes

proc scopeClaimsToScopes*(requiredClaims: openArray[OAuth2ScopeClaim]): seq[string] =
  for (name, value) in requiredClaims:
    let trimmedName = name.strip()
    let trimmedValue = value.strip()
    if trimmedName.len == 0:
      raise newException(ValueError, "scope claim name must not be empty")
    if trimmedValue.len == 0:
      raise newException(ValueError, "scope claim value must not be empty")
    result.add(trimmedName & ":" & trimmedValue)

proc isFormUrlEncodedContentType*(contentType: string): bool =
  let mediaType = contentType.split(';', maxsplit = 1)[0].strip().toLowerAscii()
  mediaType == "application/x-www-form-urlencoded"

proc isJsonContentType*(contentType: string): bool =
  let mediaType = contentType.split(';', maxsplit = 1)[0].strip().toLowerAscii()
  mediaType == "application/json"

proc initOAuth2Client*(
    clientId: string,
    clientSecret: string,
    allowedScopes: openArray[string],
    defaultScopes: openArray[string] = [],
    subject = "",
    accessTokenTtlSeconds = 0,
): OAuth2Client =
  let effectiveClientId = clientId.strip()
  if effectiveClientId.len == 0:
    raise newException(ValueError, "clientId must not be empty")
  if accessTokenTtlSeconds < 0:
    raise newException(ValueError, "accessTokenTtlSeconds must not be negative")

  result.clientId = effectiveClientId
  result.clientSecret = clientSecret
  result.allowedScopes = parseScopeList(allowedScopes.join(" "))
  result.defaultScopes = parseScopeList(defaultScopes.join(" "))
  result.subject =
    if subject.strip().len > 0:
      subject.strip()
    else:
      effectiveClientId
  result.accessTokenTtlSeconds = accessTokenTtlSeconds

  if not validateRequestedScopes(result, result.defaultScopes):
    raise newException(ValueError, "defaultScopes must be a subset of allowedScopes")

proc initOAuth2Config*(
    realm: string,
    tokenConfig: BearerTokenConfig,
    clients: openArray[OAuth2Client],
    accessTokenTtlSeconds = 3600,
): OAuth2Config =
  let effectiveRealm = realm.strip()
  if effectiveRealm.len == 0:
    raise newException(ValueError, "realm must not be empty")
  if accessTokenTtlSeconds <= 0:
    raise newException(ValueError, "accessTokenTtlSeconds must be positive")

  result.realm = effectiveRealm
  result.tokenConfig = tokenConfig
  result.clients = initTable[string, OAuth2Client]()
  result.accessTokenTtlSeconds = accessTokenTtlSeconds

  for client in clients:
    if client.clientId in result.clients:
      raise newException(ValueError, "duplicate clientId: " & client.clientId)
    result.clients[client.clientId] = client

proc toJson*(response: OAuth2TokenResponse): JsonNode =
  result =
    %*{
      "access_token": response.accessToken,
      "token_type": response.tokenType,
      "expires_in": response.expiresIn,
    }
  if response.scope.len > 0:
    result["scope"] = newJString(response.scope)

proc toJson*(failure: OAuth2Failure): JsonNode =
  result = %*{"error": failure.error}
  if failure.errorDescription.len > 0:
    result["error_description"] = newJString(failure.errorDescription)
  if failure.errorUri.len > 0:
    result["error_uri"] = newJString(failure.errorUri)

proc issueClientCredentialsToken*(
    config: OAuth2Config,
    authorizationHeader: string,
    contentType: string,
    requestBody: string,
    now = nowUnix(),
): OAuth2TokenResult =
  if not isFormUrlEncodedContentType(contentType) and not isJsonContentType(contentType):
    return tokenFailure(
      400, "invalid_request",
      "Token requests must use application/x-www-form-urlencoded or application/json",
    )

  let params =
    try:
      if isJsonContentType(contentType):
        parseJsonRequestParams(requestBody)
      else:
        parseRequestParams(requestBody)
    except ValueError as e:
      return tokenFailure(400, "invalid_request", e.msg)

  let parsedAuth = parseAuthorizationHeader(authorizationHeader)
  if parsedAuth.present and parsedAuth.malformed:
    return tokenFailure(
      401,
      "invalid_client",
      "Client authentication is malformed",
      buildChallenge("Basic", config.realm),
    )

  let usesBasicAuth = parsedAuth.present and parsedAuth.scheme == "basic"
  let hasBodyClientId = "client_id" in params
  let hasBodyClientSecret = "client_secret" in params
  let usesBodyAuth = hasBodyClientId or hasBodyClientSecret

  if parsedAuth.present and parsedAuth.scheme != "basic":
    return tokenFailure(
      401,
      "invalid_client",
      "Unsupported client authentication method",
      buildChallenge("Basic", config.realm),
    )
  if usesBasicAuth and usesBodyAuth:
    return tokenFailure(
      400, "invalid_request",
      "The client must not use more than one authentication method",
    )

  let grantType = params.getOrDefault("grant_type", "client_credentials")
  if grantType != "client_credentials":
    return tokenFailure(
      400, "unsupported_grant_type", "Only the client_credentials grant is supported"
    )

  var clientId = ""
  var clientSecret = ""
  var authMethod = oauth2ClientAuthNone

  if usesBasicAuth:
    authMethod = oauth2ClientAuthBasic
    try:
      (clientId, clientSecret) = parseBasicCredentials(parsedAuth)
    except ValueError as e:
      return tokenFailure(
        401, "invalid_client", e.msg, buildChallenge("Basic", config.realm)
      )
  elif usesBodyAuth:
    authMethod = oauth2ClientAuthRequestBody
    clientId = params.getOrDefault("client_id", "")
    clientSecret = params.getOrDefault("client_secret", "")
  else:
    return tokenFailure(
      401,
      "invalid_client",
      "Client authentication is required",
      buildChallenge("Basic", config.realm),
    )

  let effectiveClientId = clientId.strip()
  if effectiveClientId.len == 0:
    return tokenFailure(
      401,
      "invalid_client",
      "Client identifier is required",
      buildChallenge("Basic", config.realm),
    )
  if effectiveClientId notin config.clients:
    return tokenFailure(
      401,
      "invalid_client",
      "Client authentication failed",
      buildChallenge("Basic", config.realm),
    )

  let client = config.clients[effectiveClientId]
  if not constantTimeEquals(client.clientSecret, clientSecret):
    return tokenFailure(
      401,
      "invalid_client",
      "Client authentication failed",
      buildChallenge("Basic", config.realm),
    )

  let requestedScopes = resolveRequestedScopes(client, params.getOrDefault("scope", ""))
  if not validateRequestedScopes(client, requestedScopes):
    return tokenFailure(
      400, "invalid_scope", "The requested scope is invalid for this client"
    )

  let ttlSeconds =
    if client.accessTokenTtlSeconds > 0:
      client.accessTokenTtlSeconds
    else:
      config.accessTokenTtlSeconds
  let token = mintBearerToken(
    config.tokenConfig,
    initBearerTokenSpec(
      subject = client.subject,
      scopes = requestedScopes,
      ttlSeconds = ttlSeconds,
      issuedAt = now,
    ),
  )

  discard authMethod
  tokenSuccess(
    OAuth2TokenResponse(
      accessToken: token,
      tokenType: "Bearer",
      expiresIn: ttlSeconds,
      scope: scopeListToString(requestedScopes),
    )
  )

proc validateOAuth2BearerToken*(
    config: OAuth2Config,
    authorizationHeader: string,
    requiredScopes: openArray[string] = [],
    now = nowUnix(),
): OAuth2ResourceResult =
  let parsedAuth = parseAuthorizationHeader(authorizationHeader)
  if not parsedAuth.present:
    return resourceFailure(401, "", "", buildChallenge("Bearer", config.realm))
  if parsedAuth.malformed:
    return resourceFailure(
      400,
      "invalid_request",
      "The Authorization header is malformed",
      buildChallenge(
        "Bearer",
        config.realm,
        error = "invalid_request",
        errorDescription = "The Authorization header is malformed",
      ),
    )
  if parsedAuth.scheme != "bearer":
    return resourceFailure(401, "", "", buildChallenge("Bearer", config.realm))

  let validation = validateBearerToken(
    config.tokenConfig, parsedAuth.credentials, requiredScopes, now = now
  )
  if validation.ok:
    return resourceSuccess(validation.claims)

  case validation.failure.code
  of "insufficient_scope":
    let scope = scopeListToString(requiredScopes)
    return resourceFailure(
      403,
      "insufficient_scope",
      validation.failure.message,
      buildChallenge(
        "Bearer",
        config.realm,
        error = "insufficient_scope",
        errorDescription = validation.failure.message,
        scope = scope,
      ),
    )
  of "missing_token":
    return resourceFailure(401, "", "", buildChallenge("Bearer", config.realm))
  else:
    return resourceFailure(
      401,
      "invalid_token",
      validation.failure.message,
      buildChallenge(
        "Bearer",
        config.realm,
        error = "invalid_token",
        errorDescription = validation.failure.message,
      ),
    )
