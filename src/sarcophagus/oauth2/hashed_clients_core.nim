import std/[base64, json, options, strutils, tables]

import ../core/jwt_bearer_tokens
import ../security/secret_hashing
import ./core
import ./utils

type
  HashedOAuth2Client* = object
    ## OAuth2 client record with a hashed client secret.
    ##
    ## Store this shape, or map it onto your own DB row type before returning it
    ## from a `HashedOAuth2ClientLoader`.
    clientId*: string ## Public client identifier.
    secretHash*: string ## Encoded hash from `security/secret_hashing.hashSecret`.
    subject*: string ## JWT subject. Defaults to `clientId` when empty.
    scopes*: seq[string] ## Scopes this client may request.
    defaultScopes*: seq[string] ## Scopes issued when the token request omits `scope`.
    enabled*: bool ## Disabled clients are rejected before secret verification.
    accessTokenTtlSeconds*: int
      ## Per-client token TTL override. Zero uses `OAuth2Config.accessTokenTtlSeconds`.

  HashedOAuth2ClientCredentials* = object
    ## Plain credentials returned when seeding a client.
    clientId*: string
    clientSecret*: string

  HashedOAuth2AuditEvent* = object
    ## Token-attempt audit event emitted by `issueHashedClientCredentialsToken`.
    eventType*: string ## `token_minted` or `token_denied`.
    clientId*: string
    success*: bool
    reason*: string
      ## Machine-readable outcome such as `ok`, `invalid_client`, or `disabled_client`.
    scope*: string ## Requested or issued scope string when available.
    tokenId*: string ## JWT ID for successful token issuance.

  HashedOAuth2ClientLoader* =
    proc(clientId: string): Option[HashedOAuth2Client] {.gcsafe.}
    ## Loads a client record by ID.

  HashedOAuth2AuditProc* = proc(event: HashedOAuth2AuditEvent) {.gcsafe.}
    ## Receives best-effort audit events. Exceptions are swallowed.

  InMemoryHashedOAuth2ClientStore* = ref object
    ## Minimal in-memory store for tests, examples, and single-process tools.
    ##
    ## It is not synchronized. Use an application DB-backed loader/upsert pair
    ## for multi-threaded production servers.
    clients*: Table[string, HashedOAuth2Client]
    auditEvents*: seq[HashedOAuth2AuditEvent]

type ParsedAuthorizationHeader = object
  present: bool
  malformed: bool
  scheme: string
  credentials: string

proc noopHashedOAuth2Audit*(event: HashedOAuth2AuditEvent) {.gcsafe.} =
  ## Audit callback that intentionally discards events.
  discard event

proc randomOAuth2ClientId*(): string =
  ## Generates a random hex client ID.
  randomSecret(16)

proc randomOAuth2ClientSecret*(): string =
  ## Generates a random hex client secret.
  randomSecret(32)

proc initHashedOAuth2Client*(
    clientId: string,
    clientSecret: string,
    scopes: openArray[string] = [],
    defaultScopes: openArray[string] = [],
    subject = "",
    enabled = true,
    accessTokenTtlSeconds = 0,
    policy = defaultSecretHashPolicy(),
): HashedOAuth2Client =
  ## Builds a hashed OAuth2 client record from a plaintext secret.
  ##
  ## The plaintext secret is only used to compute `secretHash`; callers should
  ## return it to the operator once or discard it.
  let effectiveClientId = clientId.strip()
  if effectiveClientId.len == 0:
    raise newException(ValueError, "clientId must not be empty")
  if clientSecret.len == 0:
    raise newException(ValueError, "clientSecret must not be empty")
  if accessTokenTtlSeconds < 0:
    raise newException(ValueError, "accessTokenTtlSeconds must not be negative")

  result.clientId = effectiveClientId
  result.secretHash = hashSecret(clientSecret, policy)
  result.subject =
    if subject.strip().len > 0:
      subject.strip()
    else:
      effectiveClientId
  result.scopes = parseScopeList(scopes.join(" "))
  result.defaultScopes = parseScopeList(defaultScopes.join(" "))
  result.enabled = enabled
  result.accessTokenTtlSeconds = accessTokenTtlSeconds

  if not hasAllScopes(result.scopes, result.defaultScopes):
    raise newException(ValueError, "defaultScopes must be a subset of scopes")

proc seedHashedOAuth2Client*(
    upsertClient: proc(client: HashedOAuth2Client) {.gcsafe.},
    clientId = "",
    clientSecret = "",
    scopes: openArray[string] = [],
    defaultScopes: openArray[string] = [],
    subject = "",
    enabled = true,
    accessTokenTtlSeconds = 0,
    policy = defaultSecretHashPolicy(),
): HashedOAuth2ClientCredentials =
  ## Creates or updates a hashed client through `upsertClient`.
  ##
  ## If `clientId` or `clientSecret` are omitted, secure random values are
  ## generated. The returned plaintext secret is the only time it is available.
  let seededClientId =
    if clientId.strip().len > 0:
      clientId.strip()
    else:
      randomOAuth2ClientId()
  let seededClientSecret =
    if clientSecret.len > 0:
      clientSecret
    else:
      randomOAuth2ClientSecret()

  upsertClient(
    initHashedOAuth2Client(
      clientId = seededClientId,
      clientSecret = seededClientSecret,
      scopes = scopes,
      defaultScopes = defaultScopes,
      subject = subject,
      enabled = enabled,
      accessTokenTtlSeconds = accessTokenTtlSeconds,
      policy = policy,
    )
  )
  HashedOAuth2ClientCredentials(
    clientId: seededClientId, clientSecret: seededClientSecret
  )

proc newInMemoryHashedOAuth2ClientStore*(): InMemoryHashedOAuth2ClientStore =
  ## Creates an unsynchronized in-memory hashed-client store.
  InMemoryHashedOAuth2ClientStore(
    clients: initTable[string, HashedOAuth2Client](), auditEvents: @[]
  )

proc upsert*(
    store: InMemoryHashedOAuth2ClientStore, client: HashedOAuth2Client
) {.gcsafe.} =
  ## Inserts or replaces a client in an in-memory store.
  store.clients[client.clientId] = client

proc load*(
    store: InMemoryHashedOAuth2ClientStore, clientId: string
): Option[HashedOAuth2Client] {.gcsafe.} =
  ## Loads a client from an in-memory store.
  if clientId in store.clients:
    some(store.clients[clientId])
  else:
    none(HashedOAuth2Client)

proc audit*(
    store: InMemoryHashedOAuth2ClientStore, event: HashedOAuth2AuditEvent
) {.gcsafe.} =
  ## Appends an audit event to an in-memory store.
  store.auditEvents.add event

proc buildChallenge(scheme, realm: string): string =
  scheme & " realm=\"" & sanitizeHeaderValue(realm) & "\""

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

proc tokenFailure(
    statusCode: int, error: string, errorDescription: string, wwwAuthenticate = ""
): OAuth2TokenResult =
  OAuth2TokenResult(
    ok: false,
    failure: OAuth2Failure(
      statusCode: statusCode,
      error: error,
      errorDescription: errorDescription,
      wwwAuthenticate: wwwAuthenticate,
    ),
  )

proc tokenSuccess(response: OAuth2TokenResponse): OAuth2TokenResult =
  OAuth2TokenResult(ok: true, response: response)

proc auditAttempt(
    onAudit: HashedOAuth2AuditProc,
    clientId: string,
    success: bool,
    reason: string,
    scope = "",
    tokenId = "",
) =
  try:
    onAudit(
      HashedOAuth2AuditEvent(
        eventType: if success: "token_minted" else: "token_denied",
        clientId: clientId,
        success: success,
        reason: reason,
        scope: scope,
        tokenId: tokenId,
      )
    )
  except CatchableError:
    discard

proc resolveScopes(
    client: HashedOAuth2Client, requestedScopeParam: string
): seq[string] =
  if requestedScopeParam.len > 0:
    return parseScopeList(requestedScopeParam)
  if client.defaultScopes.len > 0:
    return client.defaultScopes
  client.scopes

proc dummySecretHash(policy: SecretHashPolicy): string =
  let prefix = if policy.prefix.len > 0: policy.prefix else: SecretHashPrefix
  let saltBytes =
    if policy.saltBytes > 0 and policy.saltBytes <= SecretHashMaxSaltBytes:
      policy.saltBytes
    else:
      SecretHashSaltBytes
  let salt = "0".repeat(saltBytes * 2)
  let digest = "0".repeat(SecretHashDigestBytes * 2)
  case policy.algorithm
  of secretHashPbkdf2Sha256:
    prefix & "$" & $policy.iterations & "$" & salt & "$" & digest
  of secretHashHmacSha256:
    prefix & "$" & salt & "$" & digest

proc verifyDummySecret(clientSecret: string, policy: SecretHashPolicy) =
  discard verifySecret(clientSecret, dummySecretHash(policy), policy)

proc issueHashedClientCredentialsToken*(
    config: OAuth2Config,
    loadClient: HashedOAuth2ClientLoader,
    authorizationHeader: string,
    contentType: string,
    requestBody: string,
    onAudit: HashedOAuth2AuditProc = noopHashedOAuth2Audit,
    policy = defaultSecretHashPolicy(),
    now = nowUnix(),
): OAuth2TokenResult =
  ## Issues a client-credentials token using hashed client secrets.
  ##
  ## This mirrors `oauth2/core.issueClientCredentialsToken`, but retrieves the
  ## client through `loadClient` and verifies `client_secret` with
  ## `verifySecret` instead of comparing a stored plaintext secret.
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
  let usesBodyAuth = "client_id" in params or "client_secret" in params
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
  if usesBasicAuth:
    try:
      (clientId, clientSecret) = parseBasicCredentials(parsedAuth)
    except ValueError as e:
      return tokenFailure(
        401, "invalid_client", e.msg, buildChallenge("Basic", config.realm)
      )
  elif usesBodyAuth:
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
  if effectiveClientId.len == 0 or clientSecret.len == 0:
    return tokenFailure(
      401,
      "invalid_client",
      "Client authentication is required",
      buildChallenge("Basic", config.realm),
    )

  let loadedClient =
    try:
      loadClient(effectiveClientId)
    except CatchableError:
      none(HashedOAuth2Client)

  if loadedClient.isNone():
    verifyDummySecret(clientSecret, policy)
    auditAttempt(onAudit, effectiveClientId, false, "unknown_client")
    return tokenFailure(
      401,
      "invalid_client",
      "Client authentication failed",
      buildChallenge("Basic", config.realm),
    )

  let client = loadedClient.get()
  if not client.enabled:
    verifyDummySecret(clientSecret, policy)
    auditAttempt(onAudit, effectiveClientId, false, "disabled_client")
    return tokenFailure(
      401,
      "invalid_client",
      "Client authentication failed",
      buildChallenge("Basic", config.realm),
    )

  if not verifySecret(clientSecret, client.secretHash, policy):
    auditAttempt(onAudit, effectiveClientId, false, "invalid_client")
    return tokenFailure(
      401,
      "invalid_client",
      "Client authentication failed",
      buildChallenge("Basic", config.realm),
    )

  let requestedScopes = resolveScopes(client, params.getOrDefault("scope", ""))
  if not hasAllScopes(client.scopes, requestedScopes):
    auditAttempt(
      onAudit,
      effectiveClientId,
      false,
      "invalid_scope",
      scopeListToString(requestedScopes),
    )
    return tokenFailure(
      400, "invalid_scope", "The requested scope is invalid for this client"
    )

  let ttlSeconds =
    if client.accessTokenTtlSeconds > 0:
      client.accessTokenTtlSeconds
    else:
      config.accessTokenTtlSeconds
  let tokenId = randomSecret(16)
  let token = mintBearerToken(
    config.tokenConfig,
    initBearerTokenSpec(
      subject = if client.subject.strip().len > 0: client.subject else: client.clientId,
      scopes = requestedScopes,
      ttlSeconds = ttlSeconds,
      issuedAt = now,
      tokenId = tokenId,
    ),
  )

  let scope = scopeListToString(requestedScopes)
  auditAttempt(onAudit, effectiveClientId, true, "ok", scope, tokenId)
  tokenSuccess(
    OAuth2TokenResponse(
      accessToken: token, tokenType: "Bearer", expiresIn: ttlSeconds, scope: scope
    )
  )
