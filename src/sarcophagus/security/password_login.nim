import std/[options, sets, strutils]

import ../core/jwt_bearer_tokens
import ./secret_hashing

type
  PasswordLoginUser* = object
    ## Authenticated user returned by application-owned credential callbacks.
    subject*: string
    username*: string
    displayName*: string
    scopes*: seq[string]

  PasswordLoginAccount* = object
    ## Optional account shape for applications that want Sarcophagus to verify
    ## a stored password hash after loading user records through a callback.
    username*: string
    subject*: string
    displayName*: string
    passwordHash*: string
    scopes*: seq[string]
    enabled*: bool

  PasswordLoginConfig* = object ## Configuration for signed browser login sessions.
    sessionConfig*: BearerTokenConfig
    sessionTtlSeconds*: int
    sessionScopes*: seq[string]

  PasswordLoginContext* = object
    ## Request-adjacent metadata for verifier callbacks.
    ##
    ## The core stays HTTP-framework agnostic. Mummy or TAPIS login handlers can
    ## populate these fields from a request before calling `authenticatePasswordLogin`.
    remoteAddress*: string
    userAgent*: string
    requestId*: string
    tenant*: string
    metadata*: seq[(string, string)]

  PasswordLoginDecisionKind* = enum
    passwordLoginAllowed
    passwordLoginDenied
    passwordLoginRateLimited
    passwordLoginMfaRequired

  PasswordLoginDecision* = object
    ## Rich verifier result for rate limiting, MFA, audit, and future policies.
    case kind*: PasswordLoginDecisionKind
    of passwordLoginAllowed:
      user*: PasswordLoginUser
    else:
      statusCode*: int
      code*: string
      message*: string
      retryAfterSeconds*: int

  PasswordLoginFailure* = object
    statusCode*: int
    code*: string
    message*: string
    retryAfterSeconds*: int

  PasswordLoginResult* = object
    ok*: bool
    user*: PasswordLoginUser
    sessionToken*: string
    expiresAt*: int64
    failure*: PasswordLoginFailure

  PasswordLoginSession* = object
    subject*: string
    scopes*: seq[string]
    tokenId*: string
    issuedAt*: int64
    notBefore*: int64
    expiresAt*: int64

  PasswordLoginSessionResult* = object
    ok*: bool
    session*: PasswordLoginSession
    failure*: PasswordLoginFailure

  PasswordLoginVerifier* =
    proc(username, password: string): Option[PasswordLoginUser] {.gcsafe.}
    ## Callback that verifies application-owned username/password credentials.

  PasswordLoginDecisionVerifier* = proc(
    context: PasswordLoginContext, username, password: string
  ): PasswordLoginDecision {.gcsafe.}
    ## Request-aware callback for login policy, rate limiting, MFA, and auditing.

  PasswordLoginAccountLoader* =
    proc(username: string): Option[PasswordLoginAccount] {.gcsafe.}
    ## Callback used by `passwordLoginVerifier` to load account records.

const DefaultPasswordLoginSessionScope* = "session:login"

proc failure(statusCode: int, code, message: string): PasswordLoginResult =
  PasswordLoginResult(
    ok: false,
    failure: PasswordLoginFailure(statusCode: statusCode, code: code, message: message),
  )

proc failure(decision: PasswordLoginDecision): PasswordLoginResult =
  let statusCode =
    if decision.statusCode > 0:
      decision.statusCode
    else:
      case decision.kind
      of passwordLoginRateLimited: 429
      of passwordLoginMfaRequired: 403
      else: 401
  let code =
    if decision.code.len > 0:
      decision.code
    else:
      case decision.kind
      of passwordLoginRateLimited: "rate_limited"
      of passwordLoginMfaRequired: "mfa_required"
      else: "invalid_credentials"
  let message =
    if decision.message.len > 0:
      decision.message
    else:
      case decision.kind
      of passwordLoginRateLimited: "Too many login attempts"
      of passwordLoginMfaRequired: "Multi-factor authentication is required"
      else: "Username or password is invalid"
  PasswordLoginResult(
    ok: false,
    failure: PasswordLoginFailure(
      statusCode: statusCode,
      code: code,
      message: message,
      retryAfterSeconds: decision.retryAfterSeconds,
    ),
  )

proc sessionFailure(
    statusCode: int, code, message: string
): PasswordLoginSessionResult =
  PasswordLoginSessionResult(
    ok: false,
    failure: PasswordLoginFailure(statusCode: statusCode, code: code, message: message),
  )

proc normalizeScopes(scopes: openArray[string]): seq[string] =
  parseScopeList(scopes.join(" "))

proc passwordLoginContext*(
    remoteAddress = "",
    userAgent = "",
    requestId = "",
    tenant = "",
    metadata: openArray[(string, string)] = [],
): PasswordLoginContext =
  ## Builds request-adjacent login context for decision verifier callbacks.
  PasswordLoginContext(
    remoteAddress: remoteAddress.strip(),
    userAgent: userAgent.strip(),
    requestId: requestId.strip(),
    tenant: tenant.strip(),
    metadata: @metadata,
  )

proc metadataValue*(context: PasswordLoginContext, key: string): Option[string] =
  ## Returns the first metadata value for `key`.
  for (candidateKey, value) in context.metadata:
    if candidateKey == key:
      return some(value)
  none(string)

proc allowPasswordLogin*(user: PasswordLoginUser): PasswordLoginDecision =
  ## Allows login for an authenticated user.
  PasswordLoginDecision(kind: passwordLoginAllowed, user: user)

proc denyPasswordLogin*(
    code = "invalid_credentials",
    message = "Username or password is invalid",
    statusCode = 401,
): PasswordLoginDecision =
  ## Denies login with a policy-specific code and message.
  PasswordLoginDecision(
    kind: passwordLoginDenied, statusCode: statusCode, code: code, message: message
  )

proc rateLimitPasswordLogin*(
    retryAfterSeconds: int,
    code = "rate_limited",
    message = "Too many login attempts",
    statusCode = 429,
): PasswordLoginDecision =
  ## Denies login because the caller is rate limited.
  PasswordLoginDecision(
    kind: passwordLoginRateLimited,
    statusCode: statusCode,
    code: code,
    message: message,
    retryAfterSeconds: retryAfterSeconds,
  )

proc requirePasswordLoginMfa*(
    code = "mfa_required",
    message = "Multi-factor authentication is required",
    statusCode = 403,
): PasswordLoginDecision =
  ## Denies login because an additional MFA step is required.
  PasswordLoginDecision(
    kind: passwordLoginMfaRequired, statusCode: statusCode, code: code, message: message
  )

proc toDecisionVerifier*(
    verifier: PasswordLoginVerifier
): PasswordLoginDecisionVerifier =
  ## Adapts the simple username/password verifier into a decision verifier.
  result = proc(
      context: PasswordLoginContext, username, password: string
  ): PasswordLoginDecision {.gcsafe.} =
    discard context
    let user = verifier(username, password)
    if user.isSome:
      allowPasswordLogin(user.get())
    else:
      denyPasswordLogin()

proc initPasswordLoginConfig*(
    sessionConfig: BearerTokenConfig,
    sessionTtlSeconds = 3600,
    sessionScopes: openArray[string] = [DefaultPasswordLoginSessionScope],
): PasswordLoginConfig =
  ## Builds password-login session configuration.
  if sessionTtlSeconds <= 0:
    raise newException(ValueError, "sessionTtlSeconds must be positive")

  result.sessionConfig = sessionConfig
  result.sessionTtlSeconds = sessionTtlSeconds
  result.sessionScopes = normalizeScopes(sessionScopes)
  if result.sessionScopes.len == 0:
    raise newException(ValueError, "sessionScopes must not be empty")

proc initPasswordLoginUser*(
    subject: string, username = "", displayName = "", scopes: openArray[string] = []
): PasswordLoginUser =
  ## Builds an authenticated user returned by a verifier callback.
  let effectiveSubject = subject.strip()
  if effectiveSubject.len == 0:
    raise newException(ValueError, "subject must not be empty")

  PasswordLoginUser(
    subject: effectiveSubject,
    username: username.strip(),
    displayName: displayName.strip(),
    scopes: normalizeScopes(scopes),
  )

proc initPasswordLoginAccount*(
    username: string,
    passwordHash: string,
    scopes: openArray[string] = [],
    subject = "",
    displayName = "",
    enabled = true,
): PasswordLoginAccount =
  ## Builds an account record around an already encoded password hash.
  let effectiveUsername = username.strip()
  if effectiveUsername.len == 0:
    raise newException(ValueError, "username must not be empty")
  if passwordHash.strip().len == 0:
    raise newException(ValueError, "passwordHash must not be empty")

  PasswordLoginAccount(
    username: effectiveUsername,
    subject:
      if subject.strip().len > 0:
        subject.strip()
      else:
        effectiveUsername,
    displayName: displayName.strip(),
    passwordHash: passwordHash,
    scopes: normalizeScopes(scopes),
    enabled: enabled,
  )

proc seedPasswordLoginAccount*(
    username, password: string,
    scopes: openArray[string] = [],
    subject = "",
    displayName = "",
    enabled = true,
    policy = defaultSecretHashPolicy(),
): PasswordLoginAccount =
  ## Hashes a plaintext password and returns an account record for persistence.
  initPasswordLoginAccount(
    username,
    hashSecret(password, policy),
    scopes = scopes,
    subject = subject,
    displayName = displayName,
    enabled = enabled,
  )

proc toPasswordLoginUser*(account: PasswordLoginAccount): PasswordLoginUser =
  ## Converts an account record to an authenticated user.
  initPasswordLoginUser(
    subject = account.subject,
    username = account.username,
    displayName = account.displayName,
    scopes = account.scopes,
  )

proc verifyPasswordLoginAccount*(
    account: PasswordLoginAccount, password: string, policy = defaultSecretHashPolicy()
): Option[PasswordLoginUser] =
  ## Verifies a password against a loaded account's encoded hash.
  if not account.enabled:
    return none(PasswordLoginUser)
  if not verifySecret(password, account.passwordHash, policy):
    return none(PasswordLoginUser)
  some(account.toPasswordLoginUser())

proc passwordLoginVerifier*(
    loadAccount: PasswordLoginAccountLoader, policy = defaultSecretHashPolicy()
): PasswordLoginVerifier =
  ## Creates a verifier callback from an account-loader callback.
  result = proc(username, password: string): Option[PasswordLoginUser] {.gcsafe.} =
    let account = loadAccount(username.strip())
    if account.isNone:
      return none(PasswordLoginUser)
    verifyPasswordLoginAccount(account.get(), password, policy)

proc sessionTokenScopes(
    config: PasswordLoginConfig, userScopes: openArray[string]
): seq[string] =
  var scopes = config.sessionScopes
  for scope in userScopes:
    scopes.add(scope)
  normalizeScopes(scopes)

proc authenticatePasswordLogin*(
    config: PasswordLoginConfig,
    verifyCredentials: PasswordLoginDecisionVerifier,
    username, password: string,
    context = passwordLoginContext(),
    now = nowUnix(),
): PasswordLoginResult =
  ## Verifies username/password credentials and mints a signed login session.
  if username.strip().len == 0 or password.len == 0:
    return failure(401, "invalid_credentials", "Username or password is invalid")

  let decision = verifyCredentials(context, username, password)
  if decision.kind != passwordLoginAllowed:
    return failure(decision)
  if decision.user.subject.strip().len == 0:
    return failure(500, "invalid_user", "Verifier returned an invalid user")

  let token = mintBearerToken(
    config.sessionConfig,
    initBearerTokenSpec(
      subject = decision.user.subject,
      scopes = sessionTokenScopes(config, decision.user.scopes),
      ttlSeconds = config.sessionTtlSeconds,
      issuedAt = now,
    ),
  )

  PasswordLoginResult(
    ok: true,
    user: decision.user,
    sessionToken: token,
    expiresAt: now + int64(config.sessionTtlSeconds),
  )

proc authenticatePasswordLogin*(
    config: PasswordLoginConfig,
    verifyCredentials: PasswordLoginVerifier,
    username, password: string,
    now = nowUnix(),
): PasswordLoginResult =
  ## Verifies username/password credentials using the simple verifier callback.
  authenticatePasswordLogin(
    config,
    verifyCredentials.toDecisionVerifier(),
    username,
    password,
    passwordLoginContext(),
    now,
  )

proc userScopesFromSession(tokenScopes, sessionScopes: openArray[string]): seq[string] =
  var reserved = initHashSet[string]()
  for scope in sessionScopes:
    reserved.incl(scope)

  for scope in tokenScopes:
    if scope notin reserved:
      result.add(scope)

proc validatePasswordLoginSession*(
    config: PasswordLoginConfig, sessionToken: string, now = nowUnix()
): PasswordLoginSessionResult =
  ## Validates a signed login session token.
  let validation = validateBearerToken(
    config.sessionConfig, sessionToken, config.sessionScopes, now = now
  )
  if not validation.ok:
    return sessionFailure(
      validation.failure.statusCode, validation.failure.code, validation.failure.message
    )

  PasswordLoginSessionResult(
    ok: true,
    session: PasswordLoginSession(
      subject: validation.claims.subject,
      scopes: userScopesFromSession(validation.claims.scopes, config.sessionScopes),
      tokenId: validation.claims.tokenId,
      issuedAt: validation.claims.issuedAt,
      notBefore: validation.claims.notBefore,
      expiresAt: validation.claims.expiresAt,
    ),
  )
