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

  PasswordLoginFailure* = object
    statusCode*: int
    code*: string
    message*: string

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

  PasswordLoginAccountLoader* =
    proc(username: string): Option[PasswordLoginAccount] {.gcsafe.}
    ## Callback used by `passwordLoginVerifier` to load account records.

const DefaultPasswordLoginSessionScope* = "session:login"

proc failure(statusCode: int, code, message: string): PasswordLoginResult =
  PasswordLoginResult(
    ok: false,
    failure: PasswordLoginFailure(statusCode: statusCode, code: code, message: message),
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
    verifyCredentials: PasswordLoginVerifier,
    username, password: string,
    now = nowUnix(),
): PasswordLoginResult =
  ## Verifies username/password credentials and mints a signed login session.
  if username.strip().len == 0 or password.len == 0:
    return failure(401, "invalid_credentials", "Username or password is invalid")

  let user = verifyCredentials(username, password)
  if user.isNone:
    return failure(401, "invalid_credentials", "Username or password is invalid")
  if user.get().subject.strip().len == 0:
    return failure(500, "invalid_user", "Verifier returned an invalid user")

  let token = mintBearerToken(
    config.sessionConfig,
    initBearerTokenSpec(
      subject = user.get().subject,
      scopes = sessionTokenScopes(config, user.get().scopes),
      ttlSeconds = config.sessionTtlSeconds,
      issuedAt = now,
    ),
  )

  PasswordLoginResult(
    ok: true,
    user: user.get(),
    sessionToken: token,
    expiresAt: now + int64(config.sessionTtlSeconds),
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
