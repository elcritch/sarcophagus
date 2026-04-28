import std/[options, tables, unittest]

import sarcophagus/[core/jwt_bearer_tokens, security/password_login]
import sarcophagus/security/secret_hashing

proc testConfig(): PasswordLoginConfig =
  initPasswordLoginConfig(
    initBearerTokenConfig(
      issuer = "password-login-test",
      audience = "browser-session",
      keys = [SigningKey(kid: "v1", secret: "session-secret")],
    ),
    sessionTtlSeconds = 600,
  )

proc loadCallback(
    accounts: Table[string, PasswordLoginAccount]
): PasswordLoginAccountLoader =
  result = proc(username: string): Option[PasswordLoginAccount] {.gcsafe.} =
    {.cast(gcsafe).}:
      if username in accounts:
        some(accounts[username])
      else:
        none(PasswordLoginAccount)

suite "password login core":
  test "verifies credentials and mints a signed session":
    let policy = fastSecretHashPolicy()
    var accounts = initTable[string, PasswordLoginAccount]()
    accounts["alice"] = seedPasswordLoginAccount(
      username = "alice",
      password = "correct horse battery staple",
      subject = "user-123",
      displayName = "Alice Example",
      scopes = ["profile:read", "notes:write"],
      policy = policy,
    )

    let config = testConfig()
    let verifier = passwordLoginVerifier(accounts.loadCallback(), policy)
    let login = authenticatePasswordLogin(
      config,
      verifier,
      username = "alice",
      password = "correct horse battery staple",
      now = 1_700_000_000,
    )

    check login.ok
    check login.user.subject == "user-123"
    check login.user.displayName == "Alice Example"
    check login.expiresAt == 1_700_000_600

    let session =
      validatePasswordLoginSession(config, login.sessionToken, now = 1_700_000_010)
    check session.ok
    check session.session.subject == "user-123"
    check session.session.scopes == @["profile:read", "notes:write"]

  test "rejects bad passwords, disabled users, and expired sessions":
    let policy = fastSecretHashPolicy()
    var accounts = initTable[string, PasswordLoginAccount]()
    accounts["alice"] = seedPasswordLoginAccount(
      username = "alice",
      password = "secret",
      scopes = ["profile:read"],
      policy = policy,
    )
    accounts["disabled"] = seedPasswordLoginAccount(
      username = "disabled",
      password = "secret",
      scopes = ["profile:read"],
      enabled = false,
      policy = policy,
    )

    let config = testConfig()
    let verifier = passwordLoginVerifier(accounts.loadCallback(), policy)

    let wrongPassword = authenticatePasswordLogin(
      config, verifier, username = "alice", password = "wrong", now = 1_700_000_000
    )
    check not wrongPassword.ok
    check wrongPassword.failure.code == "invalid_credentials"

    let disabled = authenticatePasswordLogin(
      config, verifier, username = "disabled", password = "secret", now = 1_700_000_000
    )
    check not disabled.ok
    check disabled.failure.code == "invalid_credentials"

    let login = authenticatePasswordLogin(
      config, verifier, username = "alice", password = "secret", now = 1_700_000_000
    )
    check login.ok

    let expired =
      validatePasswordLoginSession(config, login.sessionToken, now = 1_700_000_600)
    check not expired.ok
    check expired.failure.code == "invalid_token"

  test "supports request-aware login decisions for policy callbacks":
    let config = testConfig()
    let verifier = proc(
        context: PasswordLoginContext, username, password: string
    ): PasswordLoginDecision {.gcsafe.} =
      if context.remoteAddress == "198.51.100.7":
        return rateLimitPasswordLogin(30)
      if username == "mfa":
        return requirePasswordLoginMfa()
      if username == "alice" and password == "secret":
        return allowPasswordLogin(
          initPasswordLoginUser(
            subject = "user-123",
            username = "alice",
            displayName = "Alice Example",
            scopes = ["profile:read"],
          )
        )
      denyPasswordLogin()

    let allowed = authenticatePasswordLogin(
      config,
      verifier,
      username = "alice",
      password = "secret",
      context = passwordLoginContext(remoteAddress = "203.0.113.9"),
      now = 1_700_000_000,
    )
    check allowed.ok

    let limited = authenticatePasswordLogin(
      config,
      verifier,
      username = "alice",
      password = "secret",
      context = passwordLoginContext(remoteAddress = "198.51.100.7"),
      now = 1_700_000_000,
    )
    check not limited.ok
    check limited.failure.statusCode == 429
    check limited.failure.code == "rate_limited"
    check limited.failure.retryAfterSeconds == 30

    let mfa = authenticatePasswordLogin(
      config,
      verifier,
      username = "mfa",
      password = "secret",
      context = passwordLoginContext(remoteAddress = "203.0.113.9"),
      now = 1_700_000_000,
    )
    check not mfa.ok
    check mfa.failure.code == "mfa_required"
