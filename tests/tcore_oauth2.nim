import std/[json, options, strutils, unittest]

import sarcophagus/[core/jwt_bearer_tokens, oauth2/core]

proc testConfig(): OAuth2Config =
  let tokenConfig = initBearerTokenConfig(
    issuer = "sam-sync-server",
    audience = "sam-sync-api",
    keys = [SigningKey(kid: "v1", secret: "secret-a")],
  )

  initOAuth2Config(
    realm = "sam-sync",
    tokenConfig = tokenConfig,
    clients = [
      initOAuth2Client(
        clientId = "reader-app",
        clientSecret = "secret-reader",
        subject = "reader-service",
        allowedScopes = ["sync:read", "sync:write"],
        defaultScopes = ["sync:read"],
      )
    ],
    accessTokenTtlSeconds = 900,
  )

proc userLoginConfig(): OAuth2Config =
  let tokenConfig = initBearerTokenConfig(
    issuer = "sam-sync-server",
    audience = "sam-sync-api",
    keys = [SigningKey(kid: "v1", secret: "secret-a")],
  )

  initOAuth2Config(
    realm = "sam-sync",
    tokenConfig = tokenConfig,
    clients = [
      initOAuth2Client(
        clientId = "browser-client",
        clientSecret = "",
        subject = "browser-client",
        allowedScopes = ["sync:read", "sync:write"],
        defaultScopes = ["sync:read"],
        redirectUris = ["https://client.example/callback"],
        requirePkce = true,
      )
    ],
    accessTokenTtlSeconds = 900,
  )

proc saveCallback(
    store: InMemoryOAuth2AuthorizationCodeStore
): OAuth2AuthorizationCodeSaver =
  result = proc(authorizationCode: OAuth2AuthorizationCode) {.gcsafe.} =
    store.save(authorizationCode)

proc consumeCallback(
    store: InMemoryOAuth2AuthorizationCodeStore
): OAuth2AuthorizationCodeConsumer =
  result = proc(code: string): Option[OAuth2AuthorizationCode] {.gcsafe.} =
    store.consume(code)

suite "oauth2 client credentials":
  test "issues a bearer token for a valid basic-auth request":
    let config = testConfig()
    let result = issueClientCredentialsToken(
      config,
      authorizationHeader = "Basic cmVhZGVyLWFwcDpzZWNyZXQtcmVhZGVy",
      contentType = "application/x-www-form-urlencoded",
      requestBody = "grant_type=client_credentials&scope=sync%3Aread",
      now = 1_700_000_000,
    )

    check result.ok
    check result.response.tokenType == "Bearer"
    check result.response.expiresIn == 900
    check result.response.scope == "sync:read"

    let validation = validateOAuth2BearerToken(
      config,
      "Bearer " & result.response.accessToken,
      ["sync:read"],
      now = 1_700_000_010,
    )
    check validation.ok
    check validation.claims.subject == "reader-service"
    check validation.claims.scopes == @["sync:read"]

  test "supports request-body client authentication":
    let config = testConfig()
    let result = issueClientCredentialsToken(
      config,
      authorizationHeader = "",
      contentType = "application/x-www-form-urlencoded; charset=utf-8",
      requestBody =
        "grant_type=client_credentials&client_id=reader-app&client_secret=secret-reader",
      now = 1_700_000_000,
    )

    check result.ok
    check result.response.scope == "sync:read"

  test "supports json request-body auth without grant_type or scope":
    let config = testConfig()
    let result = issueClientCredentialsToken(
      config,
      authorizationHeader = "",
      contentType = "application/json",
      requestBody = """{"client_id":"reader-app","client_secret":"secret-reader"}""",
      now = 1_700_000_000,
    )

    check result.ok
    check result.response.scope == "sync:read"
    let validation = validateOAuth2BearerToken(
      config,
      "Bearer " & result.response.accessToken,
      ["sync:read"],
      now = 1_700_000_010,
    )
    check validation.ok
    check validation.claims.subject == "reader-service"

  test "rejects multiple client authentication methods":
    let config = testConfig()
    let result = issueClientCredentialsToken(
      config,
      authorizationHeader = "Basic cmVhZGVyLWFwcDpzZWNyZXQtcmVhZGVy",
      contentType = "application/x-www-form-urlencoded",
      requestBody =
        "grant_type=client_credentials&client_id=reader-app&client_secret=secret-reader",
    )

    check not result.ok
    check result.failure.statusCode == 400
    check result.failure.error == "invalid_request"

  test "rejects unsupported grant types":
    let config = testConfig()
    let result = issueClientCredentialsToken(
      config,
      authorizationHeader = "Basic cmVhZGVyLWFwcDpzZWNyZXQtcmVhZGVy",
      contentType = "application/x-www-form-urlencoded",
      requestBody = "grant_type=authorization_code",
    )

    check not result.ok
    check result.failure.statusCode == 400
    check result.failure.error == "unsupported_grant_type"

  test "rejects invalid scopes":
    let config = testConfig()
    let result = issueClientCredentialsToken(
      config,
      authorizationHeader = "Basic cmVhZGVyLWFwcDpzZWNyZXQtcmVhZGVy",
      contentType = "application/x-www-form-urlencoded",
      requestBody = "grant_type=client_credentials&scope=admin",
    )

    check not result.ok
    check result.failure.statusCode == 400
    check result.failure.error == "invalid_scope"

  test "rejects bad client credentials with a basic challenge":
    let config = testConfig()
    let result = issueClientCredentialsToken(
      config,
      authorizationHeader = "Basic cmVhZGVyLWFwcDpiYWQ=",
      contentType = "application/x-www-form-urlencoded",
      requestBody = "grant_type=client_credentials",
    )

    check not result.ok
    check result.failure.statusCode == 401
    check result.failure.error == "invalid_client"
    check result.failure.wwwAuthenticate == """Basic realm="sam-sync""""

  test "resource validation returns RFC 6750 challenges":
    let config = testConfig()

    let missing = validateOAuth2BearerToken(config, "", ["sync:read"])
    check not missing.ok
    check missing.failure.statusCode == 401
    check missing.failure.error == ""
    check missing.failure.wwwAuthenticate == """Bearer realm="sam-sync""""

    let malformed = validateOAuth2BearerToken(config, "Bearer", ["sync:read"])
    check not malformed.ok
    check malformed.failure.statusCode == 400
    check malformed.failure.error == "invalid_request"
    check """error="invalid_request"""" in malformed.failure.wwwAuthenticate

    let tokenResult = issueClientCredentialsToken(
      config,
      authorizationHeader = "Basic cmVhZGVyLWFwcDpzZWNyZXQtcmVhZGVy",
      contentType = "application/x-www-form-urlencoded",
      requestBody = "grant_type=client_credentials&scope=sync%3Aread",
      now = 1_700_000_000,
    )
    check tokenResult.ok

    let outOfScope = validateOAuth2BearerToken(
      config,
      "Bearer " & tokenResult.response.accessToken,
      ["sync:write"],
      now = 1_700_000_010,
    )
    check not outOfScope.ok
    check outOfScope.failure.statusCode == 403
    check outOfScope.failure.error == "insufficient_scope"
    check """scope="sync:write"""" in outOfScope.failure.wwwAuthenticate

  test "response bodies serialize as oauth2 json":
    let response = OAuth2TokenResponse(
      accessToken: "abc", tokenType: "Bearer", expiresIn: 60, scope: "sync:read"
    )
    let failure = OAuth2Failure(
      statusCode: 400,
      error: "invalid_request",
      errorDescription: "bad request",
      wwwAuthenticate: "",
    )

    check response.toJson()["token_type"].getStr() == "Bearer"
    check failure.toJson()["error_description"].getStr() == "bad request"

  test "scope claim pairs normalize to oauth scope strings":
    check scopeClaimsToScopes({"sync": "read"}) == @["sync:read"]
    check scopeClaimsToScopes({"sync": "read", "user": "admin"}) ==
      @["sync:read", "user:admin"]

suite "oauth2 authorization code":
  test "issues and exchanges authorization codes with pkce":
    let config = userLoginConfig()
    let store = newInMemoryOAuth2AuthorizationCodeStore()
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
    let codeResult = issueAuthorizationCode(
      config,
      store.saveCallback(),
      clientId = "browser-client",
      redirectUri = "https://client.example/callback",
      subject = "user-123",
      requestedScopeParam = "sync:read",
      codeChallenge = pkceS256Challenge(verifier),
      codeChallengeMethod = "S256",
      userAllowedScopes = ["sync:read"],
      now = 1_700_000_000,
      code = "auth-code-1",
    )

    check codeResult.ok
    check codeResult.authorizationCode.subject == "user-123"
    check codeResult.authorizationCode.scopes == @["sync:read"]

    let tokenResult = issueOAuth2Token(
      config,
      store.consumeCallback(),
      authorizationHeader = "",
      contentType = "application/x-www-form-urlencoded",
      requestBody =
        "grant_type=authorization_code&client_id=browser-client" &
        "&code=auth-code-1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback" &
        "&code_verifier=" & verifier,
      now = 1_700_000_010,
    )

    check tokenResult.ok
    check tokenResult.response.tokenType == "Bearer"
    check tokenResult.response.scope == "sync:read"

    let validation = validateOAuth2BearerToken(
      config,
      "Bearer " & tokenResult.response.accessToken,
      ["sync:read"],
      now = 1_700_000_011,
    )
    check validation.ok
    check validation.claims.subject == "user-123"

    let replay = issueOAuth2Token(
      config,
      store.consumeCallback(),
      authorizationHeader = "",
      contentType = "application/x-www-form-urlencoded",
      requestBody =
        "grant_type=authorization_code&client_id=browser-client" &
        "&code=auth-code-1&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback" &
        "&code_verifier=" & verifier,
      now = 1_700_000_012,
    )
    check not replay.ok
    check replay.failure.error == "invalid_grant"

  test "rejects invalid user scopes and pkce verifiers":
    let config = userLoginConfig()
    let store = newInMemoryOAuth2AuthorizationCodeStore()
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"

    let denied = issueAuthorizationCode(
      config,
      store.saveCallback(),
      clientId = "browser-client",
      redirectUri = "https://client.example/callback",
      subject = "user-123",
      requestedScopeParam = "sync:write",
      codeChallenge = pkceS256Challenge(verifier),
      codeChallengeMethod = "S256",
      userAllowedScopes = ["sync:read"],
    )
    check not denied.ok
    check denied.failure.error == "invalid_scope"

    let codeResult = issueAuthorizationCode(
      config,
      store.saveCallback(),
      clientId = "browser-client",
      redirectUri = "https://client.example/callback",
      subject = "user-123",
      requestedScopeParam = "sync:read",
      codeChallenge = pkceS256Challenge(verifier),
      codeChallengeMethod = "S256",
      now = 1_700_000_000,
      code = "auth-code-2",
    )
    check codeResult.ok

    let invalidPkce = issueOAuth2Token(
      config,
      store.consumeCallback(),
      authorizationHeader = "",
      contentType = "application/x-www-form-urlencoded",
      requestBody =
        "grant_type=authorization_code&client_id=browser-client" &
        "&code=auth-code-2&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback" &
        "&code_verifier=wrong-verifier-wrong-verifier-wrong-verifier-wrong",
      now = 1_700_000_010,
    )
    check not invalidPkce.ok
    check invalidPkce.failure.error == "invalid_grant"
