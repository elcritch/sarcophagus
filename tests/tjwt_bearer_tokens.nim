import std/unittest

import sarcophagus/core/jwt_bearer_tokens

suite "bearer token core":
  test "parseSigningKeys rejects duplicate kids":
    expect ValueError:
      discard parseSigningKeys("v1:alpha,v1:beta")

  test "minted tokens validate and preserve claims":
    let config = initBearerTokenConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = [SigningKey(kid: "v1", secret: "secret-a")],
    )
    let spec = initBearerTokenSpec(
      subject = "client-1",
      scopes = ["sync:read", "sync:write", "sync:read"],
      ttlSeconds = 600,
      tokenId = "token-123",
      issuedAt = 1_700_000_000,
    )
    let token = mintBearerToken(config, spec)
    let validation =
      validateBearerToken(config, token, ["sync:read"], now = 1_700_000_010)

    check validation.ok
    check validation.claims.subject == "client-1"
    check validation.claims.issuer == "sam-sync-server"
    check validation.claims.audience == "sam-sync-api"
    check validation.claims.keyId == "v1"
    check validation.claims.tokenId == "token-123"
    check validation.claims.issuedAt == 1_700_000_000
    check validation.claims.notBefore == 1_700_000_000
    check validation.claims.expiresAt == 1_700_000_600
    check validation.claims.scopes == @["sync:read", "sync:write"]

  test "validation fails when required scope is missing":
    let config = initBearerTokenConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = [SigningKey(kid: "v1", secret: "secret-a")],
    )
    let token = mintBearerToken(
      config,
      initBearerTokenSpec(
        subject = "client-1", scopes = ["sync:read"], ttlSeconds = 600
      ),
    )
    let validation = validateBearerToken(config, token, ["sync:write"])

    check not validation.ok
    check validation.failure.statusCode == 403
    check validation.failure.code == "insufficient_scope"

  test "authorization header parsing is case-insensitive and trims whitespace":
    let token = bearerTokenFromAuthorizationHeader("  bearer   abc.def.ghi  ")
    check token == "abc.def.ghi"

  test "tampered token signature is rejected":
    let config = initBearerTokenConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = [SigningKey(kid: "v1", secret: "secret-a")],
    )
    let token = mintBearerToken(
      config,
      initBearerTokenSpec(
        subject = "client-1", scopes = ["sync:read"], ttlSeconds = 600
      ),
    )
    let tampered = token[0 .. ^2] & (if token[^1] == 'a': "b" else: "a")
    let validation = validateBearerToken(config, tampered)

    check not validation.ok
    check validation.failure.statusCode == 401
    check validation.failure.code == "invalid_token"
