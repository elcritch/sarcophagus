import std/[json, strutils, unittest]

import jwt
import sarcophagus/core/jwt_bearer_tokens

const
  rsPrivateKey =
    """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----"""
  rsPublicKey =
    """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----"""
  ec256PrivateKey =
    """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"""
  ec256PublicKey =
    """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----"""

proc signedExternalToken(algorithm, kid, privateKey: string): string =
  let header = %*{"alg": algorithm, "typ": "JWT", "kid": kid}
  let claims =
    %*{
      "iss": "external-issuer",
      "sub": "user-123",
      "aud": "external-api",
      "iat": 1_700_000_000,
      "nbf": 1_700_000_000,
      "exp": 1_700_000_600,
      "scope": "sync:read profile",
    }
  var token = initJWT(header.toHeader(), claims.toClaims())
  token.sign(privateKey)
  $token

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

  test "validates RS256 tokens with a public key":
    let config = initBearerTokenConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )
    let token = signedExternalToken("RS256", "rsa-1", rsPrivateKey)
    let validation =
      validateBearerToken(config, token, ["sync:read"], now = 1_700_000_010)

    check validation.ok
    check validation.claims.subject == "user-123"
    check validation.claims.issuer == "external-issuer"
    check validation.claims.audience == "external-api"
    check validation.claims.keyId == "rsa-1"
    check validation.claims.scopes == @["sync:read", "profile"]

  test "validates ES256 tokens with a public key":
    let config = initBearerTokenConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("ec-1", ec256PublicKey, bearerTokenES256)],
    )
    let token = signedExternalToken("ES256", "ec-1", ec256PrivateKey)
    let validation =
      validateBearerToken(config, token, ["profile"], now = 1_700_000_010)

    check validation.ok
    check validation.claims.subject == "user-123"
    check validation.claims.keyId == "ec-1"
    check validation.claims.scopes == @["sync:read", "profile"]

  test "validation rejects tokens when alg does not match configured key":
    let config = initBearerTokenConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenES256)],
    )
    let token = signedExternalToken("RS256", "rsa-1", rsPrivateKey)
    let validation = validateBearerToken(config, token, now = 1_700_000_010)

    check not validation.ok
    check validation.failure.statusCode == 401
    check validation.failure.code == "invalid_token"
    check validation.failure.message == "Token algorithm does not match key"

  test "validation rejects empty asymmetric signatures without raising defects":
    let config = initBearerTokenConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )
    let token = signedExternalToken("RS256", "rsa-1", rsPrivateKey)
    let tokenParts = token.split('.')
    let emptySignatureToken = tokenParts[0] & "." & tokenParts[1] & "."
    let validation =
      validateBearerToken(config, emptySignatureToken, now = 1_700_000_010)

    check not validation.ok
    check validation.failure.statusCode == 401
    check validation.failure.code == "invalid_token"
    check validation.failure.message == "Token signature is invalid"

  test "minting requires an HS256 active signing key":
    let config = initBearerTokenConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )

    expect ValueError:
      discard mintBearerToken(
        config,
        initBearerTokenSpec(
          subject = "user-123", scopes = ["sync:read"], ttlSeconds = 600
        ),
      )

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

  test "validation rejects tokens at their exp timestamp":
    let config = initBearerTokenConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = [SigningKey(kid: "v1", secret: "secret-a")],
    )
    let token = mintBearerToken(
      config,
      initBearerTokenSpec(
        subject = "client-1",
        scopes = ["sync:read"],
        ttlSeconds = 600,
        issuedAt = 1_700_000_000,
      ),
    )

    check validateBearerToken(config, token, now = 1_700_000_599).ok
    let validation = validateBearerToken(config, token, now = 1_700_000_600)
    check not validation.ok
    check validation.failure.statusCode == 401
    check validation.failure.code == "invalid_token"
    check validation.failure.message == "Token is expired"

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
