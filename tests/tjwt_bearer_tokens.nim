import std/[base64, json, locks, os, strutils, tables, unittest]

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
  rsaJwkN =
    "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_" &
    "yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwr" &
    "XwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr" &
    "4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsI" &
    "fVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-B" &
    "tOLpJofmbGEGgvmwyCI9Mw"
  rsaJwkE = "AQAB"
  ec256JwkX = "EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84"
  ec256JwkY = "kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY"

proc externalClaims(): JsonNode =
  %*{
    "iss": "external-issuer",
    "sub": "user-123",
    "aud": "external-api",
    "iat": 1_700_000_000,
    "nbf": 1_700_000_000,
    "exp": 1_700_000_600,
    "scope": "sync:read profile",
  }

proc base64UrlEncodeTest(input: string): string =
  result = encode(input)
  result = result.replace('+', '-')
  result = result.replace('/', '_')
  result = result.replace("=", "")

proc base64UrlEncodeBytesTest(bytes: openArray[byte]): string =
  var raw = newString(bytes.len)
  for idx, value in bytes:
    raw[idx] = char(value)
  base64UrlEncodeTest(raw)

proc base64UrlDecodeTest(input: string): string =
  var normalized = input
  normalized = normalized.replace('-', '+')
  normalized = normalized.replace('_', '/')
  while normalized.len mod 4 != 0:
    normalized.add('=')
  decode(normalized)

proc testSignatureAlgorithm(algorithm: string): SignatureAlgorithm =
  case algorithm
  of "HS256":
    HS256
  of "RS256":
    RS256
  of "ES256":
    ES256
  else:
    raise newException(ValueError, "unsupported test algorithm")

proc signedExternalTokenWithClaims(
    algorithm, kid, privateKey: string, claims: JsonNode
): string =
  var header = %*{"alg": algorithm, "typ": "JWT"}
  if kid.len > 0:
    header["kid"] = newJString(kid)

  let signingInput = base64UrlEncodeTest($header) & "." & base64UrlEncodeTest($claims)
  let signature =
    signString(signingInput, privateKey, algorithm.testSignatureAlgorithm())
  signingInput & "." & base64UrlEncodeBytesTest(signature)

proc signedExternalToken(algorithm, kid, privateKey: string): string =
  signedExternalTokenWithClaims(algorithm, kid, privateKey, externalClaims())

proc tokenWithHeader(header: JsonNode): string =
  base64UrlEncodeTest($header) & ".not-json.signature"

const singleFlightThreadCount = 4

type
  JwksSingleFlightState = object
    lock: Lock
    readyCount: int
    released: bool
    fetchCount: int
    successCount: int

  JwksSingleFlightArgs = object
    state: ptr JwksSingleFlightState
    verifier: JwtVerifierConfig
    token: string
    now: int64

proc waitForSingleFlightRelease(args: JwksSingleFlightArgs) {.gcsafe.} =
  withLock args.state.lock:
    inc args.state.readyCount

  while true:
    var released = false
    withLock args.state.lock:
      released = args.state.released
    if released:
      return
    sleep(1)

proc validateSingleFlightToken(args: JwksSingleFlightArgs) {.thread.} =
  waitForSingleFlightRelease(args)
  let validation = validateBearerToken(args.verifier, args.token, now = args.now)
  if validation.ok:
    withLock args.state.lock:
      inc args.state.successCount

proc releaseSingleFlightThreads(state: var JwksSingleFlightState) =
  for _ in 0 ..< 2_000:
    var ready = false
    withLock state.lock:
      ready = state.readyCount >= singleFlightThreadCount
      if ready:
        state.released = true
    if ready:
      return
    sleep(1)
  doAssert false, "single-flight worker threads did not start"

proc rsaJwk(kid: string): JsonNode =
  %*{
    "kty": "RSA",
    "kid": kid,
    "alg": "RS256",
    "use": "sig",
    "key_ops": ["verify"],
    "n": rsaJwkN,
    "e": rsaJwkE,
  }

proc ec256Jwk(kid: string): JsonNode =
  %*{
    "kty": "EC",
    "kid": kid,
    "alg": "ES256",
    "crv": "P-256",
    "use": "sig",
    "key_ops": ["verify"],
    "x": ec256JwkX,
    "y": ec256JwkY,
  }

proc jwksDocument(keys: openArray[JsonNode]): string =
  var jwks = %*{"keys": []}
  for key in keys:
    jwks["keys"].add(key)
  $jwks

proc jwkByKid(jwks: JsonNode, kid: string): JsonNode =
  for key in jwks["keys"]:
    if key["kid"].getStr() == kid:
      return key
  raise newException(ValueError, "missing jwk kid: " & kid)

proc tempKeyPath(name: string): string =
  getTempDir() / ("sarcophagus-jwt-" & $getCurrentProcessId() & "-" & name)

proc cleanupPath(path: string) =
  if fileExists(path) or symlinkExists(path):
    removeFile(path)

proc writeKeyFile(path: string, contents: string, permissions: set[FilePermission]) =
  cleanupPath(path)
  writeFile(path, contents)
  when defined(posix):
    setFilePermissions(path, permissions)

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

  test "parsed signing key rings use explicit active kid":
    let keys = parseSigningKeys("old:secret-a,new:secret-b")
    let config = initBearerTokenConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = keys,
      activeKid = "new",
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
    let header = parseJson(base64UrlDecodeTest(token.split('.')[0]))
    check config.activeKid == "new"
    check header["kid"].getStr() == "new"
    check validateBearerToken(config, token, now = 1_700_000_010).ok

  test "mints and validates RS256 bearer tokens with private signing keys":
    let signingKey =
      initPrivateSigningKey("rsa-1", rsPrivateKey, rsPublicKey, bearerTokenRS256)
    let config = initBearerTokenConfig(
      issuer = "sam-sync-server", audience = "sam-sync-api", keys = [signingKey]
    )
    check config.keys["rsa-1"] == rsPublicKey
    check config.keys["rsa-1"] != rsPrivateKey

    let token = mintBearerToken(
      config,
      initBearerTokenSpec(
        subject = "client-1",
        scopes = ["sync:read"],
        ttlSeconds = 600,
        issuedAt = 1_700_000_000,
      ),
    )
    let header = parseJson(base64UrlDecodeTest(token.split('.')[0]))
    check header["alg"].getStr() == "RS256"
    check header["kid"].getStr() == "rsa-1"

    let localValidation =
      validateBearerToken(config, token, ["sync:read"], now = 1_700_000_010)
    check localValidation.ok
    check localValidation.claims.keyId == "rsa-1"

    let verifier = initJwtVerifierConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )
    let verifierValidation =
      validateBearerToken(verifier, token, ["sync:read"], now = 1_700_000_010)
    check verifierValidation.ok
    check verifierValidation.claims.subject == "client-1"

  test "asymmetric key rotation keeps old verification keys until removed":
    let oldKey =
      initPrivateSigningKey("rsa-old", rsPrivateKey, rsPublicKey, bearerTokenRS256)
    let newKey =
      initPrivateSigningKey("ec-new", ec256PrivateKey, ec256PublicKey, bearerTokenES256)
    let oldConfig = initBearerTokenConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = [oldKey, newKey],
      activeKid = "rsa-old",
    )
    let oldToken = mintBearerToken(
      oldConfig,
      initBearerTokenSpec(
        subject = "client-1",
        scopes = ["sync:read"],
        ttlSeconds = 600,
        issuedAt = 1_700_000_000,
      ),
    )
    let oldHeader = parseJson(base64UrlDecodeTest(oldToken.split('.')[0]))
    check oldHeader["alg"].getStr() == "RS256"
    check oldHeader["kid"].getStr() == "rsa-old"

    let rotatedConfig = initBearerTokenConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = [oldKey, newKey],
      activeKid = "ec-new",
    )
    let oldOverlap =
      validateBearerToken(rotatedConfig, oldToken, ["sync:read"], now = 1_700_000_010)
    check oldOverlap.ok
    check oldOverlap.claims.keyId == "rsa-old"

    let newToken = mintBearerToken(
      rotatedConfig,
      initBearerTokenSpec(
        subject = "client-1",
        scopes = ["sync:read"],
        ttlSeconds = 600,
        issuedAt = 1_700_000_010,
      ),
    )
    let newHeader = parseJson(base64UrlDecodeTest(newToken.split('.')[0]))
    check newHeader["alg"].getStr() == "ES256"
    check newHeader["kid"].getStr() == "ec-new"
    check validateBearerToken(
      rotatedConfig, newToken, ["sync:read"], now = 1_700_000_020
    ).ok

    let retiredConfig = initBearerTokenConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = [newKey],
      activeKid = "ec-new",
    )
    let retiredOldValidation =
      validateBearerToken(retiredConfig, oldToken, ["sync:read"], now = 1_700_000_020)
    check not retiredOldValidation.ok
    check retiredOldValidation.failure.message == "Unknown token key id"
    check validateBearerToken(
      retiredConfig, newToken, ["sync:read"], now = 1_700_000_020
    ).ok

  test "mints and validates ES256 bearer tokens with private signing keys":
    let signingKey =
      initPrivateSigningKey("ec-1", ec256PrivateKey, ec256PublicKey, bearerTokenES256)
    let config = initBearerTokenConfig(
      issuer = "sam-sync-server", audience = "sam-sync-api", keys = [signingKey]
    )
    check config.keys["ec-1"] == ec256PublicKey
    check config.keys["ec-1"] != ec256PrivateKey

    let token = mintBearerToken(
      config,
      initBearerTokenSpec(
        subject = "client-1",
        scopes = ["sync:read"],
        ttlSeconds = 600,
        issuedAt = 1_700_000_000,
      ),
    )
    let header = parseJson(base64UrlDecodeTest(token.split('.')[0]))
    check header["alg"].getStr() == "ES256"
    check header["kid"].getStr() == "ec-1"

    let localValidation =
      validateBearerToken(config, token, ["sync:read"], now = 1_700_000_010)
    check localValidation.ok
    check localValidation.claims.keyId == "ec-1"

    let verifier = initJwtVerifierConfig(
      issuer = "sam-sync-server",
      audience = "sam-sync-api",
      keys = [initPublicSigningKey("ec-1", ec256PublicKey, bearerTokenES256)],
    )
    let verifierValidation =
      validateBearerToken(verifier, token, ["sync:read"], now = 1_700_000_010)
    check verifierValidation.ok
    check verifierValidation.claims.subject == "client-1"

  test "private signing key constructor rejects invalid key material":
    expect ValueError:
      discard initPrivateSigningKey("v1", "secret", "secret", bearerTokenHS256)
    expect ValueError:
      discard initPrivateSigningKey("rsa-1", "", rsPublicKey, bearerTokenRS256)
    expect ValueError:
      discard initPrivateSigningKey("rsa-1", rsPrivateKey, "", bearerTokenRS256)

  test "loads private signing keys from files with strict permissions":
    let privatePath = tempKeyPath("rsa-private.pem")
    let publicPath = tempKeyPath("rsa-public.pem")
    defer:
      cleanupPath(privatePath)
      cleanupPath(publicPath)

    writeKeyFile(privatePath, rsPrivateKey, {fpUserRead, fpUserWrite})
    writeKeyFile(
      publicPath, rsPublicKey, {fpUserRead, fpUserWrite, fpGroupRead, fpOthersRead}
    )

    let signingKey = initPrivateSigningKeyFromFiles(
      kid = "rsa-file",
      privateKeyPath = privatePath,
      publicKeyPath = publicPath,
      algorithm = bearerTokenRS256,
    )
    let config = initBearerTokenConfig(
      issuer = "sam-sync-server", audience = "sam-sync-api", keys = [signingKey]
    )
    check config.keys["rsa-file"] == rsPublicKey
    check config.keys["rsa-file"] != rsPrivateKey

    let token = mintBearerToken(
      config,
      initBearerTokenSpec(
        subject = "client-1",
        scopes = ["sync:read"],
        ttlSeconds = 600,
        issuedAt = 1_700_000_000,
      ),
    )
    let validation =
      validateBearerToken(config, token, ["sync:read"], now = 1_700_000_010)
    check validation.ok
    check validation.claims.keyId == "rsa-file"

  test "loads ES256 private signing keys from files":
    let privatePath = tempKeyPath("ec-private.pem")
    let publicPath = tempKeyPath("ec-public.pem")
    defer:
      cleanupPath(privatePath)
      cleanupPath(publicPath)

    writeKeyFile(privatePath, ec256PrivateKey, {fpUserRead, fpUserWrite})
    writeKeyFile(publicPath, ec256PublicKey, {fpUserRead, fpUserWrite})

    let signingKey = initPrivateSigningKeyFromFiles(
      kid = "ec-file",
      privateKeyPath = privatePath,
      publicKeyPath = publicPath,
      algorithm = bearerTokenES256,
    )
    let config = initBearerTokenConfig(
      issuer = "sam-sync-server", audience = "sam-sync-api", keys = [signingKey]
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
    let validation =
      validateBearerToken(config, token, ["sync:read"], now = 1_700_000_010)
    check validation.ok
    check validation.claims.keyId == "ec-file"

  test "private signing key file loader rejects unsafe private permissions":
    when defined(posix):
      let privatePath = tempKeyPath("unsafe-private.pem")
      let publicPath = tempKeyPath("unsafe-public.pem")
      defer:
        cleanupPath(privatePath)
        cleanupPath(publicPath)

      writeKeyFile(privatePath, rsPrivateKey, {fpUserRead, fpUserWrite, fpGroupRead})
      writeKeyFile(publicPath, rsPublicKey, {fpUserRead, fpUserWrite})

      expect ValueError:
        discard initPrivateSigningKeyFromFiles(
          kid = "rsa-file",
          privateKeyPath = privatePath,
          publicKeyPath = publicPath,
          algorithm = bearerTokenRS256,
        )
    else:
      check true

  test "private signing key file loader verifies matching key pairs":
    let privatePath = tempKeyPath("mismatch-private.pem")
    let publicPath = tempKeyPath("mismatch-public.pem")
    defer:
      cleanupPath(privatePath)
      cleanupPath(publicPath)

    writeKeyFile(privatePath, rsPrivateKey, {fpUserRead, fpUserWrite})
    writeKeyFile(publicPath, ec256PublicKey, {fpUserRead, fpUserWrite})

    expect ValueError:
      discard initPrivateSigningKeyFromFiles(
        kid = "rsa-file",
        privateKeyPath = privatePath,
        publicKeyPath = publicPath,
        algorithm = bearerTokenRS256,
      )

  test "private signing key file loader enforces maxBytes":
    let privatePath = tempKeyPath("large-private.pem")
    let publicPath = tempKeyPath("large-public.pem")
    defer:
      cleanupPath(privatePath)
      cleanupPath(publicPath)

    writeKeyFile(privatePath, rsPrivateKey, {fpUserRead, fpUserWrite})
    writeKeyFile(publicPath, rsPublicKey, {fpUserRead, fpUserWrite})

    expect ValueError:
      discard initPrivateSigningKeyFromFiles(
        kid = "rsa-file",
        privateKeyPath = privatePath,
        publicKeyPath = publicPath,
        algorithm = bearerTokenRS256,
        policy = initPrivateSigningKeyFilePolicy(maxBytes = 16),
      )

  test "private signing key file loader rejects symlinks unless allowed":
    when defined(posix):
      let privateTargetPath = tempKeyPath("target-private.pem")
      let privateLinkPath = tempKeyPath("link-private.pem")
      let publicPath = tempKeyPath("link-public.pem")
      defer:
        cleanupPath(privateLinkPath)
        cleanupPath(privateTargetPath)
        cleanupPath(publicPath)

      writeKeyFile(privateTargetPath, rsPrivateKey, {fpUserRead, fpUserWrite})
      writeKeyFile(publicPath, rsPublicKey, {fpUserRead, fpUserWrite})
      cleanupPath(privateLinkPath)
      createSymlink(privateTargetPath, privateLinkPath)

      expect ValueError:
        discard initPrivateSigningKeyFromFiles(
          kid = "rsa-file",
          privateKeyPath = privateLinkPath,
          publicKeyPath = publicPath,
          algorithm = bearerTokenRS256,
        )

      let signingKey = initPrivateSigningKeyFromFiles(
        kid = "rsa-file",
        privateKeyPath = privateLinkPath,
        publicKeyPath = publicPath,
        algorithm = bearerTokenRS256,
        policy = initPrivateSigningKeyFilePolicy(allowSymlink = true),
      )
      check signingKey.publicKey == rsPublicKey
    else:
      check true

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

  test "jwt verifier config validates RS256 tokens without minting config":
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )
    check verifier.issuer == "external-issuer"
    check verifier.audience == "external-api"
    check verifier.len == 1
    check "rsa-1" in verifier
    check "missing" notin verifier

    let token = signedExternalToken("RS256", "rsa-1", rsPrivateKey)
    let validation =
      validateBearerToken(verifier, token, ["profile"], now = 1_700_000_010)

    check validation.ok
    check validation.claims.subject == "user-123"
    check validation.claims.issuer == "external-issuer"
    check validation.claims.audience == "external-api"
    check validation.claims.keyId == "rsa-1"

  test "jwt verifier config authorizes configured claim scopes":
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
      scopeClaims = [
        initJwtScopeClaim("role"),
        initJwtScopeClaim("client_id"),
        initJwtScopeClaim("user_id"),
        initJwtScopeClaim("permissions", "permission"),
      ],
    )
    check verifier.scopeClaims.len == 4
    check verifier.scopeClaims[0].claimName == "role"
    check verifier.scopeClaims[0].scopePrefix == "role"

    let claims = externalClaims()
    claims["role"] = newJString("admin")
    claims["client_id"] = newJString("admin-ui")
    claims["user_id"] = newJString("user-123")
    claims["permissions"] = %*["files:read", "files:write"]
    let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
    let validation = validateBearerToken(
      verifier,
      token,
      [
        claimScope("role", "admin"),
        claimScope("client_id", "admin-ui"),
        claimScope("user_id", "user-123"),
        claimScope("permission", "files:read"),
      ],
      now = 1_700_000_010,
    )

    check validation.ok
    check validation.claims.role == "admin"
    check validation.claims.clientId == "admin-ui"
    check validation.claims.userId == "user-123"
    check hasAllScopes(
      validation.claims.scopes,
      [
        "sync:read", "profile", "role:admin", "client_id:admin-ui", "user_id:user-123",
        "permission:files:read", "permission:files:write",
      ],
    )

  test "jwt verifier config validates HS256 tokens without active signing key":
    let signingConfig = initBearerTokenConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [SigningKey(kid: "shared-1", secret: "shared-secret")],
    )
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [SigningKey(kid: "shared-1", secret: "shared-secret")],
    )
    let token = mintBearerToken(
      signingConfig,
      initBearerTokenSpec(
        subject = "client-1",
        scopes = ["sync:read"],
        ttlSeconds = 600,
        issuedAt = 1_700_000_000,
      ),
    )
    let validation =
      validateBearerToken(verifier, token, ["sync:read"], now = 1_700_000_010)

    check validation.ok
    check validation.claims.subject == "client-1"
    check validation.claims.keyId == "shared-1"

  test "parseJwksSigningKeys converts RSA and P-256 public keys":
    let keys = parseJwksSigningKeys(jwksDocument([rsaJwk("rsa-1"), ec256Jwk("ec-1")]))
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer", audience = "external-api", keys = keys
    )

    check verifier.len == 2
    check "rsa-1" in verifier
    check "ec-1" in verifier

    let rsaToken = signedExternalToken("RS256", "rsa-1", rsPrivateKey)
    let rsaValidation = validateBearerToken(verifier, rsaToken, now = 1_700_000_010)
    check rsaValidation.ok
    check rsaValidation.claims.keyId == "rsa-1"

    let ecToken = signedExternalToken("ES256", "ec-1", ec256PrivateKey)
    let ecValidation = validateBearerToken(verifier, ecToken, now = 1_700_000_010)
    check ecValidation.ok
    check ecValidation.claims.keyId == "ec-1"

  test "toJwks publishes RSA and P-256 public verification keys":
    let rsaKey =
      initPrivateSigningKey("rsa-1", rsPrivateKey, rsPublicKey, bearerTokenRS256)
    let ecKey =
      initPrivateSigningKey("ec-1", ec256PrivateKey, ec256PublicKey, bearerTokenES256)
    let config = initBearerTokenConfig(
      issuer = "external-issuer", audience = "external-api", keys = [rsaKey, ecKey]
    )

    let jwks = config.toJwks()
    check jwks["keys"].len == 2
    check jwks.jwkByKid("rsa-1") == rsaJwk("rsa-1")
    check jwks.jwkByKid("ec-1") == ec256Jwk("ec-1")
    check "PRIVATE KEY" notin $jwks

    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = parseJwksSigningKeys($jwks),
    )
    check validateBearerToken(
      verifier, signedExternalToken("RS256", "rsa-1", rsPrivateKey), now = 1_700_000_010
    ).ok
    check validateBearerToken(
      verifier,
      signedExternalToken("ES256", "ec-1", ec256PrivateKey),
      now = 1_700_000_010,
    ).ok

  test "toJwks never publishes symmetric signing keys":
    expect ValueError:
      discard toJwk(SigningKey(kid: "shared-1", secret: "secret"))

    let symmetricConfig = initBearerTokenConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [SigningKey(kid: "shared-1", secret: "secret")],
    )
    expect ValueError:
      discard symmetricConfig.toJwks()

    let mixedConfig = initBearerTokenConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [
        SigningKey(kid: "shared-1", secret: "secret"),
        initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256),
      ],
    )
    let jwks = mixedConfig.toJwks()
    check jwks["keys"].len == 1
    check jwks.jwkByKid("rsa-1") == rsaJwk("rsa-1")

  test "jwks verifier loads caches expires and refreshes unknown kid":
    var fetchCount = 0
    let fetcher: JwksFetcher = proc(url: string): string =
      check url == "https://issuer.example/.well-known/jwks.json"
      inc fetchCount
      case fetchCount
      of 1:
        jwksDocument([rsaJwk("rsa-1")])
      of 2:
        jwksDocument([rsaJwk("rsa-1"), rsaJwk("rsa-2")])
      else:
        jwksDocument([rsaJwk("rsa-1"), rsaJwk("rsa-2"), rsaJwk("rsa-3")])

    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      jwksUrl = "https://issuer.example/.well-known/jwks.json",
      jwksCacheMaxAgeSeconds = 10,
      jwksFetcher = fetcher,
    )
    check verifier.len == 0
    check verifier.jwksUrl == "https://issuer.example/.well-known/jwks.json"
    check verifier.jwksCacheMaxAgeSeconds == 10
    check verifier.jwksUnknownKidRefreshCooldownSeconds == 60

    let firstToken = signedExternalToken("RS256", "rsa-1", rsPrivateKey)
    let firstValidation = validateBearerToken(verifier, firstToken, now = 1_700_000_010)
    check firstValidation.ok
    check fetchCount == 1
    check verifier.jwksFetchedAt == 1_700_000_010
    check verifier.len == 1
    check "rsa-1" in verifier

    let cachedValidation =
      validateBearerToken(verifier, firstToken, now = 1_700_000_015)
    check cachedValidation.ok
    check fetchCount == 1

    let rotatedToken = signedExternalToken("RS256", "rsa-2", rsPrivateKey)
    let rotatedValidation =
      validateBearerToken(verifier, rotatedToken, now = 1_700_000_016)
    check rotatedValidation.ok
    check fetchCount == 2
    check "rsa-2" in verifier
    check verifier.jwksFetchedAt == 1_700_000_016

    let suppressedToken = signedExternalToken("RS256", "rsa-3", rsPrivateKey)
    let suppressedValidation =
      validateBearerToken(verifier, suppressedToken, now = 1_700_000_017)
    check not suppressedValidation.ok
    check suppressedValidation.failure.message == "Unknown token key id"
    check fetchCount == 2
    check "rsa-3" notin verifier

    let laterUnknownValidation =
      validateBearerToken(verifier, suppressedToken, now = 1_700_000_077)
    check laterUnknownValidation.ok
    check fetchCount == 3
    check "rsa-3" in verifier
    check verifier.jwksFetchedAt == 1_700_000_077

    let staleValidation =
      validateBearerToken(verifier, rotatedToken, now = 1_700_000_088)
    check staleValidation.ok
    check fetchCount == 4
    check verifier.jwksFetchedAt == 1_700_000_088

  test "jwks verifier rejects malformed tokens without fetching":
    var fetchCount = 0
    let fetcher: JwksFetcher = proc(url: string): string =
      check url == "https://issuer.example/.well-known/jwks.json"
      inc fetchCount
      jwksDocument([rsaJwk("rsa-1")])

    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      jwksUrl = "https://issuer.example/.well-known/jwks.json",
      jwksCacheMaxAgeSeconds = 10,
      jwksFetcher = fetcher,
    )

    let missing = validateBearerToken(verifier, "", now = 1_700_000_010)
    check not missing.ok
    check missing.failure.code == "missing_token"

    let malformed = validateBearerToken(verifier, "not-a-jwt", now = 1_700_000_010)
    check not malformed.ok
    check malformed.failure.message == "Malformed bearer token"

    let invalidHeader = validateBearerToken(
      verifier,
      tokenWithHeader(%*{"alg": "none", "typ": "JWT", "kid": "rsa-1"}),
      now = 1_700_000_010,
    )
    check not invalidHeader.ok
    check invalidHeader.failure.message == "token algorithm is not allowed"
    check fetchCount == 0

  test "stale jwks refresh is single-flight across concurrent validations":
    var state: JwksSingleFlightState
    initLock(state.lock)
    defer:
      deinitLock(state.lock)

    let fetcher: JwksFetcher = proc(url: string): string =
      doAssert url == "https://issuer.example/.well-known/jwks.json"
      withLock state.lock:
        inc state.fetchCount
      sleep(100)
      jwksDocument([rsaJwk("rsa-1")])

    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      jwksUrl = "https://issuer.example/.well-known/jwks.json",
      jwksCacheMaxAgeSeconds = 10,
      jwksFetcher = fetcher,
    )
    let token = signedExternalToken("RS256", "rsa-1", rsPrivateKey)
    check validateBearerToken(verifier, token, now = 1_700_000_010).ok
    withLock state.lock:
      check state.fetchCount == 1

    var threads: array[singleFlightThreadCount, Thread[JwksSingleFlightArgs]]
    for idx in 0 ..< singleFlightThreadCount:
      let args = JwksSingleFlightArgs(
        state: addr state, verifier: verifier, token: token, now: 1_700_000_021
      )
      createThread(threads[idx], validateSingleFlightToken, args)

    releaseSingleFlightThreads(state)
    joinThreads(threads)

    withLock state.lock:
      check state.successCount == singleFlightThreadCount
      check state.fetchCount == 2
    check verifier.jwksFetchedAt == 1_700_000_021

  test "jwks unknown kid cooldown can be disabled":
    var fetchCount = 0
    let fetcher: JwksFetcher = proc(url: string): string =
      check url == "https://issuer.example/.well-known/jwks.json"
      inc fetchCount
      case fetchCount
      of 1:
        jwksDocument([rsaJwk("rsa-1")])
      of 2:
        jwksDocument([rsaJwk("rsa-1"), rsaJwk("rsa-2")])
      else:
        jwksDocument([rsaJwk("rsa-1"), rsaJwk("rsa-2"), rsaJwk("rsa-3")])

    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      jwksUrl = "https://issuer.example/.well-known/jwks.json",
      jwksCacheMaxAgeSeconds = 100,
      jwksUnknownKidRefreshCooldownSeconds = 0,
      jwksFetcher = fetcher,
    )
    check verifier.jwksUnknownKidRefreshCooldownSeconds == 0

    let firstToken = signedExternalToken("RS256", "rsa-1", rsPrivateKey)
    check validateBearerToken(verifier, firstToken, now = 1_700_000_010).ok
    check fetchCount == 1

    let secondToken = signedExternalToken("RS256", "rsa-2", rsPrivateKey)
    check validateBearerToken(verifier, secondToken, now = 1_700_000_011).ok
    check fetchCount == 2

    let thirdToken = signedExternalToken("RS256", "rsa-3", rsPrivateKey)
    check validateBearerToken(verifier, thirdToken, now = 1_700_000_012).ok
    check fetchCount == 3

  test "jwt verifier url helper derives issuer and jwks urls":
    block defaultPaths:
      let urls = deriveJwtVerifierUrls(" https://issuer.example/ ")
      check urls.issuer == "https://issuer.example"
      check urls.jwksUrl == "https://issuer.example/.well-known/jwks.json"

    block customPaths:
      let options = initJwtVerifierUrlOptions(
        issuerPath = "/tenant-a",
        jwksPath = "/tenant-a/keys.json",
        requiredHostSuffix = "example.com",
        allowRootHost = false,
        allowPort = false,
      )
      let urls = deriveJwtVerifierUrls("https://AUTH.example.com/tenant-a/", options)
      check urls.issuer == "https://auth.example.com/tenant-a"
      check urls.jwksUrl == "https://auth.example.com/tenant-a/keys.json"

  test "jwt verifier url helper rejects unsupported provider urls":
    let options = initJwtVerifierUrlOptions(
      issuerPath = "/tenant-a",
      jwksPath = "/tenant-a/keys.json",
      requiredHostSuffix = "example.com",
      allowRootHost = false,
      allowPort = false,
    )
    for invalidUrl in [
      "", "http://auth.example.com", "https://example.com",
      "https://auth.example.com:443", "https://auth.example.com/other",
      "https://auth.example.com/tenant-a?x=1", "https://auth.example.com.evil.test",
    ]:
      expect ValueError:
        discard deriveJwtVerifierUrls(invalidUrl, options)

  test "jwks verifier requires https urls and skips symmetric jwks entries":
    expect ValueError:
      discard initJwtVerifierConfig(
        issuer = "external-issuer",
        audience = "external-api",
        jwksUrl = "http://issuer.example/.well-known/jwks.json",
      )

    let keys = parseJwksSigningKeys(
      jwksDocument(
        [
          %*{
            "kty": "oct",
            "kid": "shared-1",
            "alg": "HS256",
            "use": "sig",
            "key_ops": ["verify"],
            "k": "secret",
          }
        ]
      )
    )
    check keys.len == 0

  test "jwt verifier config rejects tokens without kid":
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )
    let token = signedExternalToken("RS256", "", rsPrivateKey)
    let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

    check not validation.ok
    check validation.failure.statusCode == 401
    check validation.failure.code == "invalid_token"
    check validation.failure.message == "Token key id is missing"

  test "header validation rejects unsupported algorithms before payload parsing":
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )
    let token = tokenWithHeader(%*{"alg": "none", "typ": "JWT", "kid": "rsa-1"})
    let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

    check not validation.ok
    check validation.failure.statusCode == 401
    check validation.failure.code == "invalid_token"
    check validation.failure.message == "token algorithm is not allowed"

  test "header validation rejects invalid typ before payload parsing":
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )
    let token = tokenWithHeader(%*{"alg": "RS256", "typ": "JOSE", "kid": "rsa-1"})
    let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

    check not validation.ok
    check validation.failure.statusCode == 401
    check validation.failure.code == "invalid_token"
    check validation.failure.message == "token typ must be JWT"

  test "header validation rejects non-string kid before payload parsing":
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )
    let token = tokenWithHeader(%*{"alg": "RS256", "typ": "JWT", "kid": 7})
    let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

    check not validation.ok
    check validation.failure.statusCode == 401
    check validation.failure.code == "invalid_token"
    check validation.failure.message == "token kid must be a string"

  test "header validation rejects unknown kid before payload parsing":
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )
    let token = tokenWithHeader(%*{"alg": "RS256", "typ": "JWT", "kid": "missing"})
    let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

    check not validation.ok
    check validation.failure.statusCode == 401
    check validation.failure.code == "invalid_token"
    check validation.failure.message == "Unknown token key id"

  test "claim validation rejects invalid issuer audience and subject":
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )

    block invalidIssuer:
      let claims = externalClaims()
      claims["iss"] = newJString("other-issuer")
      let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
      let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

      check not validation.ok
      check validation.failure.statusCode == 401
      check validation.failure.code == "invalid_token"
      check validation.failure.message == "Token issuer is invalid"

    block invalidAudience:
      let claims = externalClaims()
      claims["aud"] = newJString("other-api")
      let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
      let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

      check not validation.ok
      check validation.failure.statusCode == 401
      check validation.failure.code == "invalid_token"
      check validation.failure.message == "Token audience is invalid"

    block invalidSubject:
      let claims = externalClaims()
      claims["sub"] = newJString("")
      let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
      let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

      check not validation.ok
      check validation.failure.statusCode == 401
      check validation.failure.code == "invalid_token"
      check validation.failure.message == "Token subject is invalid"

  test "claim validation requires and validates issued-at":
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )

    block missingIssuedAt:
      let claims = externalClaims()
      claims.delete("iat")
      let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
      let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

      check not validation.ok
      check validation.failure.statusCode == 401
      check validation.failure.code == "invalid_token"
      check validation.failure.message == "Token is missing iat"

    block invalidIssuedAt:
      let claims = externalClaims()
      claims["iat"] = newJString("now")
      let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
      let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

      check not validation.ok
      check validation.failure.statusCode == 401
      check validation.failure.code == "invalid_token"
      check validation.failure.message == "Token issued-at is invalid"

    block futureIssuedAt:
      let claims = externalClaims()
      claims["iat"] = newJInt(1_700_000_020)
      let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
      let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

      check not validation.ok
      check validation.failure.statusCode == 401
      check validation.failure.code == "invalid_token"
      check validation.failure.message == "Token issued-at is in the future"

  test "claim validation requires and validates expiration":
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )

    block invalidExpiration:
      let claims = externalClaims()
      claims["exp"] = newJString("later")
      let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
      let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

      check not validation.ok
      check validation.failure.statusCode == 401
      check validation.failure.code == "invalid_token"
      check validation.failure.message == "Token expiration is invalid"

    block expired:
      let claims = externalClaims()
      claims["exp"] = newJInt(1_700_000_010)
      let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
      let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

      check not validation.ok
      check validation.failure.statusCode == 401
      check validation.failure.code == "invalid_token"
      check validation.failure.message == "Token is expired"

  test "claim validation accepts optional nbf and validates it when present":
    let verifier = initJwtVerifierConfig(
      issuer = "external-issuer",
      audience = "external-api",
      keys = [initPublicSigningKey("rsa-1", rsPublicKey, bearerTokenRS256)],
    )

    block missingNotBefore:
      let claims = externalClaims()
      claims.delete("nbf")
      let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
      let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

      check validation.ok
      check validation.claims.notBefore == 1_700_000_000

    block invalidNotBefore:
      let claims = externalClaims()
      claims["nbf"] = newJString("later")
      let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
      let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

      check not validation.ok
      check validation.failure.statusCode == 401
      check validation.failure.code == "invalid_token"
      check validation.failure.message == "Token not-before is invalid"

    block futureNotBefore:
      let claims = externalClaims()
      claims["nbf"] = newJInt(1_700_000_020)
      let token = signedExternalTokenWithClaims("RS256", "rsa-1", rsPrivateKey, claims)
      let validation = validateBearerToken(verifier, token, now = 1_700_000_010)

      check not validation.ok
      check validation.failure.statusCode == 401
      check validation.failure.code == "invalid_token"
      check validation.failure.message == "Token is not valid yet"

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

  test "validation rejects PEM keys without configured algorithms":
    let config = BearerTokenConfig(
      issuer: "external-issuer",
      audience: "external-api",
      activeKid: "rsa-1",
      keys: {"rsa-1": rsPublicKey}.toTable(),
    )
    let token = signedExternalToken("HS256", "rsa-1", rsPublicKey)
    let validation = validateBearerToken(config, token, now = 1_700_000_010)

    check not validation.ok
    check validation.failure.statusCode == 401
    check validation.failure.code == "invalid_token"
    check validation.failure.message == "Token key algorithm is not configured"

  test "manually constructed HS256 configs remain supported":
    let config = BearerTokenConfig(
      issuer: "manual-issuer",
      audience: "manual-api",
      activeKid: "v1",
      keys: {"v1": "secret-a"}.toTable(),
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
    let validation =
      validateBearerToken(config, token, ["sync:read"], now = 1_700_000_010)

    check validation.ok
    check validation.claims.subject == "client-1"
    check validation.claims.keyId == "v1"

  test "minting requires active signing key material":
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
