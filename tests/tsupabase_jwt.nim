import std/[base64, json, strutils, unittest]

import jwt
import sarcophagus/security/supabase_jwt

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
  rsaJwkN =
    "nzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA-kzeVOVpVWwkWdVha4s38XM_pa_" &
    "yr47av7-z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr_Mrm_YtjCZVWgaOYIhwr" &
    "XwKLqPr_11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr" &
    "4B8nW3HCN47XUu0t8Y0e-lf4s4OxQawWD79J9_5d3Ry0vbV3Am1FtGJiJvOwRsI" &
    "fVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa-GSYOD2QU68Mb59oSk2OB-B" &
    "tOLpJofmbGEGgvmwyCI9Mw"
  rsaJwkE = "AQAB"

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

proc signedRs256Token(issuer, audience, kid: string): string =
  let claims =
    %*{
      "iss": issuer,
      "sub": "user-123",
      "aud": audience,
      "iat": 1_700_000_000,
      "nbf": 1_700_000_000,
      "exp": 1_700_000_600,
      "scope": "sync:read profile",
      "role": "authenticated",
      "client_id": "supabase-js",
      "user_id": "user-123",
      "permissions": ["photos:read", "photos:write"],
    }
  let header = %*{"alg": "RS256", "typ": "JWT", "kid": kid}
  let signingInput = base64UrlEncodeTest($header) & "." & base64UrlEncodeTest($claims)
  let signature = signString(signingInput, rsPrivateKey, RS256)
  signingInput & "." & base64UrlEncodeBytesTest(signature)

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

proc jwksDocument(keys: openArray[JsonNode]): string =
  $(%*{"keys": keys})

suite "supabase jwt helpers":
  test "derives issuer and jwks urls":
    block projectRoot:
      let urls = supabaseJwtVerifierUrls(" https://project-ref.supabase.co/ ")
      check urls.issuer == "https://project-ref.supabase.co/auth/v1"
      check urls.jwksUrl ==
        "https://project-ref.supabase.co/auth/v1/.well-known/jwks.json"

    block authIssuer:
      let urls = supabaseJwtVerifierUrls("https://PROJECT-REF.supabase.co/auth/v1/")
      check urls.issuer == "https://project-ref.supabase.co/auth/v1"
      check urls.jwksUrl ==
        "https://project-ref.supabase.co/auth/v1/.well-known/jwks.json"

  test "builds a jwks verifier config":
    var fetchCount = 0
    let fetcher: JwksFetcher = proc(url: string): string =
      check url == "https://project-ref.supabase.co/auth/v1/.well-known/jwks.json"
      inc fetchCount
      jwksDocument([rsaJwk("rsa-1")])

    let verifier = initSupabaseJwtVerifierConfig(
      projectUrl = "https://project-ref.supabase.co",
      jwksFetcher = fetcher,
      extraScopeClaims = [initJwtScopeClaim("permissions", "permission")],
    )
    check verifier.issuer == "https://project-ref.supabase.co/auth/v1"
    check verifier.audience == supabaseJwtDefaultAudience
    check verifier.jwksUrl ==
      "https://project-ref.supabase.co/auth/v1/.well-known/jwks.json"
    check verifier.scopeClaims.len == 4

    let token = signedRs256Token(verifier.issuer, supabaseJwtDefaultAudience, "rsa-1")
    let validation = validateBearerToken(
      verifier,
      token,
      [
        claimScope("role", "authenticated"),
        claimScope("client_id", "supabase-js"),
        claimScope("user_id", "user-123"),
        claimScope("permission", "photos:read"),
      ],
      now = 1_700_000_010,
    )
    check validation.ok
    check validation.claims.role == "authenticated"
    check validation.claims.clientId == "supabase-js"
    check validation.claims.userId == "user-123"
    check hasAllScopes(
      validation.claims.scopes,
      [
        "sync:read", "profile", "role:authenticated", "client_id:supabase-js",
        "user_id:user-123", "permission:photos:read", "permission:photos:write",
      ],
    )
    check fetchCount == 1

  test "rejects unsupported project urls":
    for invalidUrl in [
      "", "http://project-ref.supabase.co", "https://supabase.co",
      "https://project-ref.supabase.co:443", "https://project-ref.supabase.co/rest/v1",
      "https://project-ref.supabase.co/auth/v1?x=1",
      "https://project-ref.supabase.co.evil.example",
    ]:
      expect ValueError:
        discard supabaseJwtVerifierUrls(invalidUrl)
