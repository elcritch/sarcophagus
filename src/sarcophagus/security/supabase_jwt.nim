## Supabase JWT verifier helpers.
##
## This module is intentionally small: it shows how a provider-specific JWT
## integration can be built on the reusable verifier tools in
## `sarcophagus/core/jwt_bearer_tokens`.

import ../core/jwt_bearer_tokens

export jwt_bearer_tokens

const
  supabaseJwtDefaultAudience* = "authenticated"
  supabaseJwtIssuerPath* = "/auth/v1"
  supabaseJwtJwksPath* = "/auth/v1/.well-known/jwks.json"
  supabaseJwtHostSuffix* = "supabase.co"

proc defaultSupabaseJwtScopeClaims*(): seq[JwtScopeClaim] =
  ## Builds default Supabase JWT claim-to-scope mappings.
  @[
    initJwtScopeClaim("role"),
    initJwtScopeClaim("client_id"),
    initJwtScopeClaim("user_id"),
  ]

proc supabaseJwtScopeClaims*(
    extraScopeClaims: openArray[JwtScopeClaim] = [], includeDefaultScopeClaims = true
): seq[JwtScopeClaim] =
  ## Combines Supabase's default claim scopes with caller-provided mappings.
  if includeDefaultScopeClaims:
    result = defaultSupabaseJwtScopeClaims()
  for scopeClaim in extraScopeClaims:
    result.add(scopeClaim)

proc initSupabaseJwtVerifierUrlOptions*(): JwtVerifierUrlOptions =
  ## Builds URL derivation options for Supabase Auth JWT verification.
  initJwtVerifierUrlOptions(
    issuerPath = supabaseJwtIssuerPath,
    jwksPath = supabaseJwtJwksPath,
    requiredHostSuffix = supabaseJwtHostSuffix,
    allowRootHost = false,
    allowPort = false,
  )

proc supabaseJwtVerifierUrls*(projectUrl: string): JwtVerifierUrls =
  ## Derives Supabase Auth issuer and JWKS URLs from a project URL.
  deriveJwtVerifierUrls(projectUrl, initSupabaseJwtVerifierUrlOptions())

proc initSupabaseJwtVerifierConfigImpl(
    projectUrl: string,
    audience: string,
    keys: openArray[SigningKey],
    jwksCacheMaxAgeSeconds: Positive,
    jwksUnknownKidRefreshCooldownSeconds: Natural,
    jwksFetcher: JwksFetcher,
    scopeClaims: openArray[JwtScopeClaim],
): JwtVerifierConfig =
  let urls = supabaseJwtVerifierUrls(projectUrl)
  initJwtVerifierConfig(
    issuer = urls.issuer,
    audience = audience,
    keys = keys,
    jwksUrl = urls.jwksUrl,
    jwksCacheMaxAgeSeconds = jwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds = jwksUnknownKidRefreshCooldownSeconds,
    jwksFetcher = jwksFetcher,
    scopeClaims = scopeClaims,
  )

proc initSupabaseJwtVerifierConfig*(
    projectUrl: string,
    audience = supabaseJwtDefaultAudience,
    keys: openArray[SigningKey] = [],
    jwksCacheMaxAgeSeconds: Positive = jwtVerifierDefaultJwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds: Natural =
      jwtVerifierDefaultJwksUnknownKidRefreshCooldownSeconds,
    jwksFetcher: JwksFetcher = nil,
    extraScopeClaims: openArray[JwtScopeClaim] = [],
    includeDefaultScopeClaims = true,
): JwtVerifierConfig =
  ## Builds a validation-only JWT verifier config for a Supabase project.
  initSupabaseJwtVerifierConfigImpl(
    projectUrl,
    audience,
    keys,
    jwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds,
    jwksFetcher,
    supabaseJwtScopeClaims(extraScopeClaims, includeDefaultScopeClaims),
  )

proc initSupabaseJwtVerifierConfig*(
    projectUrl: static[string],
    audience = supabaseJwtDefaultAudience,
    keys: openArray[SigningKey] = [],
    jwksCacheMaxAgeSeconds: Positive = jwtVerifierDefaultJwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds: Natural =
      jwtVerifierDefaultJwksUnknownKidRefreshCooldownSeconds,
    extraScopeClaims: openArray[JwtScopeClaim] = [],
    includeDefaultScopeClaims = true,
): JwtVerifierConfig =
  ## Builds a validation-only JWT verifier config for a Supabase project.
  warnJwtVerifierRemoteJwksWithoutSsl(projectUrl)
  initSupabaseJwtVerifierConfigImpl(
    projectUrl,
    audience,
    keys,
    jwksCacheMaxAgeSeconds,
    jwksUnknownKidRefreshCooldownSeconds,
    nil,
    supabaseJwtScopeClaims(extraScopeClaims, includeDefaultScopeClaims),
  )
