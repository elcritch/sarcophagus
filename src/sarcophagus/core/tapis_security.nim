import std/json

import ./oauth2

type
  ApiSecurityKind* = enum
    apiSecurityNone
    apiSecurityOAuth2

  ApiSecurity* = object
    case kind*: ApiSecurityKind
    of apiSecurityNone:
      discard
    of apiSecurityOAuth2:
      oauth2Config*: OAuth2Config
      requiredScopes*: seq[string]
      schemeName*: string
      tokenUrl*: string

proc noSecurity*(): ApiSecurity =
  ApiSecurity(kind: apiSecurityNone)

proc oauth2*(
    config: OAuth2Config,
    requiredScopes: openArray[string] = [],
    schemeName = "oauth2",
    tokenUrl = "/oauth/token",
): ApiSecurity =
  ApiSecurity(
    kind: apiSecurityOAuth2,
    oauth2Config: config,
    requiredScopes: @requiredScopes,
    schemeName: schemeName,
    tokenUrl: tokenUrl,
  )

proc oauth2*(
    config: OAuth2Config,
    requiredClaims: openArray[OAuth2ScopeClaim],
    schemeName = "oauth2",
    tokenUrl = "/oauth/token",
): ApiSecurity =
  oauth2(config, scopeClaimsToScopes(requiredClaims), schemeName, tokenUrl)

proc oauth2Security*(
    config: OAuth2Config,
    requiredScopes: openArray[string] = [],
    schemeName = "oauth2",
    tokenUrl = "/oauth/token",
): ApiSecurity =
  oauth2(config, requiredScopes, schemeName, tokenUrl)

proc hasSecurity*(security: ApiSecurity): bool =
  security.kind != apiSecurityNone

proc openApiSecurityRequirement*(security: ApiSecurity): JsonNode =
  result = newJArray()
  case security.kind
  of apiSecurityNone:
    discard
  of apiSecurityOAuth2:
    var requirement = newJObject()
    requirement[security.schemeName] = %security.requiredScopes
    result.add requirement

proc addOAuth2Scopes(scopes: JsonNode, requiredScopes: openArray[string]) =
  for scope in requiredScopes:
    if scope notin scopes:
      scopes[scope] = %""

proc addOpenApiSecuritySchemes*(components: JsonNode, security: ApiSecurity) =
  if not security.hasSecurity():
    return

  if "securitySchemes" notin components:
    components["securitySchemes"] = newJObject()

  let securitySchemes = components["securitySchemes"]
  case security.kind
  of apiSecurityNone:
    discard
  of apiSecurityOAuth2:
    if security.schemeName notin securitySchemes:
      securitySchemes[security.schemeName] =
        %*{
          "type": "oauth2",
          "flows": {"clientCredentials": {"tokenUrl": security.tokenUrl, "scopes": {}}},
        }

    let scopes =
      securitySchemes[security.schemeName]["flows"]["clientCredentials"]["scopes"]
    scopes.addOAuth2Scopes(security.requiredScopes)
