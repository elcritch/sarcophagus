import std/json

import ../oauth2/core

type
  ApiSecurityKind* = enum
    apiSecurityNone
    apiSecurityOAuth2

  OAuth2FlowKind* = enum
    oauth2FlowClientCredentials
    oauth2FlowAuthorizationCode

  ApiSecurity* = object
    case kind*: ApiSecurityKind
    of apiSecurityNone:
      discard
    of apiSecurityOAuth2:
      oauth2Config*: OAuth2Config
      requiredScopes*: seq[string]
      schemeName*: string
      tokenUrl*: string
      authorizationUrl*: string
      flowKind*: OAuth2FlowKind

proc noSecurity*(): ApiSecurity =
  ApiSecurity(kind: apiSecurityNone)

proc oauth2*(
    config: OAuth2Config,
    requiredScopes: openArray[string] = [],
    schemeName = "oauth2",
    tokenUrl = "/oauth/token",
    flowKind = oauth2FlowClientCredentials,
    authorizationUrl = "/oauth/authorize",
): ApiSecurity =
  ApiSecurity(
    kind: apiSecurityOAuth2,
    oauth2Config: config,
    requiredScopes: @requiredScopes,
    schemeName: schemeName,
    tokenUrl: tokenUrl,
    authorizationUrl: authorizationUrl,
    flowKind: flowKind,
  )

proc oauth2*(
    config: OAuth2Config,
    requiredClaims: openArray[OAuth2ScopeClaim],
    schemeName = "oauth2",
    tokenUrl = "/oauth/token",
    flowKind = oauth2FlowClientCredentials,
    authorizationUrl = "/oauth/authorize",
): ApiSecurity =
  oauth2(
    config,
    scopeClaimsToScopes(requiredClaims),
    schemeName,
    tokenUrl,
    flowKind,
    authorizationUrl,
  )

proc oauth2Security*(
    config: OAuth2Config,
    requiredScopes: openArray[string] = [],
    schemeName = "oauth2",
    tokenUrl = "/oauth/token",
): ApiSecurity =
  oauth2(config, requiredScopes, schemeName, tokenUrl)

proc oauth2AuthorizationCode*(
    config: OAuth2Config,
    requiredScopes: openArray[string] = [],
    schemeName = "oauth2",
    authorizationUrl = "/oauth/authorize",
    tokenUrl = "/oauth/token",
): ApiSecurity =
  oauth2(
    config, requiredScopes, schemeName, tokenUrl, oauth2FlowAuthorizationCode,
    authorizationUrl,
  )

proc oauth2AuthorizationCode*(
    config: OAuth2Config,
    requiredClaims: openArray[OAuth2ScopeClaim],
    schemeName = "oauth2",
    authorizationUrl = "/oauth/authorize",
    tokenUrl = "/oauth/token",
): ApiSecurity =
  oauth2AuthorizationCode(
    config, scopeClaimsToScopes(requiredClaims), schemeName, authorizationUrl, tokenUrl
  )

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
      securitySchemes[security.schemeName] = %*{"type": "oauth2", "flows": {}}

    let flows = securitySchemes[security.schemeName]["flows"]
    let flowName =
      case security.flowKind
      of oauth2FlowClientCredentials: "clientCredentials"
      of oauth2FlowAuthorizationCode: "authorizationCode"

    if flowName notin flows:
      case security.flowKind
      of oauth2FlowClientCredentials:
        flows[flowName] = %*{"tokenUrl": security.tokenUrl, "scopes": {}}
      of oauth2FlowAuthorizationCode:
        flows[flowName] =
          %*{
            "authorizationUrl": security.authorizationUrl,
            "tokenUrl": security.tokenUrl,
            "scopes": {},
          }

    let scopes = flows[flowName]["scopes"]
    scopes.addOAuth2Scopes(security.requiredScopes)
