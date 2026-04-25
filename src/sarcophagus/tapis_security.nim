import mummy

import ./core/tapis_security
from ./oauth2 import requireOAuth2BearerAuth

export tapis_security

proc secureRequestHandler*(
    wrapped: RequestHandler, security: ApiSecurity
): RequestHandler =
  case security.kind
  of apiSecurityNone:
    wrapped
  of apiSecurityOAuth2:
    let config = security.oauth2Config
    let scopes = security.requiredScopes
    return proc(request: Request) {.gcsafe.} =
      if not requireOAuth2BearerAuth(request, config, scopes):
        return
      wrapped(request)
