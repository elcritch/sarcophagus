import std/macros

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

const scopedSecurityRouteNames =
  ["add", "get", "head", "post", "put", "delete", "options", "patch"]

proc nodeName(node: NimNode): string =
  case node.kind
  of nnkIdent, nnkSym:
    $node
  of nnkOpenSymChoice, nnkClosedSymChoice:
    if node.len > 0:
      nodeName(node[0])
    else:
      ""
  else:
    ""

proc isSecurityArg(node: NimNode): bool =
  node.kind in {nnkExprEqExpr, nnkExprColonExpr} and node.len == 2 and
    node[0].nodeName() == "security"

proc hasSecurityArg(call: NimNode): bool =
  for index in 1 ..< call.len:
    if call[index].isSecurityArg():
      return true

proc isScopedRouteCall(node, api: NimNode): bool =
  if node.kind notin {nnkCall, nnkCommand} or node.len == 0:
    return false

  let callee = node[0]
  if callee.kind != nnkDotExpr or callee.len != 2:
    return false

  callee[0].repr == api.repr and callee[1].nodeName() in scopedSecurityRouteNames

proc isWithSecurityCall(node: NimNode): bool =
  if node.kind notin {nnkCall, nnkCommand} or node.len == 0:
    return false
  node[0].nodeName() == "withSecurity"

proc rewriteWithSecurity(node, api, security: NimNode): NimNode =
  case node.kind
  of nnkStmtList:
    result = newStmtList()
    for child in node:
      result.add rewriteWithSecurity(child, api, security)
  of nnkCall, nnkCommand:
    result = node.copyNimTree()
    if node.isScopedRouteCall(api):
      if not result.hasSecurityArg():
        result.add newTree(nnkExprEqExpr, ident"security", security.copyNimTree())
    elif node.isWithSecurityCall():
      discard
    else:
      for index in 1 ..< result.len:
        result[index] = rewriteWithSecurity(result[index], api, security)
  else:
    result = node.copyNimTree()
    for index in 0 ..< result.len:
      result[index] = rewriteWithSecurity(result[index], api, security)

macro withSecurity*(api: typed, security: typed, body: untyped): untyped =
  rewriteWithSecurity(body, api, security)
