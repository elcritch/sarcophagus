import std/[monotimes, options, strutils, times]

import mummy

import ./typed_api

type
  ApiMiddlewareResult* = enum
    amContinue
    amHandled

  RouteContext* = ref object
    request*: Request
    config*: ApiConfig
    routeMethod*: string
    routePath*: string
    startedAt*: MonoTime
    responseHeaders*: HttpHeaders
    responseStatus*: int
    failure*: ref Exception
    requestId*: string
    traceparent*: string

  ApiMiddleware* = object
    name*: string
    before*: proc(context: RouteContext): ApiMiddlewareResult {.gcsafe.}
    after*: proc(context: RouteContext) {.gcsafe.}

var activeRouteContext {.threadvar.}: RouteContext

proc currentRouteContext*(): Option[RouteContext] =
  if activeRouteContext.isNil:
    none(RouteContext)
  else:
    some(activeRouteContext)

proc setCurrentRouteContext*(context: RouteContext) =
  activeRouteContext = context

proc clearCurrentRouteContext*() =
  activeRouteContext = nil

proc currentRequestId*(): string =
  let context = currentRouteContext()
  if context.isSome():
    context.get().requestId
  else:
    ""

proc currentTraceparent*(): string =
  let context = currentRouteContext()
  if context.isSome():
    context.get().traceparent
  else:
    ""

proc setResponseHeader*(context: RouteContext, key, value: string) =
  context.responseHeaders[key] = value

proc appendResponseHeaderToken*(context: RouteContext, key, token: string) =
  if key in context.responseHeaders:
    for i in 0 ..< context.responseHeaders.toBase.len:
      let headerValue = context.responseHeaders.toBase[i][1]
      if cmpIgnoreCase(context.responseHeaders.toBase[i][0], key) == 0:
        for part in headerValue.split(','):
          if cmpIgnoreCase(part.strip(), token) == 0:
            return
        context.responseHeaders.toBase[i][1] = headerValue & ", " & token
        return
  context.responseHeaders[key] = token

proc applyMiddlewareResponseHeaders*(headers: var HttpHeaders) =
  let context = currentRouteContext()
  if context.isNone():
    return

  for (key, value) in context.get().responseHeaders:
    if cmpIgnoreCase(key, "Vary") == 0:
      for token in value.split(','):
        context.get().appendResponseHeaderToken("Vary", token.strip())
      headers["Vary"] = context.get().responseHeaders["Vary"]
    elif key notin headers:
      headers[key] = value

proc elapsedMilliseconds*(context: RouteContext): int64 =
  (getMonoTime() - context.startedAt).inNanoseconds div 1_000_000
