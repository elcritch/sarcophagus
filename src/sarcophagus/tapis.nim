import std/[json, macros, monotimes, options, parseutils, strutils, sysrand]

import mummy
import mummy/routers
import chroniclers
import zippy

import ./core/[swagger, tapis_runtime, typed_api]
from ./oauth2/core import
  OAuth2AuthorizationCodeConsumer, OAuth2AuthorizationCodeSaver, OAuth2Config
from ./oauth2/common import OAuth2CurrentUserLoader
from ./oauth2/hashed_clients import
  HashedOAuth2AuditProc, HashedOAuth2ClientLoader, defaultSecretHashPolicy,
  hashedOAuth2TokenHandler, noopHashedOAuth2Audit
from ./oauth2/mummy_support import oauth2AuthorizeHandler, oauth2TokenHandler
import ./tapis_utils
import ./tapis_security

export swagger, tapis_runtime, typed_api, tapis_security, tapis_utils

type
  RequestIdentityConfig* = object
    requestIdHeader*: string
    traceparentHeader*: string
    generateRequestId*: bool
    echoRequestId*: bool
    echoTraceparent*: bool
    deriveRequestIdFromTraceparent*: bool

  CorsConfig* = object
    allowedOrigins*: seq[string]
    allowedMethods*: seq[string]
    allowedHeaders*: seq[string]
    exposedHeaders*: seq[string]
    allowCredentials*: bool
    maxAgeSeconds*: int

  RegisteredRoute = object
    httpMethod*: string
    path*: string
    parts*: seq[string]

type ApiRouter* = ref object
  ## Typed API router wrapper around a Mummy `Router`.
  ##
  ## The wrapper stores OpenAPI metadata and serialization configuration beside
  ## the underlying Mummy router.
  router*: Router ## Underlying Mummy router.
  config*: ApiConfig ## Request/response codec and error-response configuration.
  title*: string ## OpenAPI document title.
  version*: string ## OpenAPI document version.
  middlewares*: seq[ApiMiddleware]
  paths: JsonNode
  components: JsonNode
  registeredRoutes: seq[RegisteredRoute]
  corsPreflightInstalled: bool

template tapi*(
  httpMethod: untyped,
  path: static string,
  summary: static string = "",
  description: static string = "",
  operationId: static string = "",
  tags: static openArray[string] = [],
  responseStatus: static int = 200,
  request: untyped = apiRequestDoc(),
  responses: untyped = [],
) {.pragma.}
  ## Pragma for annotating procs that can be registered with `api.add`.
  ##
  ## Example: `proc read(id: int): Item {.tapi(get, "/items/@id").} = ...`

proc initApiRouter*(
    title = "API", version = "0.1.0", config = defaultApiConfig()
): ApiRouter =
  ## Creates an `ApiRouter` with empty OpenAPI metadata.
  ApiRouter(
    config: config,
    title: title,
    version: version,
    middlewares: @[],
    paths: newJObject(),
    components: newJObject(),
    registeredRoutes: @[],
    corsPreflightInstalled: false,
  )

proc apiResponse*[T](
    body: sink T, statusCode = 200, headers: sink HttpHeaders
): ApiResponse[T] =
  ## Builds a typed API response from a Mummy `HttpHeaders` collection.
  var apiHeaders: ApiHeaders
  for header in headers:
    apiHeaders.add((header[0], header[1]))
  typed_api.apiResponse(body, statusCode, apiHeaders)

proc toHttpHeaders(headers: ApiHeaders): HttpHeaders =
  for header in headers:
    result[header.name] = header.value

proc parseQValue(value: string): float =
  let trimmed = value.strip()
  if trimmed.len == 0:
    return 1.0
  var parsed = 0.0
  if parseFloat(trimmed, parsed) == trimmed.len: parsed else: 0.0

proc headerAcceptsToken(headers: HttpHeaders, key, token: string): bool =
  ## Parses comma-separated HTTP header tokens and honors q=0 opt-outs.
  for (headerKey, headerValue) in headers:
    if cmpIgnoreCase(headerKey, key) != 0:
      continue
    for rawPart in headerValue.split(','):
      let part = rawPart.strip()
      if part.len == 0:
        continue
      let semicolon = part.find(';')
      let value =
        if semicolon >= 0:
          part[0 ..< semicolon].strip()
        else:
          part
      if cmpIgnoreCase(value, token) != 0:
        continue

      var q = 1.0
      if semicolon >= 0:
        for rawParam in part[semicolon + 1 .. ^1].split(';'):
          let param = rawParam.strip()
          let eq = param.find('=')
          if eq > 0 and cmpIgnoreCase(param[0 ..< eq].strip(), "q") == 0:
            q = parseQValue(param[eq + 1 .. ^1])
      if q > 0.0:
        return true

proc appendHeaderToken(headers: var HttpHeaders, key, token: string) =
  if key in headers:
    for i in 0 ..< headers.toBase.len:
      let headerValue = headers.toBase[i][1]
      if cmpIgnoreCase(headers.toBase[i][0], key) == 0:
        for part in headerValue.split(','):
          if cmpIgnoreCase(part.strip(), token) == 0:
            return
        headers.toBase[i][1] = headerValue & ", " & token
        return
  headers[key] = token

proc concatMiddlewares*(
    first: openArray[ApiMiddleware], second: openArray[ApiMiddleware]
): seq[ApiMiddleware] =
  result = @[]
  for middleware in first:
    result.add(middleware)
  for middleware in second:
    result.add(middleware)

proc useMiddleware*(api: ApiRouter, middleware: ApiMiddleware) =
  api.middlewares.add(middleware)

proc useMiddleware*(api: ApiRouter, middlewares: openArray[ApiMiddleware]) =
  api.middlewares.add(middlewares)

proc addRequestHandler*(
  api: ApiRouter,
  httpMethod, path: string,
  handler: RequestHandler,
  middlewares: seq[ApiMiddleware] = @[],
)

proc routeParts(path: string): seq[string] =
  result = path.split('/')
  if result.len > 0:
    result.delete(0)

proc registerRoute(api: ApiRouter, httpMethod, path: string) =
  api.registeredRoutes.add(
    RegisteredRoute(httpMethod: httpMethod, path: path, parts: routeParts(path))
  )

proc isPartialWildcard(test: string): bool {.inline.} =
  test.len >= 2 and (test.startsWith('*') or test.endsWith('*'))

proc partialWildcardMatches(partialWildcard, test: string): bool {.inline.} =
  let
    wildcardPrefix = partialWildcard[0] == '*'
    wildcardSuffix = partialWildcard[^1] == '*'

  var
    literalLen = partialWildcard.len
    literalStart = 0
  if wildcardPrefix:
    dec literalLen
    inc literalStart
  if wildcardSuffix:
    dec literalLen

  if literalLen > test.len:
    return false

  if wildcardPrefix and not wildcardSuffix:
    return equalMem(
      partialWildcard[1].unsafeAddr, test[test.len - literalLen].unsafeAddr, literalLen
    )

  if wildcardSuffix and not wildcardPrefix:
    return equalMem(partialWildcard[0].unsafeAddr, test[0].unsafeAddr, literalLen)

  partialWildcard[1 .. ^2] in test

proc routeMatchesPath(route: RegisteredRoute, path: string): bool =
  if path.len == 0 or path[0] != '/':
    return false

  let pathParts = routeParts(path)
  if route.parts.len > pathParts.len:
    return false

  var
    i = 0
    matchedRoute = true
    atLeastOneMultiWildcardMatch = false

  for j, part in pathParts:
    if i >= route.parts.len:
      matchedRoute = false
      break

    if route.parts[i] == "*":
      inc i
    elif route.parts[i].len >= 2 and route.parts[i].startsWith('@'):
      inc i
    elif route.parts[i] == "**":
      if i + 1 < route.parts.len and atLeastOneMultiWildcardMatch:
        let matchesNextLiteral =
          if route.parts[i + 1].isPartialWildcard():
            partialWildcardMatches(route.parts[i + 1], part)
          else:
            part == route.parts[i + 1]
        if matchesNextLiteral:
          i += 2
          atLeastOneMultiWildcardMatch = false
        elif j == pathParts.high:
          matchedRoute = false
          break
      else:
        atLeastOneMultiWildcardMatch = true
    elif route.parts[i].isPartialWildcard():
      if not partialWildcardMatches(route.parts[i], part):
        matchedRoute = false
        break
      inc i
    else:
      if part != route.parts[i]:
        matchedRoute = false
        break
      inc i

  matchedRoute

proc routeMethodsForPath(api: ApiRouter, path: string): seq[string] =
  for route in api.registeredRoutes:
    if not route.routeMatchesPath(path):
      continue
    if route.httpMethod == "OPTIONS":
      continue
    if route.httpMethod notin result:
      result.add(route.httpMethod)

proc normalizeHttpTokens(values: openArray[string]): seq[string] =
  for value in values:
    let normalized = value.strip()
    if normalized.len == 0:
      continue
    let token = normalized.toUpperAscii()
    if token notin result:
      result.add(token)

proc corsConfig*(
    allowedOrigins: openArray[string] = [],
    allowedMethods: openArray[string] = [],
    allowedHeaders: openArray[string] = [],
    exposedHeaders: openArray[string] = [],
    allowCredentials = false,
    maxAgeSeconds = 0,
): CorsConfig =
  result.allowedOrigins = @allowedOrigins
  result.allowedMethods = normalizeHttpTokens(allowedMethods)
  result.allowedHeaders = @allowedHeaders
  result.exposedHeaders = @exposedHeaders
  result.allowCredentials = allowCredentials
  result.maxAgeSeconds = maxAgeSeconds

proc requestIdentityConfig*(
    requestIdHeader = "X-Request-ID",
    traceparentHeader = "traceparent",
    generateRequestId = true,
    echoRequestId = true,
    echoTraceparent = true,
    deriveRequestIdFromTraceparent = true,
): RequestIdentityConfig =
  result.requestIdHeader = requestIdHeader.strip()
  result.traceparentHeader = traceparentHeader.strip()
  result.generateRequestId = generateRequestId
  result.echoRequestId = echoRequestId
  result.echoTraceparent = echoTraceparent
  result.deriveRequestIdFromTraceparent = deriveRequestIdFromTraceparent

proc isLowerHex(value: string): bool =
  for ch in value:
    if ch notin {'0' .. '9', 'a' .. 'f'}:
      return false
  true

proc isAllZeroHex(value: string): bool =
  for ch in value:
    if ch != '0':
      return false
  true

proc parseTraceparentTraceId(headerValue: string): Option[string] =
  let parts = headerValue.strip().split('-')
  if parts.len != 4:
    return none(string)
  if parts[0].len != 2 or parts[1].len != 32 or parts[2].len != 16 or parts[3].len != 2:
    return none(string)
  if not parts[0].isLowerHex() or not parts[1].isLowerHex() or not parts[2].isLowerHex() or
      not parts[3].isLowerHex():
    return none(string)
  if parts[1].isAllZeroHex() or parts[2].isAllZeroHex():
    return none(string)
  some(parts[1])

proc generateRequestIdValue(): string =
  var bytes = newSeq[byte](16)
  if not urandom(bytes):
    raise newException(OSError, "failed to generate request id")

  const digits = "0123456789abcdef"
  result = newStringOfCap(bytes.len * 2)
  for value in bytes:
    result.add(digits[int(value shr 4)])
    result.add(digits[int(value and 0x0f)])

proc requestIdentityMiddleware*(
    config: RequestIdentityConfig = requestIdentityConfig()
): ApiMiddleware =
  result.name = "requestIdentity"
  result.before = proc(context: RouteContext): ApiMiddlewareResult {.gcsafe.} =
    let incomingTraceparent = context.request.headers[config.traceparentHeader].strip()
    let incomingRequestId = context.request.headers[config.requestIdHeader].strip()
    if incomingTraceparent.len > 0:
      context.traceparent = incomingTraceparent
    if incomingRequestId.len > 0:
      context.requestId = incomingRequestId
    elif config.deriveRequestIdFromTraceparent:
      let traceId = parseTraceparentTraceId(incomingTraceparent)
      if traceId.isSome():
        context.requestId = traceId.get()
    if context.requestId.len == 0 and config.generateRequestId:
      context.requestId = generateRequestIdValue()

    if config.echoRequestId and context.requestId.len > 0:
      context.setResponseHeader(config.requestIdHeader, context.requestId)
    if config.echoTraceparent and context.traceparent.len > 0:
      context.setResponseHeader(config.traceparentHeader, context.traceparent)
    amContinue

proc useRequestIdentity*(
    api: ApiRouter, config: RequestIdentityConfig = requestIdentityConfig()
) =
  api.useMiddleware(requestIdentityMiddleware(config))

proc originAllowed(config: CorsConfig, origin: string): bool =
  if origin.len == 0:
    return false
  if config.allowedOrigins.len == 0:
    return false
  if "*" in config.allowedOrigins:
    return true
  origin in config.allowedOrigins

proc corsAllowOriginValue(config: CorsConfig, origin: string): string =
  if "*" in config.allowedOrigins and not config.allowCredentials: "*" else: origin

proc appendCorsVary(headers: var HttpHeaders) =
  headers.appendHeaderToken("Vary", "Origin")
  headers.appendHeaderToken("Vary", "Access-Control-Request-Method")
  headers.appendHeaderToken("Vary", "Access-Control-Request-Headers")

proc corsAllowedMethods(
    config: CorsConfig, registeredMethods: openArray[string]
): seq[string] =
  let normalizedRegistered = normalizeHttpTokens(registeredMethods)
  if config.allowedMethods.len == 0:
    return normalizedRegistered
  for httpMethod in normalizedRegistered:
    if httpMethod in config.allowedMethods:
      result.add(httpMethod)

proc applyCorsResponseHeaders(
    headers: var HttpHeaders,
    config: CorsConfig,
    origin: string,
    methods: openArray[string] = [],
    requestedHeaders = "",
) =
  headers["Access-Control-Allow-Origin"] = corsAllowOriginValue(config, origin)
  if headers["Access-Control-Allow-Origin"] != "*":
    headers.appendCorsVary()
  if config.allowCredentials:
    headers["Access-Control-Allow-Credentials"] = "true"
  if config.exposedHeaders.len > 0:
    headers["Access-Control-Expose-Headers"] = config.exposedHeaders.join(", ")
  if methods.len > 0:
    headers["Access-Control-Allow-Methods"] = normalizeHttpTokens(methods).join(", ")
  if config.allowedHeaders.len > 0:
    headers["Access-Control-Allow-Headers"] = config.allowedHeaders.join(", ")
  elif requestedHeaders.len > 0:
    headers["Access-Control-Allow-Headers"] = requestedHeaders
  if config.maxAgeSeconds > 0:
    headers["Access-Control-Max-Age"] = $config.maxAgeSeconds

proc corsMiddleware*(api: ApiRouter, config: CorsConfig): ApiMiddleware =
  result.name = "cors"
  result.before = proc(context: RouteContext): ApiMiddlewareResult {.gcsafe.} =
    let request = context.request
    let origin = request.headers["Origin"].strip()
    if origin.len == 0:
      return amContinue
    if not config.originAllowed(origin):
      if request.httpMethod == "OPTIONS" and
          request.headers["Access-Control-Request-Method"].strip().len > 0:
        request.respond(403)
        return amHandled
      return amContinue

    let allowedMethods =
      corsAllowedMethods(config, api.routeMethodsForPath(request.path))
    if request.httpMethod == "OPTIONS":
      let requestedMethod =
        request.headers["Access-Control-Request-Method"].strip().toUpperAscii()
      if requestedMethod.len == 0:
        return amContinue
      if allowedMethods.len == 0:
        return amContinue
      if requestedMethod notin allowedMethods:
        var headers: HttpHeaders
        headers["Allow"] = allowedMethods.join(", ")
        headers.applyCorsResponseHeaders(
          config,
          origin,
          allowedMethods,
          request.headers["Access-Control-Request-Headers"],
        )
        request.respond(405, headers)
        return amHandled

      var headers: HttpHeaders
      headers.applyCorsResponseHeaders(
        config,
        origin,
        allowedMethods,
        request.headers["Access-Control-Request-Headers"],
      )
      request.respond(204, headers)
      return amHandled

    context.setResponseHeader(
      "Access-Control-Allow-Origin", corsAllowOriginValue(config, origin)
    )
    if corsAllowOriginValue(config, origin) != "*":
      context.appendResponseHeaderToken("Vary", "Origin")
    if config.allowCredentials:
      context.setResponseHeader("Access-Control-Allow-Credentials", "true")
    if config.exposedHeaders.len > 0:
      context.setResponseHeader(
        "Access-Control-Expose-Headers", config.exposedHeaders.join(", ")
      )
    amContinue

proc useCors*(api: ApiRouter, config: CorsConfig) =
  api.useMiddleware(api.corsMiddleware(config))
  if api.corsPreflightInstalled:
    return

  api.corsPreflightInstalled = true
  api.addRequestHandler(
    "OPTIONS",
    "/**",
    proc(request: Request) {.gcsafe.} =
      let allowedMethods = api.routeMethodsForPath(request.path)
      if allowedMethods.len == 0:
        request.respond(404)
        return

      var headers: HttpHeaders
      headers["Allow"] = allowedMethods.join(", ")
      request.respond(204, headers),
  )

type ContentEncoding = enum
  contentEncodingGzip
  contentEncodingDeflate

proc responseContentEncoding(request: Request): Option[ContentEncoding] =
  if request.headers.headerAcceptsToken("Accept-Encoding", "gzip"):
    return some(contentEncodingGzip)
  if request.headers.headerAcceptsToken("Accept-Encoding", "deflate"):
    return some(contentEncodingDeflate)

proc compressResponse(
    request: Request, statusCode: int, headers: var HttpHeaders, body: var string
) =
  if body.len <= 860:
    return
  if statusCode == 204 or (statusCode >= 100 and statusCode < 200):
    return
  if "Content-Encoding" in headers:
    return

  let encoding = responseContentEncoding(request)
  if encoding.isNone():
    return

  try:
    case encoding.get()
    of contentEncodingGzip:
      body = compress(body.cstring, body.len, BestSpeed, dfGzip)
      headers["Content-Encoding"] = "gzip"
    of contentEncodingDeflate:
      body = compress(body.cstring, body.len, BestSpeed, dfDeflate)
      headers["Content-Encoding"] = "deflate"
    headers.appendHeaderToken("Vary", "Accept-Encoding")
    headers["Content-Length"] = $body.len
  except CatchableError as e:
    discard e
    trace "tapis response compression failed",
      httpMethod = request.httpMethod,
      path = request.path,
      uri = request.uri,
      statusCode = statusCode,
      exception = e.name,
      message = e.msg

proc requestFormat(request: Request, config: ApiConfig): ApiFormat =
  typed_api.requestFormat(request.headers["Content-Type"], config)

proc responseFormat(request: Request, config: ApiConfig): ApiFormat =
  typed_api.responseFormat(request.headers["Accept"], config)

proc respondEncoded(
    request: Request,
    statusCode: int,
    format: ApiFormat,
    body: sink string,
    headers: sink HttpHeaders = emptyHttpHeaders(),
) =
  var responseHeaders = headers
  responseHeaders["Content-Type"] = formatContentType(format)
  responseHeaders.applyMiddlewareResponseHeaders()
  if currentRouteContext().isSome():
    currentRouteContext().get().responseStatus = statusCode
  compressResponse(request, statusCode, responseHeaders, body)
  trace "tapis response encoded",
    httpMethod = request.httpMethod,
    path = request.path,
    uri = request.uri,
    statusCode = statusCode,
    contentType = responseHeaders["Content-Type"],
    contentEncoding = responseHeaders["Content-Encoding"],
    bodyLength = body.len,
    requestId = currentRequestId(),
    traceparent = currentTraceparent()
  if request.httpMethod == "HEAD":
    responseHeaders["Content-Length"] = $body.len
    request.respond(statusCode, responseHeaders)
  else:
    request.respond(statusCode, responseHeaders, body)

proc respondApi[T](
    request: Request,
    value: T,
    config: ApiConfig,
    statusCode: int,
    headers: sink HttpHeaders = emptyHttpHeaders(),
) =
  let format = responseFormat(request, config)
  request.respondEncoded(statusCode, format, encodeApi(value, format), headers)

proc respondApi[T](request: Request, value: ApiResponse[T], config: ApiConfig) =
  let format = responseFormat(request, config)
  request.respondEncoded(
    value.statusCode,
    format,
    encodeApi(value.body, format),
    value.headers.toHttpHeaders(),
  )

proc traceTapisRawResponse(
    request: Request, statusCode: int, contentType: string, bodyLength: int
) {.gcsafe.} =
  trace "tapis raw response",
    httpMethod = request.httpMethod,
    path = request.path,
    uri = request.uri,
    statusCode = statusCode,
    contentType = contentType,
    bodyLength = bodyLength,
    requestId = currentRequestId(),
    traceparent = currentTraceparent()

proc traceMiddlewareAfterHookRaised(
    request: Request,
    routeMethod, routePath, middlewareName, requestId, traceparent, exceptionName,
      exceptionMessage: string,
) {.gcsafe.} =
  trace "tapis middleware after hook raised",
    httpMethod = request.httpMethod,
    path = request.path,
    uri = request.uri,
    routeMethod = routeMethod,
    routePath = routePath,
    middleware = middlewareName,
    requestId = requestId,
    traceparent = traceparent,
    exception = exceptionName,
    message = exceptionMessage

proc respondRaw[contentType: static string](
    request: Request, value: RawResponse[contentType]
) =
  var headers = value.headers.toHttpHeaders()
  headers["Content-Type"] = contentType
  headers.applyMiddlewareResponseHeaders()
  if currentRouteContext().isSome():
    currentRouteContext().get().responseStatus = value.statusCode
  var body = value.body
  compressResponse(request, value.statusCode, headers, body)
  traceTapisRawResponse(request, value.statusCode, contentType, body.len)
  if request.httpMethod == "HEAD":
    headers["Content-Length"] = $body.len
    request.respond(value.statusCode, headers)
  else:
    request.respond(value.statusCode, headers, body)

proc respondRouteValue[T](
    request: Request, value: T, config: ApiConfig, responseStatus: int
) =
  request.respondApi(value, config, responseStatus)

proc respondRouteValue[T](
    request: Request, value: ApiResponse[T], config: ApiConfig, responseStatus: int
) =
  request.respondApi(value, config)

proc respondRouteValue[contentType: static string](
    request: Request,
    value: RawResponse[contentType],
    config: ApiConfig,
    responseStatus: int,
) =
  request.respondRaw(value)

proc requestParam(request: Request, name: string): Option[string] =
  if name in request.pathParams:
    return some(request.pathParams[name])
  if name in request.queryParams:
    return some(request.queryParams[name])
  none(string)

proc tupleFieldIndex(name: string): Option[string] =
  if not name.startsWith("Field") or name.len <= "Field".len:
    return none(string)

  let index = name["Field".len .. ^1]
  for ch in index:
    if ch notin {'0' .. '9'}:
      return none(string)
  some(index)

proc requestParamForField(request: Request, name: string): Option[string] =
  result = request.requestParam(name)
  if result.isSome():
    return

  let index = tupleFieldIndex(name)
  if index.isNone():
    return

  for alias in [index.get(), "p" & index.get(), "arg" & index.get()]:
    result = request.requestParam(alias)
    if result.isSome():
      return

proc parseRequestParamValue*[T](
    request: Request, name: string, target: typedesc[T]
): T =
  ## Parses one path or query parameter from a Mummy request.
  ##
  ## Missing required values and conversion failures are raised as `ApiError`.
  let raw = request.requestParamForField(name)
  if raw.isSome():
    parseApiParam(raw.get(), name, T)
  else:
    missingApiParam(name, T)

proc parseRequestParamValue*[T](request: Request, name: string): T =
  ## Parses one path or query parameter with the target type inferred.
  parseRequestParamValue(request, name, T)

proc parseRequestParams*[T](request: Request, target: typedesc[T]): T =
  ## Parses all fields of an object or tuple from path/query parameters.
  when T is EmptyInput or T is EmptyParams or T is EmptyBody:
    discard
  elif T is object or T is tuple:
    for name, value in result.fieldPairs:
      value = parseRequestParamValue(request, name, typeof(value))
  else:
    {.error: "API parameter input must be an object or tuple type".}

proc decodeRequestBody*[T](
    request: Request, config: ApiConfig, target: typedesc[T]
): T =
  ## Decodes the request body according to `Content-Type` and `config`.
  when T is EmptyInput or T is EmptyBody:
    discard
  else:
    if request.body.len == 0:
      raiseApiError(400, "Missing request body", "missing_body")
    let format = requestFormat(request, config)
    try:
      decodeApi(request.body, format, T)
    except ApiError:
      raise
    except CatchableError as e:
      raiseApiError(400, "Invalid request body: " & e.msg, "invalid_body")

proc decodeInput*[T](
    request: Request, config: ApiConfig, source: ApiDecodeSource, target: typedesc[T]
): T =
  ## Decodes route input from parameters, body, or no source.
  case source
  of adsNone:
    when T is EmptyInput:
      discard
    else:
      raiseApiError(500, "Route has no input decoder", "route_input_error")
  of adsParams:
    parseRequestParams(request, T)
  of adsBody:
    decodeRequestBody(request, config, T)

proc decodeInput*[Params, Body](
    request: Request,
    config: ApiConfig,
    source: ApiDecodeSource,
    target: typedesc[ApiRequest[Params, Body]],
): ApiRequest[Params, Body] =
  ## Decodes combined path/query parameters and request body input.
  result.params = parseRequestParams(request, Params)
  result.body = decodeRequestBody(request, config, Body)

proc addEndpoint*[In, Out](
    api: ApiRouter,
    httpMethod, path: string,
    source: ApiDecodeSource,
    meta: EndpointMeta,
    input: typedesc[In],
    output: typedesc[Out],
) =
  ## Adds endpoint metadata to the router's OpenAPI document.
  api.components.addOpenApiSecuritySchemes(meta.security)
  swagger.addEndpoint(api.paths, httpMethod, path, source, meta, In, Out)

proc newParameterSchemas*(): JsonNode =
  ## Creates an OpenAPI parameter schema array.
  newJArray()

proc addParameterSchema*[T](
    parameters: JsonNode, path, name: string, target: typedesc[T]
) =
  ## Adds one OpenAPI parameter schema to `parameters`.
  parameters.add swagger.parameterSchema(path, name, T)

proc addParameterSchema*[T](parameters: JsonNode, path, name: string) =
  ## Adds one OpenAPI parameter schema with the target type inferred.
  addParameterSchema(parameters, path, name, T)

proc addEndpointWithParams*[Out](
    api: ApiRouter,
    httpMethod, path: string,
    meta: EndpointMeta,
    parameters: JsonNode,
    output: typedesc[Out],
) =
  ## Adds endpoint metadata when parameter schemas were built explicitly.
  api.components.addOpenApiSecuritySchemes(meta.security)
  swagger.addEndpointWithParams(api.paths, httpMethod, path, meta, parameters, Out)

proc addEndpointWithParams*[Out](
    api: ApiRouter, httpMethod, path: string, meta: EndpointMeta, parameters: JsonNode
) =
  ## Adds endpoint metadata with inferred output type.
  addEndpointWithParams(api, httpMethod, path, meta, parameters, Out)

proc addEndpointWithParamsAndBody*[Body, Out](
    api: ApiRouter,
    httpMethod, path: string,
    meta: EndpointMeta,
    parameters: JsonNode,
    body: typedesc[Body],
    output: typedesc[Out],
) =
  ## Adds endpoint metadata for flat handlers with path/query params and a body.
  api.components.addOpenApiSecuritySchemes(meta.security)
  swagger.addEndpointWithParamsAndBody(
    api.paths, httpMethod, path, meta, parameters, Body, Out
  )

proc addEndpointWithParamsAndBody*[Body, Out](
    api: ApiRouter,
    httpMethod, path: string,
    meta: EndpointMeta,
    parameters: JsonNode,
    body: typedesc[Body],
) =
  ## Adds endpoint metadata for flat handlers with inferred output type.
  addEndpointWithParamsAndBody(api, httpMethod, path, meta, parameters, Body, Out)

proc addRequestHandler*(
    api: ApiRouter,
    httpMethod, path: string,
    handler: RequestHandler,
    middlewares: seq[ApiMiddleware] = @[],
) =
  ## Registers a raw Mummy request handler on the wrapped router.
  api.registerRoute(httpMethod, path)
  let routeMiddlewares = concatMiddlewares(api.middlewares, middlewares)
  let tracedHandler: RequestHandler = proc(request: Request) {.gcsafe.} =
    let previousContext = currentRouteContext()
    var context = RouteContext(
      request: request,
      config: api.config,
      routeMethod: httpMethod,
      routePath: path,
      startedAt: getMonoTime(),
      responseHeaders: emptyHttpHeaders(),
      responseStatus: 0,
    )
    setCurrentRouteContext(context)
    var executedMiddlewares = 0
    try:
      for middleware in routeMiddlewares:
        inc executedMiddlewares
        if middleware.before != nil and middleware.before(context) == amHandled:
          trace "tapis request handled in middleware",
            httpMethod = request.httpMethod,
            path = request.path,
            uri = request.uri,
            routeMethod = httpMethod,
            routePath = path,
            middleware = middleware.name,
            requestId = context.requestId,
            traceparent = context.traceparent
          return
      trace "tapis request received",
        httpMethod = request.httpMethod,
        path = request.path,
        uri = request.uri,
        routeMethod = httpMethod,
        routePath = path,
        pathParamCount = request.pathParams.len,
        queryParamCount = request.queryParams.len,
        bodyLength = request.body.len,
        contentType = request.headers["Content-Type"],
        accept = request.headers["Accept"],
        requestId = context.requestId,
        traceparent = context.traceparent
      handler(request)
      trace "tapis request handler returned",
        httpMethod = request.httpMethod,
        path = request.path,
        uri = request.uri,
        routeMethod = httpMethod,
        routePath = path,
        requestId = context.requestId,
        traceparent = context.traceparent
    except CatchableError as e:
      context.failure = e
      trace "tapis request handler raised",
        httpMethod = request.httpMethod,
        path = request.path,
        uri = request.uri,
        routeMethod = httpMethod,
        routePath = path,
        requestId = context.requestId,
        traceparent = context.traceparent,
        exception = e.name,
        message = e.msg
      raise
    finally:
      if executedMiddlewares > 0:
        for index in countdown(executedMiddlewares - 1, 0):
          let middleware = routeMiddlewares[index]
          if middleware.after == nil:
            continue
          try:
            middleware.after(context)
          except CatchableError as e:
            traceMiddlewareAfterHookRaised(
              request, httpMethod, path, middleware.name, context.requestId,
              context.traceparent, $e.name, e.msg,
            )
      if previousContext.isSome():
        setCurrentRouteContext(previousContext.get())
      else:
        clearCurrentRouteContext()
  api.router.addRoute(httpMethod, path, tracedHandler)

proc registerOAuth2*(api: ApiRouter, config: OAuth2Config, tokenPath = "/oauth/token") =
  ## Mounts the OAuth2 token endpoint on this typed API router.
  api.addRequestHandler("POST", tokenPath, oauth2TokenHandler(config))

proc registerHashedOAuth2*(
    api: ApiRouter,
    config: OAuth2Config,
    loadClient: HashedOAuth2ClientLoader,
    tokenPath = "/oauth/token",
    onAudit: HashedOAuth2AuditProc = noopHashedOAuth2Audit,
    policy = defaultSecretHashPolicy(),
) =
  ## Mounts a hashed-client OAuth2 token endpoint on this typed API router.
  api.addRequestHandler(
    "POST",
    tokenPath,
    hashedOAuth2TokenHandler(config, loadClient, onAudit = onAudit, policy = policy),
  )

proc registerOAuth2AuthorizationCode*(
    api: ApiRouter,
    config: OAuth2Config,
    saveAuthorizationCode: OAuth2AuthorizationCodeSaver,
    consumeAuthorizationCode: OAuth2AuthorizationCodeConsumer,
    currentUser: OAuth2CurrentUserLoader,
    tokenPath = "/oauth/token",
    authorizationPath = "/oauth/authorize",
    loginUrl = "/login",
) =
  ## Mounts OAuth2 authorization-code endpoints on this API router.
  api.addRequestHandler(
    "GET",
    authorizationPath,
    oauth2AuthorizeHandler(config, saveAuthorizationCode, currentUser, loginUrl),
  )
  api.addRequestHandler(
    "POST", tokenPath, oauth2TokenHandler(config, consumeAuthorizationCode)
  )

proc respondApiError*(request: Request, e: ref Exception, config: ApiConfig) =
  ## Converts an exception to a negotiated TAPIS error response.
  let statusCode = apiErrorStatus(e)
  let body = apiErrorBody(e, config)
  if statusCode >= 500:
    error "tapis request failed",
      httpMethod = request.httpMethod,
      path = request.path,
      uri = request.uri,
      statusCode = statusCode,
      errorCode = apiErrorCode(e),
      exception = e.name,
      message = e.msg,
      requestId = currentRequestId(),
      traceparent = currentTraceparent()
  else:
    warn "tapis request rejected",
      httpMethod = request.httpMethod,
      path = request.path,
      uri = request.uri,
      statusCode = statusCode,
      errorCode = apiErrorCode(e),
      exception = e.name,
      message = e.msg,
      requestId = currentRequestId(),
      traceparent = currentTraceparent()
  let format =
    try:
      responseFormat(request, config)
    except CatchableError:
      apiJson
  request.respondEncoded(statusCode, format, encodeApi(body, format))

proc toApiHandler*[Out](
    handler: proc(): Out {.gcsafe.}, config: ApiConfig, responseStatus: int
): RequestHandler =
  ## Converts a no-argument typed handler into a Mummy request handler.
  return proc(request: Request) {.gcsafe.} =
    try:
      request.respondRouteValue(handler(), config, responseStatus)
    except CatchableError as e:
      request.respondApiError(e, config)

proc toMummyHandler*[Out](
    handler: proc(): Out {.gcsafe.},
    config: ApiConfig = defaultApiConfig(),
    responseStatus = 200,
): RequestHandler =
  ## Converts a typed no-argument TAPIS-style handler to a plain Mummy handler.
  toApiHandler(handler, config, responseStatus)

proc toApiHandler*[Out](
    handler: proc(request: Request): Out {.gcsafe.},
    config: ApiConfig,
    responseStatus: int,
): RequestHandler =
  ## Converts a request-aware typed handler into a Mummy request handler.
  return proc(request: Request) {.gcsafe.} =
    try:
      request.respondRouteValue(handler(request), config, responseStatus)
    except CatchableError as e:
      request.respondApiError(e, config)

proc toMummyHandler*[Out](
    handler: proc(request: Request): Out {.gcsafe.},
    config: ApiConfig = defaultApiConfig(),
    responseStatus = 200,
): RequestHandler =
  ## Converts a request-aware typed TAPIS-style handler to a plain Mummy handler.
  toApiHandler(handler, config, responseStatus)

proc toApiHandler*[In, Out](
    handler: proc(input: In): Out {.gcsafe.},
    config: ApiConfig,
    source: ApiDecodeSource,
    responseStatus: int,
): RequestHandler =
  ## Converts a typed-input handler into a Mummy request handler.
  return proc(request: Request) {.gcsafe.} =
    try:
      let input = decodeInput(request, config, source, In)
      request.respondRouteValue(handler(input), config, responseStatus)
    except CatchableError as e:
      request.respondApiError(e, config)

proc toMummyHandler*[In, Out](
    handler: proc(input: In): Out {.gcsafe.},
    source: ApiDecodeSource,
    config: ApiConfig = defaultApiConfig(),
    responseStatus = 200,
): RequestHandler =
  ## Converts a typed-input TAPIS-style handler to a plain Mummy handler.
  toApiHandler(handler, config, source, responseStatus)

proc toApiHandler*[In, Out](
    handler: proc(request: Request, input: In): Out {.gcsafe.},
    config: ApiConfig,
    source: ApiDecodeSource,
    responseStatus: int,
): RequestHandler =
  ## Converts a request-aware typed-input handler into a Mummy request handler.
  return proc(request: Request) {.gcsafe.} =
    try:
      let input = decodeInput(request, config, source, In)
      request.respondRouteValue(handler(request, input), config, responseStatus)
    except CatchableError as e:
      request.respondApiError(e, config)

proc toMummyHandler*[In, Out](
    handler: proc(request: Request, input: In): Out {.gcsafe.},
    source: ApiDecodeSource,
    config: ApiConfig = defaultApiConfig(),
    responseStatus = 200,
): RequestHandler =
  ## Converts a request-aware typed-input TAPIS-style handler to a plain Mummy handler.
  toApiHandler(handler, config, source, responseStatus)

proc route*[Out](
    api: ApiRouter,
    httpMethod, path: string,
    handler: proc(): Out {.gcsafe.},
    source: ApiDecodeSource = adsNone,
    middlewares: seq[ApiMiddleware] = @[],
    meta: EndpointMeta = endpointMeta(),
) =
  ## Registers a typed route with no decoded input.
  api.addEndpoint(httpMethod, path, source, meta, EmptyInput, Out)
  let securedHandler = secureRequestHandler(
    toApiHandler(handler, api.config, meta.responseStatus), meta.security
  )
  if middlewares.len == 0:
    api.addRequestHandler(httpMethod, path, securedHandler)
  else:
    api.addRequestHandler(httpMethod, path, securedHandler, middlewares)

proc route*[Out](
    api: ApiRouter,
    httpMethod, path: string,
    handler: proc(request: Request): Out {.gcsafe.},
    source: ApiDecodeSource = adsNone,
    middlewares: seq[ApiMiddleware] = @[],
    meta: EndpointMeta = endpointMeta(),
) =
  ## Registers a request-aware typed route with no decoded input.
  api.addEndpoint(httpMethod, path, source, meta, EmptyInput, Out)
  let securedHandler = secureRequestHandler(
    toApiHandler(handler, api.config, meta.responseStatus), meta.security
  )
  if middlewares.len == 0:
    api.addRequestHandler(httpMethod, path, securedHandler)
  else:
    api.addRequestHandler(httpMethod, path, securedHandler, middlewares)

proc route*[In, Out](
    api: ApiRouter,
    httpMethod, path: string,
    handler: proc(input: In): Out {.gcsafe.},
    source: ApiDecodeSource,
    middlewares: seq[ApiMiddleware] = @[],
    meta: EndpointMeta = endpointMeta(),
) =
  ## Registers a typed route with decoded parameters or body input.
  api.addEndpoint(httpMethod, path, source, meta, In, Out)
  let securedHandler = secureRequestHandler(
    toApiHandler(handler, api.config, source, meta.responseStatus), meta.security
  )
  if middlewares.len == 0:
    api.addRequestHandler(httpMethod, path, securedHandler)
  else:
    api.addRequestHandler(httpMethod, path, securedHandler, middlewares)

proc route*[In, Out](
    api: ApiRouter,
    httpMethod, path: string,
    handler: proc(request: Request, input: In): Out {.gcsafe.},
    source: ApiDecodeSource,
    middlewares: seq[ApiMiddleware] = @[],
    meta: EndpointMeta = endpointMeta(),
) =
  ## Registers a request-aware typed route with decoded input.
  api.addEndpoint(httpMethod, path, source, meta, In, Out)
  let securedHandler = secureRequestHandler(
    toApiHandler(handler, api.config, source, meta.responseStatus), meta.security
  )
  if middlewares.len == 0:
    api.addRequestHandler(httpMethod, path, securedHandler)
  else:
    api.addRequestHandler(httpMethod, path, securedHandler, middlewares)

type HandlerParam = object
  name: string
  typeNode: NimNode

proc typeName(node: NimNode): string =
  case node.kind
  of nnkIdent, nnkSym:
    $node
  of nnkOpenSymChoice, nnkClosedSymChoice:
    if node.len > 0:
      typeName(node[0])
    else:
      ""
  of nnkBracketExpr:
    if node.len > 0:
      typeName(node[0])
    else:
      ""
  of nnkDotExpr:
    if node.len > 0:
      typeName(node[^1])
    else:
      ""
  else:
    ""

proc isRequestType(node: NimNode): bool =
  node.typeName() == "Request"

proc isParamsType(node: NimNode): bool =
  node.typeName().normalize() == "params"

proc isBodyType(node: NimNode): bool =
  node.typeName().normalize() == "body"

proc bodyInnerType(node: NimNode): NimNode =
  if node.isBodyType() and node.kind == nnkBracketExpr and node.len >= 2:
    node[1].copyNimTree()
  else:
    node.copyNimTree()

proc isApiRequestType(node: NimNode): bool =
  node.typeName() == "ApiRequest"

proc isGroupedValueType(node: NimNode): bool =
  if node.isRequestType():
    return false

  case node.typeName()
  of "tuple":
    return true
  of "Option":
    return false
  else:
    discard

  case node.kind
  of nnkTupleTy, nnkTupleConstr:
    return true
  else:
    node.getTypeImpl().kind in {nnkObjectTy, nnkTupleTy}

proc handlerSignature(
    handler: NimNode
): tuple[returnType: NimNode, params: seq[HandlerParam]] =
  let impl = handler.getImpl()
  if impl.kind notin {nnkProcDef, nnkFuncDef} or impl.len < 4 or
      impl[3].kind != nnkFormalParams:
    error("expected a proc handler", handler)

  let formalParams = impl[3]
  result.returnType = formalParams[0].copyNimTree()
  for index in 1 ..< formalParams.len:
    let identDefs = formalParams[index]
    if identDefs.kind != nnkIdentDefs or identDefs.len < 3:
      continue

    let paramType = identDefs[^2]
    for nameIndex in 0 ..< identDefs.len - 2:
      var param: HandlerParam
      param.name = $identDefs[nameIndex]
      param.typeNode = paramType.copyNimTree()
      result.params.add param

proc sourceName(node: NimNode): string =
  node.typeName().normalize()

proc canUseDirectRoute(params: seq[HandlerParam], source: NimNode): bool =
  for param in params:
    if param.typeNode.isBodyType():
      return false

  let source = source.sourceName()
  if params.len == 0:
    return true
  if params.len == 1:
    return
      params[0].typeNode.isRequestType() or params[0].typeNode.isParamsType() or
      params[0].typeNode.isApiRequestType() or source == "adsbody"
  params.len == 2 and params[0].typeNode.isRequestType() and (
    params[1].typeNode.isParamsType() or params[1].typeNode.isApiRequestType() or
    source == "adsbody"
  )

proc flatParamStart(params: seq[HandlerParam]): int =
  if params.len > 0 and params[0].typeNode.isRequestType(): 1 else: 0

proc middlewareSeqExpr(middlewares: NimNode): NimNode =
  if middlewares.kind == nnkBracket:
    newTree(nnkPrefix, ident"@", middlewares.copyNimTree())
  else:
    middlewares.copyNimTree()

proc buildRouteHandler(
    api: NimNode,
    httpMethod: NimNode,
    path: NimNode,
    handler: NimNode,
    source: NimNode,
    middlewares: NimNode,
    meta: NimNode,
): NimNode =
  let signature = handler.handlerSignature()
  let handlerTarget =
    case handler.kind
    of nnkIdent, nnkSym:
      ident($handler)
    else:
      handler.copyNimTree()
  if signature.params.canUseDirectRoute(source):
    let middlewareExpr =
      if middlewares.kind == nnkBracket and middlewares.len == 0:
        newTree(nnkPrefix, ident"@", newTree(nnkBracket))
      else:
        middlewareSeqExpr(middlewares)
    return newCall(
      bindSym"route", api, httpMethod, path, handlerTarget, source, middlewareExpr, meta
    )

  let start = signature.params.flatParamStart()
  if start >= signature.params.len:
    error("flat TAPIS handlers need at least one request parameter", handler)

  let sourceKind = source.sourceName()
  var bodyIndex = -1
  for index in start ..< signature.params.len:
    if signature.params[index].typeNode.isBodyType():
      if bodyIndex >= 0:
        error("flat TAPIS handlers support only one Body[T] parameter", handler)
      bodyIndex = index

  if bodyIndex >= 0 and sourceKind != "adsbody":
    error(
      "Body[T] parameters require a body route such as post, put, or patch", handler
    )

  if sourceKind == "adsbody" and bodyIndex >= 0:
    let returnType = signature.returnType
    let requestType = bindSym"Request"
    let respondRouteValueSym = bindSym"respondRouteValue"
    let wrapperName = genSym(nskProc, "tapisWrapper")
    let requestName = genSym(nskParam, "request")
    let routeMeta = genSym(nskLet, "routeMeta")
    let routeConfig = genSym(nskLet, "routeConfig")
    let routeStatus = genSym(nskLet, "routeStatus")
    let parametersName = genSym(nskVar, "parameters")
    var parseStmts = newStmtList()
    var schemaStmts = newStmtList()
    var callArgs: seq[NimNode]
    let bodyType = signature.params[bodyIndex].typeNode.bodyInnerType()

    if start == 1:
      callArgs.add requestName

    for index in start ..< signature.params.len:
      let param = signature.params[index]
      let valueName = genSym(nskLet, param.name)

      if index == bodyIndex:
        let decodeCall = newCall(
          newTree(nnkBracketExpr, bindSym"decodeRequestBody", bodyType.copyNimTree()),
          requestName,
          routeConfig,
          bodyType.copyNimTree(),
        )
        parseStmts.add quote do:
          let `valueName` = `decodeCall`
        callArgs.add valueName
        continue

      if param.typeNode.isGroupedValueType():
        error("grouped path/query parameters must use Params[T]", param.typeNode)

      let paramName = newLit(param.name)
      let paramType = param.typeNode.copyNimTree()
      let parseCall = newCall(
        newTree(
          nnkBracketExpr, bindSym"parseRequestParamValue", paramType.copyNimTree()
        ),
        requestName,
        paramName,
      )
      let schemaCall = newCall(
        newTree(nnkBracketExpr, bindSym"addParameterSchema", paramType.copyNimTree()),
        parametersName,
        path,
        paramName,
      )
      parseStmts.add quote do:
        let `valueName` = `parseCall`
      schemaStmts.add schemaCall
      callArgs.add valueName

    let handlerCall = newCall(handlerTarget, callArgs)
    let addEndpointCall = newCall(
      newTree(
        nnkBracketExpr,
        bindSym"addEndpointWithParamsAndBody",
        bodyType.copyNimTree(),
        returnType.copyNimTree(),
      ),
      api,
      httpMethod,
      path,
      routeMeta,
      parametersName,
      bodyType.copyNimTree(),
    )
    let middlewareExpr = middlewareSeqExpr(middlewares)
    let addHandlerCall =
      if middlewares.kind == nnkBracket and middlewares.len == 0:
        quote:
          addRequestHandler(
            `api`,
            `httpMethod`,
            `path`,
            secureRequestHandler(`wrapperName`, `routeMeta`.security),
          )
      else:
        quote:
          addRequestHandler(
            `api`,
            `httpMethod`,
            `path`,
            secureRequestHandler(`wrapperName`, `routeMeta`.security),
            `middlewareExpr`,
          )
    return quote:
      block:
        let `routeMeta` = `meta`
        let `routeConfig` = `api`.config
        let `routeStatus` = `routeMeta`.responseStatus
        var `parametersName` = newParameterSchemas()
        `schemaStmts`
        `addEndpointCall`
        proc `wrapperName`(`requestName`: `requestType`) {.gcsafe.} =
          try:
            `parseStmts`
            `respondRouteValueSym`(
              `requestName`, `handlerCall`, `routeConfig`, `routeStatus`
            )
          except CatchableError as e:
            `requestName`.respondApiError(e, `routeConfig`)

        `addHandlerCall`

  if sourceKind != "adsparams":
    error("flat TAPIS handlers currently decode path/query parameters only", handler)

  let returnType = signature.returnType
  let requestType = bindSym"Request"
  let respondRouteValueSym = bindSym"respondRouteValue"
  let wrapperName = genSym(nskProc, "tapisWrapper")
  let requestName = genSym(nskParam, "request")
  let routeMeta = genSym(nskLet, "routeMeta")
  let routeConfig = genSym(nskLet, "routeConfig")
  let routeStatus = genSym(nskLet, "routeStatus")
  let parametersName = genSym(nskVar, "parameters")
  var parseStmts = newStmtList()
  var schemaStmts = newStmtList()
  var callArgs: seq[NimNode]

  if start == 1:
    callArgs.add requestName

  for index in start ..< signature.params.len:
    let param = signature.params[index]
    if param.typeNode.isGroupedValueType():
      error("grouped path/query parameters must use Params[T]", param.typeNode)

    let valueName = genSym(nskLet, param.name)
    let paramName = newLit(param.name)
    let paramType = param.typeNode.copyNimTree()
    let parseCall = newCall(
      newTree(nnkBracketExpr, bindSym"parseRequestParamValue", paramType.copyNimTree()),
      requestName,
      paramName,
    )
    let schemaCall = newCall(
      newTree(nnkBracketExpr, bindSym"addParameterSchema", paramType.copyNimTree()),
      parametersName,
      path,
      paramName,
    )
    parseStmts.add quote do:
      let `valueName` = `parseCall`
    schemaStmts.add schemaCall
    callArgs.add valueName

  let handlerCall = newCall(handlerTarget, callArgs)
  let addEndpointCall = newCall(
    newTree(nnkBracketExpr, bindSym"addEndpointWithParams", returnType.copyNimTree()),
    api,
    httpMethod,
    path,
    routeMeta,
    parametersName,
  )
  let middlewareExpr = middlewareSeqExpr(middlewares)
  let addHandlerCall =
    if middlewares.kind == nnkBracket and middlewares.len == 0:
      quote:
        addRequestHandler(
          `api`,
          `httpMethod`,
          `path`,
          secureRequestHandler(`wrapperName`, `routeMeta`.security),
        )
    else:
      quote:
        addRequestHandler(
          `api`,
          `httpMethod`,
          `path`,
          secureRequestHandler(`wrapperName`, `routeMeta`.security),
          `middlewareExpr`,
        )
  result = quote:
    block:
      let `routeMeta` = `meta`
      let `routeConfig` = `api`.config
      let `routeStatus` = `routeMeta`.responseStatus
      var `parametersName` = newParameterSchemas()
      `schemaStmts`
      `addEndpointCall`
      proc `wrapperName`(`requestName`: `requestType`) {.gcsafe.} =
        try:
          `parseStmts`
          `respondRouteValueSym`(
            `requestName`, `handlerCall`, `routeConfig`, `routeStatus`
          )
        except CatchableError as e:
          `requestName`.respondApiError(e, `routeConfig`)

      `addHandlerCall`

macro routeHandler*(
    api: typed,
    httpMethod: typed,
    path: typed,
    handler: typed,
    source: typed,
    middlewares: typed,
    meta: typed,
): untyped =
  ## Registers a typed route by analyzing the handler signature at compile time.
  ##
  ## Most applications use `api.get`, `api.post`, or `api.add` instead.
  buildRouteHandler(api, httpMethod, path, handler, source, middlewares, meta)

template defineApiMethod(name, httpMethod, source: untyped) =
  template name*(
      api: ApiRouter,
      path: string,
      handler: typed,
      summary: string = "",
      description: string = "",
      operationId: string = "",
      tags: openArray[string] = [],
      responseStatus: int = 200,
      request: ApiRequestDoc = apiRequestDoc(),
      responses: openArray[(int, ApiResponseDoc)] = [],
      middlewares: openArray[ApiMiddleware] = [],
      security: ApiSecurity = noSecurity(),
  ): untyped =
    ## Registers a typed TAPIS route for this HTTP method.
    routeHandler(
      api,
      httpMethod,
      path,
      handler,
      source,
      middlewares,
      endpointMeta(
        summary, description, operationId, tags, responseStatus, request, responses,
        security,
      ),
    )

defineApiMethod(get, "GET", adsParams)
defineApiMethod(head, "HEAD", adsParams)
defineApiMethod(delete, "DELETE", adsParams)
defineApiMethod(post, "POST", adsBody)
defineApiMethod(put, "PUT", adsBody)
defineApiMethod(patch, "PATCH", adsBody)

proc callName(node: NimNode): string =
  case node.kind
  of nnkIdent, nnkSym:
    $node
  of nnkOpenSymChoice, nnkClosedSymChoice:
    if node.len > 0:
      callName(node[0])
    else:
      ""
  else:
    ""

proc findTapiPragma(impl: NimNode): NimNode =
  if impl.kind notin {nnkProcDef, nnkFuncDef, nnkIteratorDef}:
    return nil

  let pragmas = impl[4]
  if pragmas.kind != nnkPragma:
    return nil

  for pragma in pragmas:
    if pragma.kind in {nnkCall, nnkCommand} and pragma.len > 0:
      if callName(pragma[0]) == "tapi":
        return pragma

proc tapiArg(pragma: NimNode, index: int, fallback: NimNode): NimNode =
  if pragma.len > index:
    pragma[index].copyNimTree()
  else:
    fallback

proc staticStringArg(node: NimNode): NimNode =
  case node.kind
  of nnkStrLit .. nnkTripleStrLit:
    result = newLit(node.strVal)
  else:
    result = node.copyNimTree()

proc staticIntArg(node: NimNode): NimNode =
  case node.kind
  of nnkIntLit .. nnkUInt64Lit:
    result = newLit(node.intVal())
  else:
    result = node.copyNimTree()

proc staticTagsArg(node: NimNode): NimNode =
  case node.kind
  of nnkBracket:
    result = newTree(nnkBracket)
    for child in node:
      result.add staticStringArg(child)
  of nnkHiddenSubConv, nnkHiddenStdConv:
    if node.len > 0:
      result = staticTagsArg(node[^1])
    else:
      result = newTree(nnkBracket)
  else:
    result = node.copyNimTree()

proc isDefaultRequestArg(node: NimNode): bool =
  if node.kind != nnkCall or node.len == 0 or node[0].kind notin {nnkIdent, nnkSym} or
      $node[0] != "apiRequestDoc":
    return false
  if node.len == 1:
    return true
  if node.len >= 4 and node[2].kind == nnkNilLit:
    let examples = node[3]
    if examples.kind == nnkBracket and examples.len == 0:
      return true
    if examples.kind in {nnkHiddenStdConv, nnkHiddenSubConv} and examples.len > 0 and
        examples[^1].kind == nnkBracket and examples[^1].len == 0:
      return true

proc isDefaultResponsesArg(node: NimNode): bool =
  node.kind == nnkBracket and node.len == 0

const scopedMiddlewareRouteNames =
  ["add", "get", "head", "post", "put", "delete", "options", "patch"]

proc isMiddlewaresArg(node: NimNode): bool =
  node.kind in {nnkExprEqExpr, nnkExprColonExpr} and node.len == 2 and
    node[0].callName() == "middlewares"

proc middlewaresArgIndex(call: NimNode): int =
  for index in 1 ..< call.len:
    if call[index].isMiddlewaresArg():
      return index
  -1

proc isScopedMiddlewareRouteCall(node, api: NimNode): bool =
  if node.kind notin {nnkCall, nnkCommand} or node.len == 0:
    return false

  let callee = node[0]
  if callee.kind != nnkDotExpr or callee.len != 2:
    return false

  callee[0].repr == api.repr and callee[1].callName() in scopedMiddlewareRouteNames

proc isWithMiddlewareCall(node: NimNode): bool =
  if node.kind notin {nnkCall, nnkCommand} or node.len == 0:
    return false
  node[0].callName() == "withMiddleware"

proc rewriteWithMiddleware(node, api, middleware: NimNode): NimNode =
  case node.kind
  of nnkStmtList:
    result = newStmtList()
    for child in node:
      result.add rewriteWithMiddleware(child, api, middleware)
  of nnkCall, nnkCommand:
    result = node.copyNimTree()
    if node.isScopedMiddlewareRouteCall(api):
      let index = result.middlewaresArgIndex()
      if index < 0:
        result.add newTree(
          nnkExprEqExpr,
          ident"middlewares",
          newTree(nnkBracket, middleware.copyNimTree()),
        )
      else:
        let existing = result[index][1]
        result[index][1] = newCall(
          bindSym"concatMiddlewares",
          newTree(nnkBracket, middleware.copyNimTree()),
          existing.copyNimTree(),
        )
    elif node.isWithMiddlewareCall():
      discard
    else:
      for index in 1 ..< result.len:
        result[index] = rewriteWithMiddleware(result[index], api, middleware)
  else:
    result = node.copyNimTree()
    for index in 0 ..< result.len:
      result[index] = rewriteWithMiddleware(result[index], api, middleware)

macro withMiddleware*(api: typed, middleware: typed, body: untyped): untyped =
  rewriteWithMiddleware(body, api, middleware)

macro add*(
    api: typed,
    handler: typed,
    security: typed = noSecurity(),
    request: typed = apiRequestDoc(),
    responses: typed = [],
    middlewares: typed = [],
): untyped =
  ## Registers a proc annotated with the `tapi` pragma.
  ##
  ## Route metadata is read from the pragma, while `security` may be supplied at
  ## the registration site or injected by `withSecurity`.
  let pragma = findTapiPragma(handler.getImpl())
  if pragma.isNil:
    error("api.add expects a handler annotated with {.tapi(...).}", handler)

  if pragma.len < 3:
    error("tapi pragma requires an HTTP method and path", pragma)

  let methodNameValue = callName(pragma[1]).normalize()
  case methodNameValue
  of "get", "head", "delete", "post", "put", "patch", "options":
    discard
  else:
    error("unsupported TAPIS HTTP method: " & pragma[1].repr, pragma[1])
  let methodName = ident(methodNameValue)
  let path = staticStringArg(pragma[2])
  let summary = staticStringArg(tapiArg(pragma, 3, newLit("")))
  let description = staticStringArg(tapiArg(pragma, 4, newLit("")))
  let operationId = staticStringArg(tapiArg(pragma, 5, newLit("")))
  let tags = staticTagsArg(tapiArg(pragma, 6, newTree(nnkBracket)))
  let responseStatus = staticIntArg(tapiArg(pragma, 7, newLit(200)))
  let pragmaRequest = tapiArg(pragma, 8, newCall(bindSym"apiRequestDoc"))
  let pragmaResponses = tapiArg(pragma, 9, newTree(nnkBracket))
  let requestArg =
    if request.isDefaultRequestArg():
      pragmaRequest
    else:
      request.copyNimTree()
  let responsesArg =
    if responses.isDefaultResponsesArg():
      pragmaResponses
    else:
      responses.copyNimTree()
  let handlerTarget =
    case handler.kind
    of nnkIdent, nnkSym:
      ident($handler)
    else:
      handler.copyNimTree()

  result = newCall(
    newDotExpr(api, methodName),
    path,
    handlerTarget,
    summary,
    description,
    operationId,
    tags,
    responseStatus,
    newTree(nnkExprEqExpr, ident"request", requestArg),
    newTree(nnkExprEqExpr, ident"responses", responsesArg),
    newTree(nnkExprEqExpr, ident"middlewares", middlewares.copyNimTree()),
    newTree(nnkExprEqExpr, ident"security", security),
  )

template options*(
    api: ApiRouter,
    path: string,
    handler: typed,
    summary = "",
    description = "",
    operationId = "",
    tags: openArray[string] = [],
    responseStatus = 200,
    request: ApiRequestDoc = apiRequestDoc(),
    responses: openArray[(int, ApiResponseDoc)] = [],
    middlewares: openArray[ApiMiddleware] = [],
    security: ApiSecurity = noSecurity(),
): untyped =
  ## Registers an `OPTIONS` TAPIS route.
  route(
    api,
    "OPTIONS",
    path,
    handler,
    adsNone,
    middlewares,
    endpointMeta(
      summary, description, operationId, tags, responseStatus, request, responses,
      security,
    ),
  )

proc openApiJson*(api: ApiRouter): JsonNode =
  ## Builds the OpenAPI document for all registered TAPIS routes.
  swagger.openApiJson(api.title, api.version, api.paths, api.components)

proc openApiHandler*(api: ApiRouter): RequestHandler =
  ## Returns a Mummy handler that serves this router's OpenAPI JSON document.
  return proc(request: Request) {.gcsafe.} =
    var headers: HttpHeaders
    headers["Content-Type"] = jsonContentType
    headers.applyMiddlewareResponseHeaders()
    let body = $api.openApiJson()
    var responseBody = body
    if currentRouteContext().isSome():
      currentRouteContext().get().responseStatus = 200
    compressResponse(request, 200, headers, responseBody)
    trace "tapis openapi response",
      httpMethod = request.httpMethod,
      path = request.path,
      uri = request.uri,
      statusCode = 200,
      contentType = headers["Content-Type"],
      contentEncoding = headers["Content-Encoding"],
      bodyLength = responseBody.len
    if request.httpMethod == "HEAD":
      headers["Content-Length"] = $responseBody.len
      request.respond(200, headers)
    else:
      request.respond(200, headers, responseBody)

proc mountOpenApi*(api: ApiRouter, path = "/swagger.json") =
  ## Mounts the OpenAPI JSON handler at `path`.
  api.addRequestHandler("GET", path, api.openApiHandler())

proc toHandler*(api: ApiRouter): RequestHandler =
  ## Converts the wrapped Mummy router to a Mummy request handler.
  api.router.toHandler()

proc toMummyHandler*(api: ApiRouter): RequestHandler =
  ## Converts the wrapped TAPIS API router to a plain Mummy request handler.
  api.toHandler()

converter toMummyRouter*(api: ApiRouter): Router =
  ## Allows an `ApiRouter` to be passed where a Mummy `Router` is expected.
  api.router
