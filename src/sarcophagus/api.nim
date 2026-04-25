import std/[json, options]

import mummy
import mummy/routers

import ./core/[swagger, typed_api]

export swagger, typed_api

type ApiRouter* = ref object
  router*: Router
  config*: ApiConfig
  title*: string
  version*: string
  paths: JsonNode

proc initApiRouter*(
    title = "API", version = "0.1.0", config = defaultApiConfig()
): ApiRouter =
  ApiRouter(config: config, title: title, version: version, paths: newJObject())

proc apiResponse*[T](
    body: sink T, statusCode = 200, headers: sink HttpHeaders
): ApiResponse[T] =
  var apiHeaders: ApiHeaders
  for header in headers:
    apiHeaders.add((header[0], header[1]))
  typed_api.apiResponse(body, statusCode, apiHeaders)

proc toHttpHeaders(headers: ApiHeaders): HttpHeaders =
  for header in headers:
    result[header.name] = header.value

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

proc respondRouteValue[T](
    request: Request, value: T, config: ApiConfig, responseStatus: int
) =
  request.respondApi(value, config, responseStatus)

proc respondRouteValue[T](
    request: Request, value: ApiResponse[T], config: ApiConfig, responseStatus: int
) =
  request.respondApi(value, config)

proc requestParam(request: Request, name: string): Option[string] =
  if name in request.pathParams:
    return some(request.pathParams[name])
  if name in request.queryParams:
    return some(request.queryParams[name])
  none(string)

proc parseRequestParams*[T](request: Request, target: typedesc[T]): T =
  when T is EmptyInput or T is EmptyParams or T is EmptyBody:
    discard
  elif T is object:
    for name, value in result.fieldPairs:
      let raw = request.requestParam(name)
      if raw.isSome():
        value = parseApiParam(raw.get(), name, typeof(value))
      else:
        value = missingApiParam(name, typeof(value))
  else:
    {.error: "API parameter input must be an object type".}

proc decodeRequestBody*[T](
    request: Request, config: ApiConfig, target: typedesc[T]
): T =
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
  swagger.addEndpoint(api.paths, httpMethod, path, source, meta, In, Out)

proc respondApiError*(request: Request, e: ref Exception, config: ApiConfig) =
  let statusCode = apiErrorStatus(e)
  let body = apiErrorBody(e, config)
  let format =
    try:
      responseFormat(request, config)
    except CatchableError:
      apiJson
  request.respondEncoded(statusCode, format, encodeApi(body, format))

proc toApiHandler*[Out](
    handler: proc(): Out {.gcsafe.}, config: ApiConfig, responseStatus: int
): RequestHandler =
  return proc(request: Request) {.gcsafe.} =
    try:
      request.respondRouteValue(handler(), config, responseStatus)
    except CatchableError as e:
      request.respondApiError(e, config)

proc toApiHandler*[Out](
    handler: proc(request: Request): Out {.gcsafe.},
    config: ApiConfig,
    responseStatus: int,
): RequestHandler =
  return proc(request: Request) {.gcsafe.} =
    try:
      request.respondRouteValue(handler(request), config, responseStatus)
    except CatchableError as e:
      request.respondApiError(e, config)

proc toApiHandler*[In, Out](
    handler: proc(input: In): Out {.gcsafe.},
    config: ApiConfig,
    source: ApiDecodeSource,
    responseStatus: int,
): RequestHandler =
  return proc(request: Request) {.gcsafe.} =
    try:
      let input = decodeInput(request, config, source, In)
      request.respondRouteValue(handler(input), config, responseStatus)
    except CatchableError as e:
      request.respondApiError(e, config)

proc toApiHandler*[In, Out](
    handler: proc(request: Request, input: In): Out {.gcsafe.},
    config: ApiConfig,
    source: ApiDecodeSource,
    responseStatus: int,
): RequestHandler =
  return proc(request: Request) {.gcsafe.} =
    try:
      let input = decodeInput(request, config, source, In)
      request.respondRouteValue(handler(request, input), config, responseStatus)
    except CatchableError as e:
      request.respondApiError(e, config)

proc route*[Out](
    api: ApiRouter,
    httpMethod, path: string,
    handler: proc(): Out {.gcsafe.},
    source: ApiDecodeSource = adsNone,
    meta: EndpointMeta = endpointMeta(),
) =
  api.addEndpoint(httpMethod, path, source, meta, EmptyInput, Out)
  api.router.addRoute(
    httpMethod, path, toApiHandler(handler, api.config, meta.responseStatus)
  )

proc route*[Out](
    api: ApiRouter,
    httpMethod, path: string,
    handler: proc(request: Request): Out {.gcsafe.},
    source: ApiDecodeSource = adsNone,
    meta: EndpointMeta = endpointMeta(),
) =
  api.addEndpoint(httpMethod, path, source, meta, EmptyInput, Out)
  api.router.addRoute(
    httpMethod, path, toApiHandler(handler, api.config, meta.responseStatus)
  )

proc route*[In, Out](
    api: ApiRouter,
    httpMethod, path: string,
    handler: proc(input: In): Out {.gcsafe.},
    source: ApiDecodeSource,
    meta: EndpointMeta = endpointMeta(),
) =
  api.addEndpoint(httpMethod, path, source, meta, In, Out)
  api.router.addRoute(
    httpMethod, path, toApiHandler(handler, api.config, source, meta.responseStatus)
  )

proc route*[In, Out](
    api: ApiRouter,
    httpMethod, path: string,
    handler: proc(request: Request, input: In): Out {.gcsafe.},
    source: ApiDecodeSource,
    meta: EndpointMeta = endpointMeta(),
) =
  api.addEndpoint(httpMethod, path, source, meta, In, Out)
  api.router.addRoute(
    httpMethod, path, toApiHandler(handler, api.config, source, meta.responseStatus)
  )

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
  ): untyped =
    route(
      api,
      httpMethod,
      path,
      handler,
      source,
      endpointMeta(summary, description, operationId, tags, responseStatus),
    )

defineApiMethod(get, "GET", adsParams)
defineApiMethod(head, "HEAD", adsParams)
defineApiMethod(delete, "DELETE", adsParams)
defineApiMethod(post, "POST", adsBody)
defineApiMethod(put, "PUT", adsBody)
defineApiMethod(patch, "PATCH", adsBody)

template options*(
    api: ApiRouter,
    path: string,
    handler: typed,
    summary = "",
    description = "",
    operationId = "",
    tags: openArray[string] = [],
    responseStatus = 200,
): untyped =
  route(
    api,
    "OPTIONS",
    path,
    handler,
    adsNone,
    endpointMeta(summary, description, operationId, tags, responseStatus),
  )

proc openApiJson*(api: ApiRouter): JsonNode =
  swagger.openApiJson(api.title, api.version, api.paths)

proc openApiHandler*(api: ApiRouter): RequestHandler =
  return proc(request: Request) {.gcsafe.} =
    var headers: HttpHeaders
    headers["Content-Type"] = jsonContentType
    let body = $api.openApiJson()
    if request.httpMethod == "HEAD":
      headers["Content-Length"] = $body.len
      request.respond(200, headers)
    else:
      request.respond(200, headers, body)

proc mountOpenApi*(api: ApiRouter, path = "/swagger.json") =
  api.router.get(path, api.openApiHandler())

proc toHandler*(api: ApiRouter): RequestHandler =
  api.router.toHandler()

converter toMummyRouter*(api: ApiRouter): Router =
  api.router
