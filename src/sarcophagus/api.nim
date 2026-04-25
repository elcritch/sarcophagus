import std/[json, options, strutils]

import mummy
import mummy/routers

when defined(feature.sarcophagus.jsony):
  import jsony
  export jsony
else:
  import std/jsonutils

when defined(feature.sarcophagus.cbor):
  import cborious
  import cborious/cbor2json
  export cborious

type
  ApiFormat* = enum
    apiJson
    apiCbor

  ApiDecodeSource* = enum
    adsNone
    adsParams
    adsBody

  EmptyInput* = object
  EmptyParams* = object
  EmptyBody* = object

  ApiRequest*[Params, Body] = object
    params*: Params
    body*: Body

  ApiResponse*[T] = object
    statusCode*: int
    headers*: HttpHeaders
    body*: T

  ApiError* = object of CatchableError
    statusCode*: int
    code*: string
    details*: JsonNode

  ApiConfig* = object
    includeStackTraces*: bool
    defaultResponseFormat*: ApiFormat
    requestFormats*: set[ApiFormat]
    responseFormats*: set[ApiFormat]

  EndpointMeta* = object
    summary*: string
    description*: string
    operationId*: string
    tags*: seq[string]
    responseStatus*: int

  ApiRouter* = ref object
    router*: Router
    config*: ApiConfig
    title*: string
    version*: string
    paths: JsonNode

const
  jsonContentType = "application/json; charset=utf-8"
  cborContentType = "application/cbor"

when defined(feature.sarcophagus.cbor):
  const apiCborEncodingMode = {CborObjToMap, CborEnumAsString, CborCheckHoleyEnums}

proc defaultApiConfig*(): ApiConfig =
  result.includeStackTraces = false
  result.defaultResponseFormat = apiJson
  result.requestFormats = {apiJson}
  result.responseFormats = {apiJson}
  when defined(feature.sarcophagus.cbor):
    result.requestFormats.incl apiCbor
    result.responseFormats.incl apiCbor

proc endpointMeta*(
    summary = "",
    description = "",
    operationId = "",
    tags: openArray[string] = [],
    responseStatus = 200,
): EndpointMeta =
  EndpointMeta(
    summary: summary,
    description: description,
    operationId: operationId,
    tags: @tags,
    responseStatus: responseStatus,
  )

proc initApiRouter*(
    title = "API", version = "0.1.0", config = defaultApiConfig()
): ApiRouter =
  ApiRouter(config: config, title: title, version: version, paths: newJObject())

proc apiResponse*[T](
    body: sink T, statusCode = 200, headers: sink HttpHeaders = emptyHttpHeaders()
): ApiResponse[T] =
  ApiResponse[T](statusCode: statusCode, headers: headers, body: body)

proc newApiError*(
    statusCode: int, message: string, code = "api_error", details: JsonNode = nil
): ref ApiError =
  result = newException(ApiError, message)
  result.statusCode = statusCode
  result.code = code
  result.details = details

proc raiseApiError*(
    statusCode: int, message: string, code = "api_error", details: JsonNode = nil
) {.noreturn.} =
  raise newApiError(statusCode, message, code, details)

proc mediaType(raw: string): string =
  let semi = raw.find(';')
  let value =
    if semi >= 0:
      raw[0 ..< semi]
    else:
      raw
  value.strip().toLowerAscii()

proc mediaMatches(raw, exact, suffix: string): bool =
  let value = mediaType(raw)
  value == exact or value.endsWith(suffix)

proc formatContentType(format: ApiFormat): string =
  case format
  of apiJson: jsonContentType
  of apiCbor: cborContentType

proc requestFormat(request: Request, config: ApiConfig): ApiFormat =
  let contentType = request.headers["Content-Type"]
  if contentType.len == 0:
    return apiJson
  if mediaMatches(contentType, "application/json", "+json"):
    if apiJson in config.requestFormats:
      return apiJson
  elif mediaMatches(contentType, "application/cbor", "+cbor"):
    when defined(feature.sarcophagus.cbor):
      if apiCbor in config.requestFormats:
        return apiCbor
    else:
      discard

  raiseApiError(
    415, "Unsupported request content type: " & contentType, "unsupported_content_type"
  )

proc acceptTokenFormat(token: string, config: ApiConfig): Option[ApiFormat] =
  let value = token.mediaType()
  if value.len == 0 or value == "*/*":
    return some(config.defaultResponseFormat)
  if mediaMatches(value, "application/json", "+json") and
      apiJson in config.responseFormats:
    return some(apiJson)
  if mediaMatches(value, "application/cbor", "+cbor"):
    when defined(feature.sarcophagus.cbor):
      if apiCbor in config.responseFormats:
        return some(apiCbor)
    else:
      discard
  none(ApiFormat)

proc responseFormat(request: Request, config: ApiConfig): ApiFormat =
  let accept = request.headers["Accept"]
  if accept.len == 0:
    return config.defaultResponseFormat

  for token in accept.split(','):
    let format = acceptTokenFormat(token, config)
    if format.isSome():
      return format.get()

  raiseApiError(406, "No acceptable response content type", "not_acceptable")

proc encodeJsonApi[T](value: T): string =
  when T is JsonNode:
    $value
  elif defined(feature.sarcophagus.jsony):
    jsony.toJson(value)
  else:
    $jsonutils.toJson(value, ToJsonOptions(enumMode: joptEnumString))

proc decodeJsonApi[T](body: string, target: typedesc[T]): T =
  when T is JsonNode:
    parseJson(body)
  elif defined(feature.sarcophagus.jsony):
    body.fromJson(T)
  else:
    parseJson(body).to(T)

when defined(feature.sarcophagus.cbor):
  proc encodeCborApi[T](value: T): string =
    when T is JsonNode:
      cbor2json.fromJsonNode(value)
    else:
      toCbor(value, apiCborEncodingMode)

  proc decodeCborApi[T](body: string, target: typedesc[T]): T =
    when T is JsonNode:
      cbor2json.toJsonNode(body)
    else:
      fromCbor(body, T, apiCborEncodingMode)

proc encodeApi[T](value: T, format: ApiFormat): string =
  case format
  of apiJson:
    encodeJsonApi(value)
  of apiCbor:
    when defined(feature.sarcophagus.cbor):
      encodeCborApi(value)
    else:
      raiseApiError(406, "CBOR responses are not enabled", "cbor_not_enabled")

proc decodeApi[T](body: string, format: ApiFormat, target: typedesc[T]): T =
  case format
  of apiJson:
    decodeJsonApi(body, T)
  of apiCbor:
    when defined(feature.sarcophagus.cbor):
      decodeCborApi(body, T)
    else:
      raiseApiError(415, "CBOR requests are not enabled", "cbor_not_enabled")

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
    value.statusCode, format, encodeApi(value.body, format), value.headers
  )

proc respondRouteValue[T](
    request: Request, value: T, config: ApiConfig, responseStatus: int
) =
  request.respondApi(value, config, responseStatus)

proc respondRouteValue[T](
    request: Request, value: ApiResponse[T], config: ApiConfig, responseStatus: int
) =
  request.respondApi(value, config)

proc parseBoolParam(raw, name: string): bool =
  case raw.strip().toLowerAscii()
  of "1", "true", "yes", "on":
    true
  of "0", "false", "no", "off":
    false
  else:
    raiseApiError(400, "Invalid boolean value for '" & name & "'", "invalid_param")

proc parseApiParam*[T](raw, name: string, target: typedesc[T]): T =
  try:
    when T is string:
      raw
    elif T is bool:
      parseBoolParam(raw, name)
    elif T is SomeSignedInt:
      let parsed = parseBiggestInt(raw)
      if parsed < BiggestInt(low(T)) or parsed > BiggestInt(high(T)):
        raise newException(ValueError, "integer out of range")
      T(parsed)
    elif T is SomeUnsignedInt:
      let parsed = parseBiggestUInt(raw)
      if parsed > BiggestUInt(high(T)):
        raise newException(ValueError, "unsigned integer out of range")
      T(parsed)
    elif T is SomeFloat:
      T(parseFloat(raw))
    elif T is enum:
      parseEnum[T](raw)
    else:
      decodeJsonApi(raw, T)
  except CatchableError as e:
    raiseApiError(400, "Invalid value for '" & name & "': " & e.msg, "invalid_param")

proc parseApiParam*[T](raw, name: string, target: typedesc[Option[T]]): Option[T] =
  some(parseApiParam(raw, name, T))

proc missingApiParam*[T](name: string, target: typedesc[T]): T =
  raiseApiError(400, "Missing required parameter '" & name & "'", "missing_param")

proc missingApiParam*[T](name: string, target: typedesc[Option[T]]): Option[T] =
  none(T)

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

template apiRequiredField(T: typedesc): bool =
  when T is Option: false else: true

proc openApiSchema*[T](target: typedesc[T]): JsonNode

proc openApiSchema*[T](target: typedesc[Option[T]]): JsonNode =
  result = openApiSchema(T)
  result["nullable"] = newJBool(true)

proc openApiSchema*[Params, Body](
    target: typedesc[ApiRequest[Params, Body]]
): JsonNode =
  result = newJObject()
  result["type"] = %"object"
  result["properties"] =
    %*{"params": openApiSchema(Params), "body": openApiSchema(Body)}
  result["required"] = %*["params", "body"]

proc openApiSchema*[T](target: typedesc[T]): JsonNode =
  when T is EmptyInput or T is EmptyParams or T is EmptyBody:
    result = %*{"type": "object", "properties": {}}
  elif T is JsonNode:
    result = newJObject()
  elif T is string or T is char:
    result = %*{"type": "string"}
  elif T is bool:
    result = %*{"type": "boolean"}
  elif T is SomeSignedInt or T is SomeUnsignedInt:
    result = %*{"type": "integer"}
    when sizeof(T) <= 4:
      result["format"] = %"int32"
    else:
      result["format"] = %"int64"
  elif T is SomeFloat:
    result = %*{"type": "number"}
    when sizeof(T) <= 4:
      result["format"] = %"float"
    else:
      result["format"] = %"double"
  elif T is enum:
    result = %*{"type": "string"}
    var values = newJArray()
    for value in T:
      values.add(%($value))
    result["enum"] = values
  elif T is seq:
    result = %*{"type": "array", "items": openApiSchema(typeof(default(T)[0]))}
  elif T is array:
    result = %*{"type": "array", "items": openApiSchema(typeof(default(T)[0]))}
  elif T is object or T is tuple:
    var properties = newJObject()
    var required = newJArray()
    for name, value in default(T).fieldPairs:
      properties[name] = openApiSchema(typeof(value))
      when apiRequiredField(typeof(value)):
        required.add(%name)
    result = newJObject()
    result["type"] = %"object"
    result["properties"] = properties
    if required.len > 0:
      result["required"] = required
  else:
    result = newJObject()

proc responseOpenApiSchema*[T](target: typedesc[T]): JsonNode =
  openApiSchema(T)

proc responseOpenApiSchema*[T](target: typedesc[ApiResponse[T]]): JsonNode =
  openApiSchema(T)

proc pathHasParam(path, name: string): bool =
  let needle = "@" & name
  for part in path.split('/'):
    if part == needle or part == "{" & name & "}":
      return true
  false

proc openApiPath(path: string): string =
  let parts = path.split('/')
  for index in 0 ..< parts.len:
    let part = parts[index]
    if index > 0:
      result.add '/'
    if part.len > 1 and part[0] == '@':
      result.add '{'
      result.add part[1 .. ^1]
      result.add '}'
    else:
      result.add part

proc defaultOperationId(httpMethod, path: string): string =
  result = httpMethod.toLowerAscii()
  for part in path.split('/'):
    if part.len == 0:
      continue
    result.add '_'
    if part[0] == '@':
      result.add part[1 .. ^1]
    else:
      for ch in part:
        if ch.isAlphaNumeric():
          result.add ch
        else:
          result.add '_'

proc parameterSchemas*[T](path: string, target: typedesc[T]): JsonNode =
  result = newJArray()
  when T is EmptyInput or T is EmptyParams or T is EmptyBody:
    discard
  elif T is object or T is tuple:
    for name, value in default(T).fieldPairs:
      let isPathParam = path.pathHasParam(name)
      let location = if isPathParam: "path" else: "query"
      var param =
        %*{"name": name, "in": location, "schema": openApiSchema(typeof(value))}
      when apiRequiredField(typeof(value)):
        param["required"] = newJBool(true)
      else:
        param["required"] = newJBool(isPathParam)
      result.add param
  else:
    discard

proc parameterSchemas*[Params, Body](
    path: string, target: typedesc[ApiRequest[Params, Body]]
): JsonNode =
  parameterSchemas(path, Params)

proc requestBodySchema*[T](target: typedesc[T]): JsonNode =
  openApiSchema(T)

proc requestBodySchema*[Params, Body](
    target: typedesc[ApiRequest[Params, Body]]
): JsonNode =
  openApiSchema(Body)

proc hasRequestBody*[T](source: ApiDecodeSource, target: typedesc[T]): bool =
  when T is EmptyInput or T is EmptyBody or T is EmptyParams:
    false
  else:
    source == adsBody

proc hasRequestBody*[Params, Body](
    source: ApiDecodeSource, target: typedesc[ApiRequest[Params, Body]]
): bool =
  when Body is EmptyInput or Body is EmptyBody or Body is EmptyParams: false else: true

proc contentSchema(schema: JsonNode): JsonNode =
  result = newJObject()
  result["application/json"] = %*{"schema": schema}
  when defined(feature.sarcophagus.cbor):
    result["application/cbor"] = %*{"schema": schema}

proc addEndpoint*[In, Out](
    api: ApiRouter,
    httpMethod, path: string,
    source: ApiDecodeSource,
    meta: EndpointMeta,
    input: typedesc[In],
    output: typedesc[Out],
) =
  let apiPath = openApiPath(path)
  if apiPath notin api.paths:
    api.paths[apiPath] = newJObject()

  var operation = newJObject()
  operation["operationId"] =
    %(
      if meta.operationId.len > 0: meta.operationId
      else: defaultOperationId(httpMethod, path)
    )
  if meta.summary.len > 0:
    operation["summary"] = %meta.summary
  if meta.description.len > 0:
    operation["description"] = %meta.description
  if meta.tags.len > 0:
    operation["tags"] = %meta.tags

  let params = parameterSchemas(path, In)
  if params.len > 0:
    operation["parameters"] = params

  if hasRequestBody(source, In):
    operation["requestBody"] =
      %*{"required": true, "content": contentSchema(requestBodySchema(In))}

  operation["responses"] =
    %*{
      $meta.responseStatus: {
        "description": "Successful response",
        "content": contentSchema(responseOpenApiSchema(Out)),
      },
      "400": {"description": "Invalid request"},
      "500": {"description": "Internal server error"},
    }

  api.paths[apiPath][httpMethod.toLowerAscii()] = operation

proc apiErrorStatus(e: ref Exception): int =
  if e of ApiError:
    cast[ref ApiError](e).statusCode
  elif e of ValueError:
    400
  else:
    500

proc apiErrorCode(e: ref Exception): string =
  if e of ApiError:
    cast[ref ApiError](e).code
  elif e of ValueError:
    "invalid_request"
  else:
    "internal_error"

proc apiErrorDetails(e: ref Exception): JsonNode =
  if e of ApiError:
    cast[ref ApiError](e).details
  else:
    nil

proc apiErrorBody(e: ref Exception, config: ApiConfig): JsonNode =
  var err = %*{"code": apiErrorCode(e), "message": e.msg, "type": $e.name}
  let details = apiErrorDetails(e)
  if details != nil:
    err["details"] = details
  if config.includeStackTraces:
    err["stackTrace"] = %e.getStackTrace()
  %*{"status": "error", "error": err}

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
  %*{
    "openapi": "3.1.0",
    "info": {"title": api.title, "version": api.version},
    "paths": api.paths,
  }

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
