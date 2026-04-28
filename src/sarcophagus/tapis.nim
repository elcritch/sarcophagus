import std/[json, macros, options, strutils]

import mummy
import mummy/routers

import ./core/[swagger, typed_api]
from ./oauth2/core import
  OAuth2AuthorizationCodeConsumer, OAuth2AuthorizationCodeSaver, OAuth2Config
from ./oauth2/common import OAuth2CurrentUserLoader
from ./oauth2/mummy_support import oauth2AuthorizeHandler, oauth2TokenHandler
import ./tapis_utils
import ./tapis_security

export swagger, typed_api, tapis_security, tapis_utils

type ApiRouter* = ref object
  ## Typed API router wrapper around a Mummy `Router`.
  ##
  ## The wrapper stores OpenAPI metadata and serialization configuration beside
  ## the underlying Mummy router.
  router*: Router ## Underlying Mummy router.
  config*: ApiConfig ## Request/response codec and error-response configuration.
  title*: string ## OpenAPI document title.
  version*: string ## OpenAPI document version.
  paths: JsonNode
  components: JsonNode

template tapi*(
  httpMethod: untyped,
  path: static string,
  summary: static string = "",
  description: static string = "",
  operationId: static string = "",
  tags: static openArray[string] = [],
  responseStatus: static int = 200,
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
    paths: newJObject(),
    components: newJObject(),
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

proc respondRaw[contentType: static string](
    request: Request, value: RawResponse[contentType]
) =
  var headers = value.headers.toHttpHeaders()
  headers["Content-Type"] = contentType
  if request.httpMethod == "HEAD":
    headers["Content-Length"] = $value.body.len
    request.respond(value.statusCode, headers)
  else:
    request.respond(value.statusCode, headers, value.body)

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
    api: ApiRouter, httpMethod, path: string, handler: RequestHandler
) =
  ## Registers a raw Mummy request handler on the wrapped router.
  api.router.addRoute(httpMethod, path, handler)

proc registerOAuth2*(api: ApiRouter, config: OAuth2Config, tokenPath = "/oauth/token") =
  ## Mounts the OAuth2 token endpoint on this typed API router.
  api.addRequestHandler("POST", tokenPath, oauth2TokenHandler(config))

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
    meta: EndpointMeta = endpointMeta(),
) =
  ## Registers a typed route with no decoded input.
  api.addEndpoint(httpMethod, path, source, meta, EmptyInput, Out)
  api.router.addRoute(
    httpMethod,
    path,
    secureRequestHandler(
      toApiHandler(handler, api.config, meta.responseStatus), meta.security
    ),
  )

proc route*[Out](
    api: ApiRouter,
    httpMethod, path: string,
    handler: proc(request: Request): Out {.gcsafe.},
    source: ApiDecodeSource = adsNone,
    meta: EndpointMeta = endpointMeta(),
) =
  ## Registers a request-aware typed route with no decoded input.
  api.addEndpoint(httpMethod, path, source, meta, EmptyInput, Out)
  api.router.addRoute(
    httpMethod,
    path,
    secureRequestHandler(
      toApiHandler(handler, api.config, meta.responseStatus), meta.security
    ),
  )

proc route*[In, Out](
    api: ApiRouter,
    httpMethod, path: string,
    handler: proc(input: In): Out {.gcsafe.},
    source: ApiDecodeSource,
    meta: EndpointMeta = endpointMeta(),
) =
  ## Registers a typed route with decoded parameters or body input.
  api.addEndpoint(httpMethod, path, source, meta, In, Out)
  api.router.addRoute(
    httpMethod,
    path,
    secureRequestHandler(
      toApiHandler(handler, api.config, source, meta.responseStatus), meta.security
    ),
  )

proc route*[In, Out](
    api: ApiRouter,
    httpMethod, path: string,
    handler: proc(request: Request, input: In): Out {.gcsafe.},
    source: ApiDecodeSource,
    meta: EndpointMeta = endpointMeta(),
) =
  ## Registers a request-aware typed route with decoded input.
  api.addEndpoint(httpMethod, path, source, meta, In, Out)
  api.router.addRoute(
    httpMethod,
    path,
    secureRequestHandler(
      toApiHandler(handler, api.config, source, meta.responseStatus), meta.security
    ),
  )

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

proc buildRouteHandler(
    api: NimNode,
    httpMethod: NimNode,
    path: NimNode,
    handler: NimNode,
    source: NimNode,
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
    return newCall(bindSym"route", api, httpMethod, path, handlerTarget, source, meta)

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

        addRequestHandler(
          `api`,
          `httpMethod`,
          `path`,
          secureRequestHandler(`wrapperName`, `routeMeta`.security),
        )

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

      addRequestHandler(
        `api`,
        `httpMethod`,
        `path`,
        secureRequestHandler(`wrapperName`, `routeMeta`.security),
      )

macro routeHandler*(
    api: typed,
    httpMethod: typed,
    path: typed,
    handler: typed,
    source: typed,
    meta: typed,
): untyped =
  ## Registers a typed route by analyzing the handler signature at compile time.
  ##
  ## Most applications use `api.get`, `api.post`, or `api.add` instead.
  buildRouteHandler(api, httpMethod, path, handler, source, meta)

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
      responses: openArray[(int, ApiResponseDoc)] = [],
      security: ApiSecurity = noSecurity(),
  ): untyped =
    ## Registers a typed TAPIS route for this HTTP method.
    routeHandler(
      api,
      httpMethod,
      path,
      handler,
      source,
      endpointMeta(
        summary, description, operationId, tags, responseStatus, responses, security
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

macro add*(
    api: typed, handler: typed, responses: typed = [], security: typed = noSecurity()
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
    responses,
    security,
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
    responses: openArray[(int, ApiResponseDoc)] = [],
    security: ApiSecurity = noSecurity(),
): untyped =
  ## Registers an `OPTIONS` TAPIS route.
  route(
    api,
    "OPTIONS",
    path,
    handler,
    adsNone,
    endpointMeta(
      summary, description, operationId, tags, responseStatus, responses, security
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
    let body = $api.openApiJson()
    if request.httpMethod == "HEAD":
      headers["Content-Length"] = $body.len
      request.respond(200, headers)
    else:
      request.respond(200, headers, body)

proc mountOpenApi*(api: ApiRouter, path = "/swagger.json") =
  ## Mounts the OpenAPI JSON handler at `path`.
  api.router.get(path, api.openApiHandler())

proc toHandler*(api: ApiRouter): RequestHandler =
  ## Converts the wrapped Mummy router to a Mummy request handler.
  api.router.toHandler()

proc toMummyHandler*(api: ApiRouter): RequestHandler =
  ## Converts the wrapped TAPIS API router to a plain Mummy request handler.
  api.toHandler()

converter toMummyRouter*(api: ApiRouter): Router =
  ## Allows an `ApiRouter` to be passed where a Mummy `Router` is expected.
  api.router
