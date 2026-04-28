import std/[json, options, strutils]

import ./tapis_security
import ./typed_api

type EndpointMeta* = object
  summary*: string
  description*: string
  operationId*: string
  tags*: seq[string]
  responseStatus*: int
  security*: ApiSecurity

proc endpointMeta*(
    summary = "",
    description = "",
    operationId = "",
    tags: openArray[string] = [],
    responseStatus = 200,
    security = noSecurity(),
): EndpointMeta =
  EndpointMeta(
    summary: summary,
    description: description,
    operationId: operationId,
    tags: @tags,
    responseStatus: responseStatus,
    security: security,
  )

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

proc responseOpenApiSchema*[contentType: static string](
    target: typedesc[RawResponse[contentType]]
): JsonNode =
  %*{"type": "string"}

proc pathHasParam*(path, name: string): bool =
  let needle = "@" & name
  for part in path.split('/'):
    if part == needle or part == "{" & name & "}":
      return true
  false

proc tupleFieldIndex(name: string): string =
  if not name.startsWith("Field") or name.len <= "Field".len:
    return ""

  result = name["Field".len .. ^1]
  for ch in result:
    if ch notin {'0' .. '9'}:
      return ""

proc apiParamName*(name: string): string =
  let index = tupleFieldIndex(name)
  if index.len > 0:
    return index
  name

proc openApiPath*(path: string): string =
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

proc defaultOperationId*(httpMethod, path: string): string =
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
      let paramName = apiParamName(name)
      let isPathParam = path.pathHasParam(name) or path.pathHasParam(paramName)
      let location = if isPathParam: "path" else: "query"
      var param =
        %*{"name": paramName, "in": location, "schema": openApiSchema(typeof(value))}
      when apiRequiredField(typeof(value)):
        param["required"] = newJBool(true)
      else:
        param["required"] = newJBool(isPathParam)
      result.add param
  else:
    discard

proc parameterSchema*[T](path, name: string, target: typedesc[T]): JsonNode =
  let isPathParam = path.pathHasParam(name)
  let location = if isPathParam: "path" else: "query"
  result = %*{"name": name, "in": location, "schema": openApiSchema(T)}
  when apiRequiredField(T):
    result["required"] = newJBool(true)
  else:
    result["required"] = newJBool(isPathParam)

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

proc contentSchema*(schema: JsonNode): JsonNode =
  result = newJObject()
  result["application/json"] = %*{"schema": schema}
  when defined(feature.sarcophagus.cbor):
    result["application/cbor"] = %*{"schema": schema}
  when defined(feature.sarcophagus.msgpack) or defined(feature.sarcophagus.msgpack4nim):
    result["application/msgpack"] = %*{"schema": schema}

proc responseContentSchema*[T](target: typedesc[T]): JsonNode =
  contentSchema(responseOpenApiSchema(T))

proc responseContentSchema*[contentType: static string](
    target: typedesc[RawResponse[contentType]]
): JsonNode =
  result = newJObject()
  result[contentType] = %*{"schema": responseOpenApiSchema(RawResponse[contentType])}

proc endpointOperation*[In, Out](
    httpMethod, path: string,
    source: ApiDecodeSource,
    meta: EndpointMeta,
    input: typedesc[In],
    output: typedesc[Out],
): JsonNode =
  result = newJObject()
  result["operationId"] =
    %(
      if meta.operationId.len > 0: meta.operationId
      else: defaultOperationId(httpMethod, path)
    )
  if meta.summary.len > 0:
    result["summary"] = %meta.summary
  if meta.description.len > 0:
    result["description"] = %meta.description
  if meta.tags.len > 0:
    result["tags"] = %meta.tags
  let security = openApiSecurityRequirement(meta.security)
  if security.len > 0:
    result["security"] = security

  let params = parameterSchemas(path, In)
  if params.len > 0:
    result["parameters"] = params

  if hasRequestBody(source, In):
    result["requestBody"] =
      %*{"required": true, "content": contentSchema(requestBodySchema(In))}

  result["responses"] =
    %*{
      $meta.responseStatus:
        {"description": "Successful response", "content": responseContentSchema(Out)},
      "400": {"description": "Invalid request"},
      "500": {"description": "Internal server error"},
    }

proc endpointOperationWithParams*[Out](
    httpMethod, path: string,
    meta: EndpointMeta,
    parameters: JsonNode,
    output: typedesc[Out],
): JsonNode =
  result = newJObject()
  result["operationId"] =
    %(
      if meta.operationId.len > 0: meta.operationId
      else: defaultOperationId(httpMethod, path)
    )
  if meta.summary.len > 0:
    result["summary"] = %meta.summary
  if meta.description.len > 0:
    result["description"] = %meta.description
  if meta.tags.len > 0:
    result["tags"] = %meta.tags
  let security = openApiSecurityRequirement(meta.security)
  if security.len > 0:
    result["security"] = security
  if parameters.len > 0:
    result["parameters"] = parameters
  result["responses"] =
    %*{
      $meta.responseStatus:
        {"description": "Successful response", "content": responseContentSchema(Out)},
      "400": {"description": "Invalid request"},
      "500": {"description": "Internal server error"},
    }

proc endpointOperationWithParamsAndBody*[Body, Out](
    httpMethod, path: string,
    meta: EndpointMeta,
    parameters: JsonNode,
    body: typedesc[Body],
    output: typedesc[Out],
): JsonNode =
  result = endpointOperationWithParams(httpMethod, path, meta, parameters, Out)
  result["requestBody"] =
    %*{"required": true, "content": contentSchema(requestBodySchema(Body))}

proc addEndpoint*[In, Out](
    paths: JsonNode,
    httpMethod, path: string,
    source: ApiDecodeSource,
    meta: EndpointMeta,
    input: typedesc[In],
    output: typedesc[Out],
) =
  let apiPath = openApiPath(path)
  if apiPath notin paths:
    paths[apiPath] = newJObject()
  paths[apiPath][httpMethod.toLowerAscii()] =
    endpointOperation(httpMethod, path, source, meta, In, Out)

proc addEndpointWithParams*[Out](
    paths: JsonNode,
    httpMethod, path: string,
    meta: EndpointMeta,
    parameters: JsonNode,
    output: typedesc[Out],
) =
  let apiPath = openApiPath(path)
  if apiPath notin paths:
    paths[apiPath] = newJObject()
  paths[apiPath][httpMethod.toLowerAscii()] =
    endpointOperationWithParams(httpMethod, path, meta, parameters, Out)

proc addEndpointWithParamsAndBody*[Body, Out](
    paths: JsonNode,
    httpMethod, path: string,
    meta: EndpointMeta,
    parameters: JsonNode,
    body: typedesc[Body],
    output: typedesc[Out],
) =
  let apiPath = openApiPath(path)
  if apiPath notin paths:
    paths[apiPath] = newJObject()
  paths[apiPath][httpMethod.toLowerAscii()] =
    endpointOperationWithParamsAndBody(httpMethod, path, meta, parameters, Body, Out)

proc openApiJson*(title, version: string, paths: JsonNode): JsonNode =
  %*{"openapi": "3.1.0", "info": {"title": title, "version": version}, "paths": paths}

proc openApiJson*(
    title, version: string, paths: JsonNode, components: JsonNode
): JsonNode =
  result = openApiJson(title, version, paths)
  if components.len > 0:
    result["components"] = components
