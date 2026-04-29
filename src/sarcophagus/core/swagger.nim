import std/[json, macros, options, strutils]

import ./tapis_security
import ./typed_api

type
  ApiExample* = object
    summary*: string
    description*: string
    value*: JsonNode
    externalValue*: string

  ApiResponseDoc* = object
    description*: string
    contentType*: string
    example*: JsonNode
    examples*: seq[(string, ApiExample)]

  ApiRequestDoc* = object
    contentType*: string
    example*: JsonNode
    examples*: seq[(string, ApiExample)]

  EndpointMeta* = object
    summary*: string
    description*: string
    operationId*: string
    tags*: seq[string]
    responseStatus*: int
    request*: ApiRequestDoc
    responses*: seq[(int, ApiResponseDoc)]
    security*: ApiSecurity

proc apiExample*(
    summary = "", description = "", value: JsonNode = nil, externalValue = ""
): ApiExample =
  ApiExample(
    summary: summary,
    description: description,
    value: value,
    externalValue: externalValue,
  )

proc apiExample*[T](
    summary = "", description = "", value: T, externalValue = ""
): ApiExample =
  apiExample(summary, description, parseJson(encodeJsonApi(value)), externalValue)

proc apiResponseDoc*(
    description = "",
    contentType = "application/json",
    example: JsonNode = nil,
    examples: openArray[(string, ApiExample)] = [],
): ApiResponseDoc =
  ApiResponseDoc(
    description: description,
    contentType: contentType,
    example: example,
    examples: @examples,
  )

proc nodeName*(node: NimNode): string =
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

proc fieldValue*(node: NimNode): tuple[name: string, value: NimNode] =
  if node.kind != nnkAsgn or node.len != 2:
    error("expected name = value", node)
  (node[0].nodeName(), node[1].copyNimTree())

proc parseApiExampleBlock*(node: NimNode): NimNode =
  if node.kind != nnkCall or node[0].nodeName() != "apiExample":
    error("expected apiExample(name): block", node)
  if node.len notin {2, 3}:
    error("expected apiExample(name): block", node)

  var name: NimNode =
    if node.len == 3:
      node[1].copyNimTree()
    else:
      nil
  var summary: NimNode
  var description: NimNode
  var value: NimNode
  var externalValue: NimNode

  let body = node[^1]
  for child in body:
    let field = child.fieldValue()
    case field.name
    of "name":
      name = field.value
    of "summary":
      summary = field.value
    of "description":
      description = field.value
    of "value":
      value = field.value
    of "externalValue":
      externalValue = field.value
    else:
      error("unknown apiExample field: " & field.name, child)

  if name.isNil:
    error("apiExample block requires apiExample(name):", node)

  let call = newCall(bindSym"apiExample")
  if not summary.isNil:
    call.add newTree(nnkExprEqExpr, ident"summary", summary)
  if not description.isNil:
    call.add newTree(nnkExprEqExpr, ident"description", description)
  if not value.isNil:
    call.add newTree(nnkExprEqExpr, ident"value", value)
  if not externalValue.isNil:
    call.add newTree(nnkExprEqExpr, ident"externalValue", externalValue)

  newTree(nnkExprColonExpr, name, call)

proc parseApiExamplesBlock*(node: NimNode): NimNode =
  if node.kind != nnkCall or node.len != 2 or node[0].nodeName() != "examples":
    error("expected examples: block", node)

  result = newTree(nnkTableConstr)
  for child in node[1]:
    result.add parseApiExampleBlock(child)

proc parseApiRequestDocBlock*(body: NimNode): NimNode =
  result = newCall(ident"apiRequestDoc")
  for child in body:
    if child.kind == nnkAsgn:
      let field = child.fieldValue()
      case field.name
      of "contentType":
        result.add newTree(nnkExprEqExpr, ident"contentType", field.value)
      of "example":
        result.add newTree(nnkExprEqExpr, ident"example", field.value)
      else:
        error("unknown apiRequestDoc field: " & field.name, child)
    elif child.kind == nnkCall and child[0].nodeName() == "examples":
      result.add newTree(nnkExprEqExpr, ident"examples", parseApiExamplesBlock(child))
    else:
      error("expected request field or examples block", child)

proc parseApiResponseDocsBlock*(body: NimNode): NimNode =
  result = newTree(nnkTableConstr)
  for response in body:
    if response.kind != nnkCall or response.len != 3 or response[0].nodeName() != "http":
      error("expected http(status): block", response)

    let statusCode = response[1].copyNimTree()
    let responseDoc = newCall(bindSym"apiResponseDoc")
    for child in response[2]:
      if child.kind == nnkAsgn:
        let field = child.fieldValue()
        case field.name
        of "description":
          responseDoc.add newTree(nnkExprEqExpr, ident"description", field.value)
        of "contentType":
          responseDoc.add newTree(nnkExprEqExpr, ident"contentType", field.value)
        of "example":
          responseDoc.add newTree(nnkExprEqExpr, ident"example", field.value)
        else:
          error("unknown apiResponseDoc field: " & field.name, child)
      elif child.kind == nnkCall and child[0].nodeName() == "examples":
        responseDoc.add newTree(
          nnkExprEqExpr, ident"examples", parseApiExamplesBlock(child)
        )
      else:
        error("expected response field or examples block", child)

    result.add newTree(nnkExprColonExpr, statusCode, responseDoc)

macro apiResponseDocs*(body: untyped): untyped =
  ## Builds response documentation metadata for TAPIS route registration.
  ##
  ## Example:
  ##   responses = block:
  ##     apiResponseDocs:
  ##       http(201):
  ##         description = "Created"
  ##         examples:
  ##           apiExample("created"):
  ##             value = MyResponse(...)
  result = parseApiResponseDocsBlock(body)

macro apiRequestDocs*(body: untyped): untyped =
  ## Builds request body documentation metadata for TAPIS route registration.
  ##
  ## Example:
  ##   request = block:
  ##     apiRequestDocs:
  ##       examples:
  ##         apiExample("create"):
  ##           value = MyRequest(...)
  result = parseApiRequestDocBlock(body)

proc apiRequestDoc*(
    contentType = "application/json",
    example: JsonNode = nil,
    examples: openArray[(string, ApiExample)] = [],
): ApiRequestDoc =
  ApiRequestDoc(contentType: contentType, example: example, examples: @examples)

proc endpointMeta*(
    summary = "",
    description = "",
    operationId = "",
    tags: openArray[string] = [],
    responseStatus = 200,
    request = apiRequestDoc(),
    responses: openArray[(int, ApiResponseDoc)] = [],
    security = noSecurity(),
): EndpointMeta =
  EndpointMeta(
    summary: summary,
    description: description,
    operationId: operationId,
    tags: @tags,
    responseStatus: responseStatus,
    request: request,
    responses: @responses,
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

proc apiExampleJson(example: ApiExample): JsonNode =
  result = newJObject()
  if example.summary.len > 0:
    result["summary"] = %example.summary
  if example.description.len > 0:
    result["description"] = %example.description
  if example.value != nil:
    result["value"] = example.value
  if example.externalValue.len > 0:
    result["externalValue"] = %example.externalValue

proc applyExamples(
    mediaType: JsonNode, example: JsonNode, examples: seq[(string, ApiExample)]
) =
  if example != nil:
    mediaType["example"] = example
  if examples.len > 0:
    var examplesJson = newJObject()
    for (name, example) in examples:
      examplesJson[name] = apiExampleJson(example)
    mediaType["examples"] = examplesJson

proc applyRequestDoc(requestBody: JsonNode, doc: ApiRequestDoc) =
  if doc.example == nil and doc.examples.len == 0:
    return

  if "content" notin requestBody:
    requestBody["content"] = newJObject()
  if doc.contentType notin requestBody["content"]:
    requestBody["content"][doc.contentType] = newJObject()

  requestBody["content"][doc.contentType].applyExamples(doc.example, doc.examples)

proc applyResponseDoc(response: JsonNode, doc: ApiResponseDoc) =
  if doc.description.len > 0:
    response["description"] = %doc.description

  if doc.example == nil and doc.examples.len == 0:
    return

  if "content" notin response:
    response["content"] = newJObject()
  if doc.contentType notin response["content"]:
    response["content"][doc.contentType] = newJObject()

  let mediaType = response["content"][doc.contentType]
  mediaType.applyExamples(doc.example, doc.examples)

proc applyResponseDocs(responses: JsonNode, docs: openArray[(int, ApiResponseDoc)]) =
  for (statusCode, doc) in docs:
    let key = $statusCode
    if key notin responses:
      responses[key] = newJObject()
      responses[key]["description"] =
        %(if doc.description.len > 0: doc.description else: "Additional response")
    applyResponseDoc(responses[key], doc)

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
    result["requestBody"].applyRequestDoc(meta.request)

  result["responses"] =
    %*{
      $meta.responseStatus:
        {"description": "Successful response", "content": responseContentSchema(Out)},
      "400": {"description": "Invalid request"},
      "500": {"description": "Internal server error"},
    }
  result["responses"].applyResponseDocs(meta.responses)

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
  result["responses"].applyResponseDocs(meta.responses)

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
  result["requestBody"].applyRequestDoc(meta.request)

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
