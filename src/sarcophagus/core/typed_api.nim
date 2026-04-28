import std/[json, options, strutils]

when defined(feature.sarcophagus.jsony):
  import jsony
  export jsony
else:
  import std/jsonutils

when defined(feature.sarcophagus.cbor):
  import cborious
  import cborious/cbor2json
  export cborious

when defined(feature.sarcophagus.msgpack) or defined(feature.sarcophagus.msgpack4nim):
  import msgpack4nim
  import msgpack4nim/msgpack2json
  export msgpack4nim

type
  ApiFormat* = enum
    apiJson
    apiCbor
    apiMsgPack

  ApiDecodeSource* = enum
    adsNone
    adsParams
    adsBody

  EmptyInput* = object
  EmptyParams* = object
  EmptyBody* = object

  Params*[T] = T
  Body*[T] = T

  ApiRequest*[Params, Body] = object
    params*: Params
    body*: Body

  ApiHeader* = tuple[name: string, value: string]
  ApiHeaders* = seq[ApiHeader]

  ApiResponse*[T] = object
    statusCode*: int
    headers*: ApiHeaders
    body*: T

  RawResponse*[contentType: static string] = object
    statusCode*: int
    headers*: ApiHeaders
    body*: string

  ApiError* = object of CatchableError
    statusCode*: int
    code*: string
    details*: JsonNode

  ApiConfig* = object
    includeStackTraces*: bool
    defaultResponseFormat*: ApiFormat
    requestFormats*: set[ApiFormat]
    responseFormats*: set[ApiFormat]

const
  jsonContentType* = "application/json; charset=utf-8"
  cborContentType* = "application/cbor"
  msgPackContentType* = "application/msgpack"

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
  when defined(feature.sarcophagus.msgpack) or defined(feature.sarcophagus.msgpack4nim):
    result.requestFormats.incl apiMsgPack
    result.responseFormats.incl apiMsgPack

proc apiResponse*[T](
    body: sink T, statusCode = 200, headers: openArray[ApiHeader] = []
): ApiResponse[T] =
  ApiResponse[T](statusCode: statusCode, headers: @headers, body: body)

proc rawResponse*[contentType: static string](
    body: sink string, statusCode = 200, headers: openArray[ApiHeader] = []
): RawResponse[contentType] =
  RawResponse[contentType](statusCode: statusCode, headers: @headers, body: body)

proc htmlResponse*(
    body: sink string, statusCode = 200, headers: openArray[ApiHeader] = []
): RawResponse["text/html"] =
  rawResponse["text/html"](body, statusCode, headers)

proc textResponse*(
    body: sink string, statusCode = 200, headers: openArray[ApiHeader] = []
): RawResponse["text/plain"] =
  rawResponse["text/plain"](body, statusCode, headers)

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

proc mediaType*(raw: string): string =
  let semi = raw.find(';')
  let value =
    if semi >= 0:
      raw[0 ..< semi]
    else:
      raw
  value.strip().toLowerAscii()

proc mediaMatches*(raw, exact, suffix: string): bool =
  let value = mediaType(raw)
  value == exact or value.endsWith(suffix)

proc mediaMatchesMsgPack*(raw: string): bool =
  let value = mediaType(raw)
  value == "application/msgpack" or value == "application/x-msgpack" or
    value.endsWith("+msgpack")

proc formatContentType*(format: ApiFormat): string =
  case format
  of apiJson: jsonContentType
  of apiCbor: cborContentType
  of apiMsgPack: msgPackContentType

proc requestFormat*(contentType: string, config: ApiConfig): ApiFormat =
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
  elif mediaMatchesMsgPack(contentType):
    when defined(feature.sarcophagus.msgpack) or defined(
      feature.sarcophagus.msgpack4nim
    ):
      if apiMsgPack in config.requestFormats:
        return apiMsgPack
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
  if mediaMatchesMsgPack(value):
    when defined(feature.sarcophagus.msgpack) or defined(
      feature.sarcophagus.msgpack4nim
    ):
      if apiMsgPack in config.responseFormats:
        return some(apiMsgPack)
    else:
      discard
  none(ApiFormat)

proc responseFormat*(accept: string, config: ApiConfig): ApiFormat =
  if accept.len == 0:
    return config.defaultResponseFormat

  for token in accept.split(','):
    let format = acceptTokenFormat(token, config)
    if format.isSome():
      return format.get()

  raiseApiError(406, "No acceptable response content type", "not_acceptable")

proc encodeJsonApi*[T](value: T): string =
  when T is JsonNode:
    $value
  elif defined(feature.sarcophagus.jsony):
    jsony.toJson(value)
  else:
    $jsonutils.toJson(value, ToJsonOptions(enumMode: joptEnumString))

proc decodeJsonApi*[T](body: string, target: typedesc[T]): T =
  when T is JsonNode:
    parseJson(body)
  elif defined(feature.sarcophagus.jsony):
    body.fromJson(T)
  else:
    parseJson(body).to(T)

when defined(feature.sarcophagus.cbor):
  proc encodeCborApi*[T](value: T): string =
    when T is JsonNode:
      cbor2json.fromJsonNode(value)
    else:
      toCbor(value, apiCborEncodingMode)

  proc decodeCborApi*[T](body: string, target: typedesc[T]): T =
    when T is JsonNode:
      cbor2json.toJsonNode(body)
    else:
      fromCbor(body, T, apiCborEncodingMode)

when defined(feature.sarcophagus.msgpack) or defined(feature.sarcophagus.msgpack4nim):
  proc encodeMsgPackApi*[T](value: T): string =
    when T is JsonNode:
      msgpack2json.fromJsonNode(value)
    else:
      msgpack2json.fromJsonNode(parseJson(encodeJsonApi(value)))

  proc decodeMsgPackApi*[T](body: string, target: typedesc[T]): T =
    when T is JsonNode:
      msgpack2json.toJsonNode(body)
    else:
      decodeJsonApi($msgpack2json.toJsonNode(body), T)

proc encodeApi*[T](value: T, format: ApiFormat): string =
  case format
  of apiJson:
    encodeJsonApi(value)
  of apiCbor:
    when defined(feature.sarcophagus.cbor):
      encodeCborApi(value)
    else:
      raiseApiError(406, "CBOR responses are not enabled", "cbor_not_enabled")
  of apiMsgPack:
    when defined(feature.sarcophagus.msgpack) or defined(
      feature.sarcophagus.msgpack4nim
    ):
      encodeMsgPackApi(value)
    else:
      raiseApiError(406, "MessagePack responses are not enabled", "msgpack_not_enabled")

proc decodeApi*[T](body: string, format: ApiFormat, target: typedesc[T]): T =
  case format
  of apiJson:
    decodeJsonApi(body, T)
  of apiCbor:
    when defined(feature.sarcophagus.cbor):
      decodeCborApi(body, T)
    else:
      raiseApiError(415, "CBOR requests are not enabled", "cbor_not_enabled")
  of apiMsgPack:
    when defined(feature.sarcophagus.msgpack) or defined(
      feature.sarcophagus.msgpack4nim
    ):
      decodeMsgPackApi(body, T)
    else:
      raiseApiError(415, "MessagePack requests are not enabled", "msgpack_not_enabled")

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

proc apiErrorStatus*(e: ref Exception): int =
  if e of ApiError:
    cast[ref ApiError](e).statusCode
  elif e of ValueError:
    400
  else:
    500

proc apiErrorCode*(e: ref Exception): string =
  if e of ApiError:
    cast[ref ApiError](e).code
  elif e of ValueError:
    "invalid_request"
  else:
    "internal_error"

proc apiErrorDetails*(e: ref Exception): JsonNode =
  if e of ApiError:
    cast[ref ApiError](e).details
  else:
    nil

proc apiErrorBody*(e: ref Exception, config: ApiConfig): JsonNode =
  var err = %*{"code": apiErrorCode(e), "message": e.msg, "type": $e.name}
  let details = apiErrorDetails(e)
  if details != nil:
    err["details"] = details
  if config.includeStackTraces:
    err["stackTrace"] = %e.getStackTrace()
  %*{"status": "error", "error": err}
