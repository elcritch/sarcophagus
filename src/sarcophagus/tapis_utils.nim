import mummy

import ./core/typed_api

export typed_api

proc mummyToApiHeaders*(headers: HttpHeaders): ApiHeaders =
  ## Converts Mummy response headers to typed API headers.
  for header in headers:
    result.add((header[0], header[1]))

proc apiToMummyHeaders*(headers: ApiHeaders): HttpHeaders =
  ## Converts typed API response headers to Mummy response headers.
  for header in headers:
    result[header.name] = header.value

proc respondTypedApiValue*[T](request: Request, value: ApiResponse[T]) =
  ## Writes a typed API response to a Mummy request as JSON.
  var responseHeaders = value.headers.apiToMummyHeaders()
  responseHeaders["Content-Type"] = jsonContentType
  let body = encodeApi(value.body, apiJson)

  if request.httpMethod == "HEAD":
    responseHeaders["Content-Length"] = $body.len
    request.respond(value.statusCode, responseHeaders)
  else:
    request.respond(value.statusCode, responseHeaders, body)

proc respondTypedApiValue*[T](request: Request, value: T, responseStatus = 200) =
  ## Writes a plain typed value to a Mummy request as JSON.
  request.respondTypedApiValue(apiResponse(value, responseStatus))

proc typedHandle*[T](
    request: Request, handler: proc(): ApiResponse[T] {.gcsafe.}
) {.gcsafe.} =
  ## Calls a typed handler from a Mummy request and writes the encoded response.
  request.respondTypedApiValue(handler())

proc typedHandle*[Out](
    request: Request, handler: proc(): Out {.gcsafe.}, responseStatus = 200
) {.gcsafe.} =
  ## Calls a typed no-argument handler from a Mummy request.
  request.respondTypedApiValue(handler(), responseStatus)

proc typedHandle*[T](
    request: Request, handler: proc(request: Request): ApiResponse[T] {.gcsafe.}
) {.gcsafe.} =
  ## Calls a request-aware typed handler from a Mummy request.
  request.respondTypedApiValue(handler(request))

proc typedHandle*[Out](
    request: Request,
    handler: proc(request: Request): Out {.gcsafe.},
    responseStatus = 200,
) {.gcsafe.} =
  ## Calls a request-aware typed handler from a Mummy request.
  request.respondTypedApiValue(handler(request), responseStatus)

proc typedMummyHandler*[T](handler: proc(): ApiResponse[T] {.gcsafe.}): RequestHandler =
  ## Converts a typed no-argument handler to a Mummy handler.
  return proc(request: Request) {.gcsafe.} =
    request.typedHandle(handler)

proc typedMummyHandler*[Out](
    handler: proc(): Out {.gcsafe.}, responseStatus = 200
): RequestHandler =
  ## Converts a typed no-argument handler to a Mummy handler.
  return proc(request: Request) {.gcsafe.} =
    request.typedHandle(handler, responseStatus)

proc typedMummyHandler*[T](
    handler: proc(request: Request): ApiResponse[T] {.gcsafe.}
): RequestHandler =
  ## Converts a request-aware typed handler to a Mummy handler.
  return proc(request: Request) {.gcsafe.} =
    request.typedHandle(handler)

proc typedMummyHandler*[Out](
    handler: proc(request: Request): Out {.gcsafe.}, responseStatus = 200
): RequestHandler =
  ## Converts a request-aware typed handler to a Mummy handler.
  return proc(request: Request) {.gcsafe.} =
    request.typedHandle(handler, responseStatus)
