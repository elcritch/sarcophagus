import std/[httpclient, json, options, random, unittest]

import mummy

import sarcophagus/tapis

when defined(feature.sarcophagus.cbor):
  import cborious

type
  ServerThreadArgs = object
    server: Server
    port: Port
    address: string

  ItemMode = enum
    modeFast
    modeSlow

  GetItemParams = object
    id*: int
    verbose*: Option[bool]
    mode*: Option[ItemMode]

  ItemBody = object
    name*: string
    count*: int

  ItemPath = object
    id*: int

  ItemOut = object
    id*: int
    name*: string
    count*: int
    verbose*: bool
    mode*: string

proc serveServer(args: ServerThreadArgs) {.thread.} =
  args.server.serve(args.port, address = args.address)

proc getItem(params: GetItemParams): ItemOut {.gcsafe.} =
  let verbose =
    if params.verbose.isSome():
      params.verbose.get()
    else:
      false
  let mode =
    if params.mode.isSome():
      $params.mode.get()
    else:
      ""
  ItemOut(
    id: params.id, name: "item-" & $params.id, count: 1, verbose: verbose, mode: mode
  )

proc createItem(body: ItemBody): ApiResponse[ItemOut] {.gcsafe.} =
  apiResponse(
    ItemOut(id: 42, name: body.name, count: body.count, verbose: false, mode: ""),
    statusCode = 201,
  )

proc upsertItem(input: ApiRequest[ItemPath, ItemBody]): ItemOut {.gcsafe.} =
  ItemOut(
    id: input.params.id,
    name: input.body.name,
    count: input.body.count,
    verbose: false,
    mode: "",
  )

proc valueErrorHandler(): ItemOut {.gcsafe.} =
  raise newException(ValueError, "bad value")

proc apiErrorHandler(): ItemOut {.gcsafe.} =
  raiseApiError(409, "item conflict", "item_conflict", %*{"id": 42})

proc buildApi(includeStackTraces = false): ApiRouter =
  var config = defaultApiConfig()
  config.includeStackTraces = includeStackTraces

  let api = initApiRouter("Typed Test API", "1.2.3", config)
  api.get("/items/@id", getItem, summary = "Get item", tags = ["items"])
  api.post("/items", createItem, summary = "Create item", responseStatus = 201)
  api.put("/items/@id", upsertItem, summary = "Upsert item")
  api.get("/value-error", valueErrorHandler)
  api.get("/api-error", apiErrorHandler)
  api.mountOpenApi()
  api

proc withTestServer(body: proc(baseUrl: string) {.gcsafe.}) =
  randomize()
  let api = buildApi(includeStackTraces = true)
  let server = newServer(api.router, workerThreads = 1)
  let portNumber = 20000 + rand(20000)
  let args =
    ServerThreadArgs(server: server, port: Port(portNumber), address: "127.0.0.1")

  var serverThread: Thread[ServerThreadArgs]
  createThread(serverThread, serveServer, args)
  defer:
    server.close()
    joinThread(serverThread)

  server.waitUntilReady()
  body("http://127.0.0.1:" & $portNumber)

suite "typed mummy tapis":
  test "parses path and query params into typed objects":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.get(baseUrl & "/items/7?verbose=true&mode=modeFast")
      check response.code.int == 200

      let body = parseJson(response.body)
      check body["id"].getInt() == 7
      check body["verbose"].getBool() == true
      check body["mode"].getStr() == "modeFast"

  test "parses json request bodies and response metadata":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let headers = newHttpHeaders(
        {"Content-Type": "application/json", "Accept": "application/json"}
      )
      let response = client.request(
        baseUrl & "/items",
        httpMethod = HttpPost,
        body = """{"name":"probe","count":3}""",
        headers = headers,
      )
      check response.code.int == 201

      let body = parseJson(response.body)
      check body["id"].getInt() == 42
      check body["name"].getStr() == "probe"
      check body["count"].getInt() == 3

  test "combines path params and request bodies":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let headers = newHttpHeaders({"Content-Type": "application/json"})
      let response = client.request(
        baseUrl & "/items/9",
        httpMethod = HttpPut,
        body = """{"name":"updated","count":5}""",
        headers = headers,
      )
      check response.code.int == 200

      let body = parseJson(response.body)
      check body["id"].getInt() == 9
      check body["name"].getStr() == "updated"
      check body["count"].getInt() == 5

  test "converts validation and api errors into useful json responses":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let invalid = client.get(baseUrl & "/items/not-an-int")
      check invalid.code.int == 400
      let invalidBody = parseJson(invalid.body)
      check invalidBody["status"].getStr() == "error"
      check invalidBody["error"]["code"].getStr() == "invalid_param"
      check invalidBody["error"].hasKey("stackTrace")

      let valueError = client.get(baseUrl & "/value-error")
      check valueError.code.int == 400
      check parseJson(valueError.body)["error"]["code"].getStr() == "invalid_request"

      let conflict = client.get(baseUrl & "/api-error")
      check conflict.code.int == 409
      let conflictBody = parseJson(conflict.body)
      check conflictBody["error"]["code"].getStr() == "item_conflict"
      check conflictBody["error"]["details"]["id"].getInt() == 42

  test "emits swagger compatible openapi json from registered types":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.get(baseUrl & "/swagger.json")
      check response.code.int == 200

      let spec = parseJson(response.body)
      check spec["openapi"].getStr() == "3.1.0"
      check spec["info"]["title"].getStr() == "Typed Test API"
      check spec["paths"].hasKey("/items/{id}")

      let getOperation = spec["paths"]["/items/{id}"]["get"]
      check getOperation["summary"].getStr() == "Get item"
      check getOperation["parameters"][0]["name"].getStr() == "id"
      check getOperation["parameters"][0]["in"].getStr() == "path"
      check getOperation["parameters"][0]["required"].getBool() == true

      let postOperation = spec["paths"]["/items"]["post"]
      check postOperation["requestBody"]["required"].getBool() == true
      check postOperation["responses"].hasKey("201")

  when defined(feature.sarcophagus.cbor):
    test "negotiates cbor request and response bodies":
      withTestServer do(baseUrl: string):
        var client = newHttpClient(timeout = 5_000)
        defer:
          client.close()

        let headers = newHttpHeaders(
          {"Content-Type": "application/cbor", "Accept": "application/cbor"}
        )
        let requestBody = toCbor(
          ItemBody(name: "binary", count: 8),
          {CborObjToMap, CborEnumAsString, CborCheckHoleyEnums},
        )
        let response = client.request(
          baseUrl & "/items",
          httpMethod = HttpPost,
          body = requestBody,
          headers = headers,
        )
        check response.code.int == 201

        let body = fromCbor(
          response.body, ItemOut, {CborObjToMap, CborEnumAsString, CborCheckHoleyEnums}
        )
        check body.name == "binary"
        check body.count == 8
