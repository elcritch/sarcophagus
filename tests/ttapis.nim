import std/[httpclient, json, options, random, unittest]

import mummy
import mummy/routers

import sarcophagus/tapis

when defined(feature.sarcophagus.cbor):
  import cborious

when defined(feature.sarcophagus.msgpack) or defined(feature.sarcophagus.msgpack4nim):
  import msgpack4nim/msgpack2json

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

proc getItem(params: Params[GetItemParams]): ItemOut {.gcsafe.} =
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

# api.get("/read-items/@id", readItem, summary = "Read item", tags = ["items"])
proc readItem(
    params: Params[GetItemParams]
): ItemOut {.tapi(get, "/read-items/@id", summary = "Read item", tags = ["items"]).} =
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
    id: params.id, name: "read-" & $params.id, count: 1, verbose: verbose, mode: mode
  )

proc getFlatItem(id: int, verbose: Option[bool]): ItemOut {.gcsafe.} =
  ItemOut(id: id, name: "flat-" & $id, count: 1, verbose: verbose.get(false), mode: "")

proc readFlatItem(
    id: int, verbose: Option[bool]
): ItemOut {.tapi(get, "/flat-read-items/@id", summary = "Read flat item").} =
  ItemOut(
    id: id, name: "flat-read-" & $id, count: 1, verbose: verbose.get(false), mode: ""
  )

proc getNamedTupleItem(
    params: Params[tuple[id: int, verbose: Option[bool]]]
): ItemOut {.gcsafe.} =
  ItemOut(
    id: params.id,
    name: "tuple-" & $params.id,
    count: 1,
    verbose: params.verbose.get(false),
    mode: "",
  )

proc getUnnamedTupleItem(
    params: Params[(int, string)]
): tuple[id: int, label: string] {.gcsafe.} =
  (id: params[0], label: params[1])

proc createItem(body: ItemBody): ApiResponse[ItemOut] {.gcsafe.} =
  apiResponse(
    ItemOut(id: 42, name: body.name, count: body.count, verbose: false, mode: ""),
    statusCode = 201,
  )

proc createBulkItem(
    body: Body[ItemBody], id: int, verbose: Option[bool]
): ItemOut {.gcsafe.} =
  ItemOut(
    id: id, name: body.name, count: body.count, verbose: verbose.get(false), mode: ""
  )

proc createQueriedItem(
    body: Body[ItemBody], verbose: Option[bool], mode: Option[ItemMode]
): ItemOut {.gcsafe.} =
  ItemOut(
    id: 0,
    name: body.name,
    count: body.count,
    verbose: verbose.get(false),
    mode:
      if mode.isSome():
        $mode.get()
      else:
        "",
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

proc htmlDocs(): RawResponse["text/html"] {.gcsafe.} =
  htmlResponse("<!DOCTYPE html><h1>Docs</h1>")

proc rawMummyStatus(request: Request) {.gcsafe.} =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "application/json; charset=utf-8"
  request.respond(200, headers, """{"status":"raw-mummy"}""")

proc buildApi(includeStackTraces = false): ApiRouter =
  var config = defaultApiConfig()
  config.includeStackTraces = includeStackTraces

  let api = initApiRouter("Typed Test API", "1.2.3", config)
  api.router.get("/raw-status", rawMummyStatus)
  api.get("/items/@id", getItem, summary = "Get item", tags = ["items"])
  api.add(
    readItem,
    responses = {
      200: apiResponseDoc(
        description = "Read item response",
        examples = {
          "read": apiExample(
            summary = "Read item",
            value =
              %*{
                "id": 8,
                "name": "read-8",
                "count": 1,
                "verbose": true,
                "mode": "modeSlow",
              },
          )
        },
      )
    },
  )
  api.get("/flat-items/@id", getFlatItem, summary = "Get flat item")
  api.add(readFlatItem)
  api.post(
    "/items",
    createItem,
    summary = "Create item",
    responseStatus = 201,
    responses = {
      201: apiResponseDoc(
        description = "Created item response",
        examples = {
          "created": apiExample(
            summary = "Created item",
            value =
              %*{"id": 42, "name": "probe", "count": 3, "verbose": false, "mode": ""},
          )
        },
      )
    },
  )
  api.post("/bulk-items/@id", createBulkItem, summary = "Create bulk item")
  api.post("/queried-items", createQueriedItem, summary = "Create queried item")
  api.put("/items/@id", upsertItem, summary = "Upsert item")
  api.get("/tuple-items/@id", getNamedTupleItem, summary = "Get tuple item")
  api.get("/unnamed-tuple", getUnnamedTupleItem, summary = "Get unnamed tuple")
  api.get("/value-error", valueErrorHandler)
  api.get("/api-error", apiErrorHandler)
  api.get("/docs", htmlDocs, summary = "HTML docs")
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

  test "mixes regular mummy handlers with typed tapis handlers":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let rawResponse = client.get(baseUrl & "/raw-status")
      check rawResponse.code.int == 200
      check parseJson(rawResponse.body)["status"].getStr() == "raw-mummy"

      let typedResponse = client.get(baseUrl & "/items/17?verbose=true")
      check typedResponse.code.int == 200
      let typedBody = parseJson(typedResponse.body)
      check typedBody["id"].getInt() == 17
      check typedBody["verbose"].getBool() == true

  test "serves raw typed responses without json encoding":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.get(baseUrl & "/docs")
      check response.code.int == 200
      check response.headers["Content-Type"] == "text/html"
      check response.body == "<!DOCTYPE html><h1>Docs</h1>"

  test "converts typed handlers to plain mummy handlers":
    randomize()
    var router: Router
    router.get("/converted/@id", toMummyHandler(getItem, adsParams))

    let server = newServer(router, workerThreads = 1)
    let portNumber = 20000 + rand(20000)
    let args =
      ServerThreadArgs(server: server, port: Port(portNumber), address: "127.0.0.1")

    var serverThread: Thread[ServerThreadArgs]
    createThread(serverThread, serveServer, args)
    defer:
      server.close()
      joinThread(serverThread)

    server.waitUntilReady()

    var client = newHttpClient(timeout = 5_000)
    defer:
      client.close()

    let response =
      client.get("http://127.0.0.1:" & $portNumber & "/converted/21?verbose=true")
    check response.code.int == 200
    let body = parseJson(response.body)
    check body["id"].getInt() == 21
    check body["name"].getStr() == "item-21"
    check body["verbose"].getBool() == true

  test "registers tapi pragma handlers with api.add":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.get(baseUrl & "/read-items/8?verbose=true&mode=modeSlow")
      check response.code.int == 200

      let body = parseJson(response.body)
      check body["id"].getInt() == 8
      check body["name"].getStr() == "read-8"
      check body["verbose"].getBool() == true
      check body["mode"].getStr() == "modeSlow"

  test "parses flat path and query handler parameters":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.get(baseUrl & "/flat-items/11?verbose=true")
      check response.code.int == 200

      let body = parseJson(response.body)
      check body["id"].getInt() == 11
      check body["name"].getStr() == "flat-11"
      check body["verbose"].getBool() == true

  test "registers flat tapi pragma handlers with api.add":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.get(baseUrl & "/flat-read-items/12?verbose=true")
      check response.code.int == 200

      let body = parseJson(response.body)
      check body["id"].getInt() == 12
      check body["name"].getStr() == "flat-read-12"
      check body["verbose"].getBool() == true

  test "parses named tuple query params without declaring an object type":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.get(baseUrl & "/tuple-items/13?verbose=true")
      check response.code.int == 200

      let body = parseJson(response.body)
      check body["id"].getInt() == 13
      check body["name"].getStr() == "tuple-13"
      check body["verbose"].getBool() == true

  test "parses unnamed tuple query params by index aliases":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let response = client.get(baseUrl & "/unnamed-tuple?0=21&1=soil")
      check response.code.int == 200

      let body = parseJson(response.body)
      check body[0].getInt() == 21
      check body[1].getStr() == "soil"

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

  test "parses explicit body marker with flat path and query parameters":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let headers = newHttpHeaders({"Content-Type": "application/json"})
      let response = client.request(
        baseUrl & "/bulk-items/16?verbose=true",
        httpMethod = HttpPost,
        body = """{"name":"bulk","count":6}""",
        headers = headers,
      )
      check response.code.int == 200

      let body = parseJson(response.body)
      check body["id"].getInt() == 16
      check body["name"].getStr() == "bulk"
      check body["count"].getInt() == 6
      check body["verbose"].getBool() == true

  test "parses explicit body marker with query parameters only":
    withTestServer do(baseUrl: string):
      var client = newHttpClient(timeout = 5_000)
      defer:
        client.close()

      let headers = newHttpHeaders({"Content-Type": "application/json"})
      let response = client.request(
        baseUrl & "/queried-items?verbose=true&mode=modeSlow",
        httpMethod = HttpPost,
        body = """{"name":"queried","count":4}""",
        headers = headers,
      )
      check response.code.int == 200

      let body = parseJson(response.body)
      check body["id"].getInt() == 0
      check body["name"].getStr() == "queried"
      check body["count"].getInt() == 4
      check body["verbose"].getBool() == true
      check body["mode"].getStr() == "modeSlow"

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

      let flatOperation = spec["paths"]["/flat-items/{id}"]["get"]
      check flatOperation["parameters"][0]["name"].getStr() == "id"
      check flatOperation["parameters"][0]["in"].getStr() == "path"
      check flatOperation["parameters"][1]["name"].getStr() == "verbose"
      check flatOperation["parameters"][1]["in"].getStr() == "query"
      check flatOperation["parameters"][1]["required"].getBool() == false

      let unnamedOperation = spec["paths"]["/unnamed-tuple"]["get"]
      check unnamedOperation["parameters"][0]["name"].getStr() == "0"
      check unnamedOperation["parameters"][1]["name"].getStr() == "1"

      let postOperation = spec["paths"]["/items"]["post"]
      check postOperation["requestBody"]["required"].getBool() == true
      check postOperation["responses"].hasKey("201")
      let createdResponse = postOperation["responses"]["201"]
      check createdResponse["description"].getStr() == "Created item response"
      check createdResponse["content"]["application/json"].hasKey("schema")
      check createdResponse["content"]["application/json"]["examples"]["created"][
        "summary"
      ].getStr() == "Created item"

      let readOperation = spec["paths"]["/read-items/{id}"]["get"]
      let readResponse = readOperation["responses"]["200"]
      check readResponse["description"].getStr() == "Read item response"
      check readResponse["content"]["application/json"]["examples"]["read"]["value"][
        "name"
      ].getStr() == "read-8"

      let bulkOperation = spec["paths"]["/bulk-items/{id}"]["post"]
      check bulkOperation["parameters"][0]["name"].getStr() == "id"
      check bulkOperation["parameters"][0]["in"].getStr() == "path"
      check bulkOperation["parameters"][1]["name"].getStr() == "verbose"
      check bulkOperation["parameters"][1]["in"].getStr() == "query"
      check bulkOperation["requestBody"]["required"].getBool() == true

      let queriedOperation = spec["paths"]["/queried-items"]["post"]
      check queriedOperation["parameters"][0]["name"].getStr() == "verbose"
      check queriedOperation["parameters"][0]["in"].getStr() == "query"
      check queriedOperation["parameters"][1]["name"].getStr() == "mode"
      check queriedOperation["parameters"][1]["in"].getStr() == "query"
      check queriedOperation["requestBody"]["required"].getBool() == true

      let docsOperation = spec["paths"]["/docs"]["get"]
      let docsContent = docsOperation["responses"]["200"]["content"]
      check docsContent.hasKey("text/html")
      check not docsContent.hasKey("application/json")

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

  when defined(feature.sarcophagus.msgpack) or defined(feature.sarcophagus.msgpack4nim):
    test "negotiates msgpack request and response bodies":
      withTestServer do(baseUrl: string):
        var client = newHttpClient(timeout = 5_000)
        defer:
          client.close()

        let headers = newHttpHeaders(
          {"Content-Type": "application/msgpack", "Accept": "application/msgpack"}
        )
        let requestBody = msgpack2json.fromJsonNode(%*{"name": "packed", "count": 11})
        let response = client.request(
          baseUrl & "/items",
          httpMethod = HttpPost,
          body = requestBody,
          headers = headers,
        )
        check response.code.int == 201
        check response.headers["Content-Type"] == "application/msgpack"

        let body = msgpack2json.toJsonNode(response.body)
        check body["name"].getStr() == "packed"
        check body["count"].getInt() == 11
