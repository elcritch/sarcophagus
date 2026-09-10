import std/[json, unittest]
import sarcophagus/tapis

const endpointPath = "/foo"

proc readFoo(): string {.tapi(get, endpointPath).} =
  "foo"

proc plainFoo(): string =
  "foo"

proc flatFoo(id: int): string {.tapi(get, "/foo/@id").} =
  $id

template checkMethod(methodName: untyped) =
  block:
    proc endpoint(): string {.tapi(methodName, "/endpoint").} =
      "ok"

    static:
      doAssert compiles(
        block:
          let api = initApiRouter()
          api.methodName("/endpoint", endpoint)
      )
      doAssert not compiles(
        block:
          let api = initApiRouter()
          api.methodName("/different", endpoint)
      )

checkMethod(get)
checkMethod(head)
checkMethod(post)
checkMethod(put)
checkMethod(patch)
checkMethod(delete)
checkMethod(options)

static:
  doAssert compiles(
    block:
      let api = initApiRouter()
      api.add(readFoo)
  )
  doAssert compiles(
    block:
      let api = initApiRouter()
      api.add(readFoo, middlewares = [])
  )
  doAssert not compiles(
    block:
      let api = initApiRouter()
      api.post(endpointPath, readFoo)
  )
  doAssert not compiles(
    block:
      let api = initApiRouter()
      api.options(endpointPath, readFoo)
  )
  doAssert not compiles(
    block:
      let api = initApiRouter()
      var path = endpointPath
      api.get(path, readFoo)
  )
  doAssert not compiles(
    block:
      let api = initApiRouter()
      api.get("/wrong/@id", flatFoo)
  )
  doAssert compiles(
    block:
      let api = initApiRouter()
      var path = endpointPath
      api.get(path, plainFoo)
  )

suite "TAPIS route declarations":
  test "matching explicit routes populate OpenAPI":
    let api = initApiRouter()
    api.get(endpointPath, readFoo)
    api.get("/foo/@" & "id", flatFoo)
    let spec = api.openApiJson()
    check spec["paths"].hasKey(endpointPath)
    check spec["paths"][endpointPath].hasKey("get")
    check spec["paths"].hasKey("/foo/{id}")
