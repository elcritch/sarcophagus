import std/[json, options, os, strutils]

import mummy

import sarcophagus/tapis

type
  PetStatus = enum
    petAvailable
    petPending
    petSold

  HealthResponse = object
    status*: string

  MessageResponse = object
    status*: string
    message*: string

  Pet = object
    id*: int
    name*: string
    species*: string
    status*: PetStatus
    age*: Option[int]

  PetList = object
    items*: seq[Pet]
    count*: int

  ListPetsParams = object
    limit*: Option[int]
    status*: Option[PetStatus]

  PetPath = object
    id*: int

  CreatePetBody = object
    name*: string
    species*: string
    age*: Option[int]

proc health(): HealthResponse {.gcsafe.} =
  HealthResponse(status: "ok")

proc examplePets(): seq[Pet] =
  @[
    Pet(id: 1, name: "Ada", species: "cat", status: petAvailable, age: some(4)),
    Pet(id: 2, name: "Grace", species: "dog", status: petPending, age: none(int)),
    Pet(id: 3, name: "Linus", species: "fox", status: petSold, age: some(6)),
  ]

proc listPets(params: Params[ListPetsParams]): PetList {.gcsafe.} =
  var pets: seq[Pet]
  for pet in examplePets():
    if params.status.isSome() and pet.status != params.status.get():
      continue
    pets.add pet

  if params.limit.isSome() and params.limit.get() < pets.len:
    pets.setLen(params.limit.get())

  PetList(items: pets, count: pets.len)

proc getPet(params: Params[PetPath]): Pet {.gcsafe.} =
  for pet in examplePets():
    if pet.id == params.id:
      return pet

  raiseApiError(404, "pet not found", "pet_not_found", details = %*{"id": params.id})

proc getPetFlat(id: int, includeSold: Option[bool]): Pet {.gcsafe.} =
  for pet in examplePets():
    if pet.id == id and (includeSold.get(false) or pet.status != petSold):
      return pet

  raiseApiError(404, "pet not found", "pet_not_found", details = %*{"id": id})

proc createPet(body: CreatePetBody): ApiResponse[Pet] {.gcsafe.} =
  var headers: HttpHeaders
  headers["Location"] = "/pets/100"
  apiResponse(
    Pet(
      id: 100,
      name: body.name,
      species: body.species,
      status: petAvailable,
      age: body.age,
    ),
    statusCode = 201,
    headers = headers,
  )

proc updatePet(input: ApiRequest[PetPath, CreatePetBody]): Pet {.gcsafe.} =
  Pet(
    id: input.params.id,
    name: input.body.name,
    species: input.body.species,
    status: petPending,
    age: input.body.age,
  )

proc deletePet(params: Params[PetPath]): MessageResponse {.gcsafe.} =
  MessageResponse(status: "ok", message: "delete requested for pet " & $params.id)

proc brokenRoute(): MessageResponse {.gcsafe.} =
  raise newException(ValueError, "simulated validation failure")

proc parsePort(): Port =
  let rawPort =
    if paramCount() >= 1:
      paramStr(1)
    else:
      getEnv("API_EXAMPLE_PORT", "9082")

  try:
    Port(parseInt(rawPort))
  except ValueError:
    raise newException(ValueError, "invalid port: " & rawPort)

when isMainModule:
  let host = getEnv("API_EXAMPLE_HOST", "127.0.0.1")
  let port = parsePort()

  var config = defaultApiConfig()
  config.includeStackTraces =
    getEnv("API_EXAMPLE_STACKTRACES", "") in ["1", "true", "yes"]

  let apiRouter = initApiRouter("Sarcophagus TAPIS Example", "1.0.0", config)

  apiRouter.get("/health", health, summary = "Health check", tags = ["system"])
  apiRouter.get("/pets", listPets, summary = "List pets", tags = ["pets"])
  apiRouter.get("/pets/@id", getPet, summary = "Get a pet", tags = ["pets"])
  apiRouter.get(
    "/flat-pets/@id",
    getPetFlat,
    summary = "Get a pet with flat params",
    tags = ["pets"],
  )
  apiRouter.post(
    "/pets", createPet, summary = "Create a pet", tags = ["pets"], responseStatus = 201
  )
  apiRouter.put("/pets/@id", updatePet, summary = "Update a pet", tags = ["pets"])
  apiRouter.delete("/pets/@id", deletePet, summary = "Delete a pet", tags = ["pets"])
  apiRouter.get(
    "/broken", brokenRoute, summary = "Example error response", tags = ["system"]
  )
  apiRouter.mountOpenApi()

  let server = newServer(apiRouter.router, workerThreads = 1)
  echo "TAPIS example server listening on http://", host, ":", port.int
  echo "OpenAPI document: http://", host, ":", port.int, "/swagger.json"
  server.serve(port, address = host)
