# Sarcophagus

Sarcophagus is a FastAPI inspired higher-level API layer for [Mummy](https://github.com/guzba/mummy).

It enables writing REST & JSON APIs for Mummy web server using Nim types that are automatically parsed for you. Sarcophagus calls these "TAPIS" short for typed APIs.

The Nim types can be encoded/decorded using JSON, CBOR, or MSGPACK. The typed apis are used to create OpenAPI route metadata and to produce a `swagger.json` docs for you. Swagger examples can be added to the endpoints as well. Other non-JSON/CBOR/SGPACK endpoints can also be added.

Sarcophagus also provides security helpers to make OAuth2-protected API endpoints. This uses JWT tokens. These can be used directly with Mummy in addition to Sarcophagus typed APIs.

## Installation

```sh
atlas use https://github.com/elcritch/sarcophagus
# or
nimble install https://github.com/elcritch/sarcophagus
```

Note, `jwt` can cause issues during installation. Add `requires "jwt >= 0.3"` to your nimble file if you get `jwt` issues.

## Logging

Sarcophagus uses [Chroniclers](https://github.com/elcritch/chroniclers) for
logging facade support. TAPIS logs handled route errors by default with the
request method, path, response status, error code, exception type, and message.
To compile out Chroniclers log calls in an application, build with:

```sh
nim c -d:chroniclersLogBackend=none app.nim
```

Use `-d:chroniclersLogBackend=std` for Nim's `std/logging`, or enable
Sarcophagus' `chronicles` feature to route Chroniclers through Chronicles.

## Basic Example

```nim
import std/options
import mummy
import sarcophagus/tapis

type Item = object
  id*: int
  name*: string
  verbose*: bool

proc readItem(
    id: int, verbose: Option[bool]
): Item {.tapi(get, "/items/@id", summary = "Read an item", tags = ["items"])
.} =
  Item(id: id, name: "item-" & $id, verbose: verbose.get(false))

proc createItem(
    item: Item
): ApiResponse[Item] {.tapi(post, "/items", summary = "Create an item", responseStatus = 201).} =
  apiResponse(item, statusCode = 201)

let api = initApiRouter("Example API", "1.0.0")
api.add(readItem)
api.add(createItem)
api.mountOpenApi()

echo "Listening on http://127.0.0.1:8080"
newServer(api.router).serve(Port(8080), address = "127.0.0.1")
```

Run it with:

```sh
nim c -r --path:src server.nim
```

Then try `GET /items/42?verbose=true`, `POST /items`, or inspect
`/swagger.json`.

## `sarcophagus/tapis`

`sarcophagus/tapis` is the typed API layer. It exports the TAPIS router, typed
encoding/decoding helpers, OpenAPI helpers, and TAPIS security helpers.

Core pieces:

- `initApiRouter(title, version, config)` creates a typed Mummy router wrapper.
- `tapi(method, path, ...)` marks a proc as an API endpoint.
- `api.add(handler)` registers a `tapi`-annotated proc.
- `api.registerOAuth2(config)` mounts the standard typed-router `/oauth/token`
  endpoint.
- `api.mountOpenApi()` mounts `/swagger.json`.
- `ApiResponse[T]` lets a handler set status codes and headers.
- `raiseApiError(status, message, code, details)` produces structured error JSON.

Flat handler style keeps simple APIs concise:

```nim
proc readItem(
    id: int, verbose: Option[bool]
): ItemOut {.tapi(get, "/items/@id", summary = "Read item").} =
  ItemOut(id: id, verbose: verbose.get(false))

api.add(readItem)
```

Path parameters are identified by `@name` in the route path. Query parameters are
the remaining proc parameters. Optional query parameters should use
`Option[T]`.

Grouped parameter style is available when a route has enough parameters to merit
a named type:

```nim
type ListItemsParams = object
  limit*: Option[int]
  tag*: Option[string]

proc listItems(
    params: Params[ListItemsParams]
): ItemList {.tapi(get, "/items", summary = "List items").} =
  discard
```

For request bodies, `post`, `put`, and `patch` decode the body into the single
handler input type:

```nim
type CreateItemBody = object
  name*: string
  count*: int

proc createItem(
    body: CreateItemBody
): ApiResponse[ItemOut] {.tapi(post, "/items", summary = "Create item", responseStatus = 201).} =
  apiResponse(ItemOut(name: body.name, count: body.count), statusCode = 201)
```

Use `Body[T]` when a flat route needs both path/query parameters and a request
body:

```nim
proc updateItem(
    body: Body[CreateItemBody],
    id: int,
    notify: Option[bool],
): ItemOut {.tapi(put, "/items/@id", summary = "Update item").} =
  ItemOut(id: id, name: body.name, count: body.count)

proc createItem(
    body: Body[CreateItemBody],
    dryRun: Option[bool],
): ItemOut {.tapi(post, "/items", summary = "Create item").} =
  ItemOut(id: 0, name: body.name, count: body.count)
```

Use `ApiRequest[Params, Body]` when grouped path/query parameters are clearer:

```nim
type ItemPath = object
  id*: int

proc updateItem(
    input: ApiRequest[ItemPath, CreateItemBody]
): ItemOut {.tapi(put, "/items/@id", summary = "Update item").} =
  ItemOut(id: input.params.id, name: input.body.name, count: input.body.count)
```

### OpenAPI Examples

Request and response examples can be added to the OpenAPI document with the
block-style docs helpers:

```nim
api.post(
  "/items",
  createItem,
  summary = "Create item",
  responseStatus = 201,
  request = block:
    apiRequestDocs:
      examples:
        "create":
          summary = "Create item request"
          value = CreateItemBody(name: "probe", count: 3),
  responses = block:
    apiResponseDocs:
      http(201):
        description = "Created item response"
        examples:
          "created":
            summary = "Created item"
            value = ItemOut(id: 42, name: "probe", count: 3),
)
```

### Mixed Routers

TAPIS routes and regular Mummy handlers can use the same router. Register raw
Mummy handlers on `api.router` when you need lower-level control or an endpoint
that should not participate in TAPIS encoding and OpenAPI metadata:

```nim
import mummy
import mummy/routers
import sarcophagus/tapis

proc status(request: Request) {.gcsafe.} =
  var headers: mummy.HttpHeaders
  headers["Content-Type"] = "application/json; charset=utf-8"
  request.respond(200, headers, """{"status":"ok"}""")

proc readItem(id: int): ItemOut {.gcsafe.} =
  ItemOut(id: id, name: "item-" & $id)

let api = initApiRouter("Mixed API", "1.0.0")
api.router.get("/status", status)
api.get("/items/@id", readItem, summary = "Read item")
api.mountOpenApi()

newServer(api.router).serve(Port(8080), address = "127.0.0.1")
```

### Raw HTML Responses

Use `RawResponse["text/html"]` when a typed TAPIS handler should return HTML or
another pre-encoded string body instead of JSON encoding:

```nim
proc docs(): RawResponse["text/html"] {.gcsafe.} =
  htmlResponse("""
<!DOCTYPE html>
<html>
<head><title>API Docs</title></head>
<body><div id="redoc"></div></body>
</html>""")

api.get("/docs", docs, summary = "API docs")
```

`rawResponse["content/type"](...)` and `textResponse(...)` are also available
for other string response types.

By default, TAPIS supports JSON. Compile with `-d:feature.sarcophagus.cbor` or
`-d:feature.sarcophagus.msgpack` to enable CBOR or MessagePack request/response
negotiation.

Error handling is automatic for TAPIS routes:

- `ApiError` uses its explicit status, code, message, and details.
- `ValueError` maps to HTTP 400 with `invalid_request`.
- Other `CatchableError` values map to HTTP 500 with `internal_error`.
- Set `config.includeStackTraces = true` to include stack traces in error bodies.

## `sarcophagus/tapis_security`

`sarcophagus/tapis_security` adds OpenAPI-aware route security to TAPIS. It is
exported by `sarcophagus/tapis`, so most applications only need to import
`sarcophagus/tapis`.

Use `security = ...` for one route:

```nim
api.add(readItem, security = oauth2(config, ["items:read"]))
```

If a route only needs a valid bearer token and does not require specific scopes, omit the scope list:

```nim
type UserInfo = object
  status*: string
  message*: string

proc health(): HealthResponse {.
  tapi(get, "/health", summary = "Health check", tags = ["system"])
.} =
  HealthResponse(status: "ok")

proc currentUser(): UserInfo {.
  tapi(get, "/me", summary = "Current authenticated user", tags = ["users"])
.} =
  UserInfo(status: "ok", message: "authenticated")

let api = initApiRouter("Authenticated API", "1.0.0")
let auth = oauth2(config)

api.registerOAuth2(config)
api.add(health)
api.add(currentUser, security = auth)
api.mountOpenApi()
```

That setup does not use `api.get`, `api.post`, or raw `router.get`/`router.post`
registration. Route metadata stays on the proc via `tapi`, while `api.add`
registers it and applies the OpenAPI-aware security wrapper.

The same security model also works with explicit router-style TAPIS registration:

```nim
type
  CreateItemBody = object
    name*: string

  ItemOut = object
    id*: int
    name*: string

proc readItem(id: int): ItemOut {.gcsafe.} =
  ItemOut(id: id, name: "item-" & $id)

proc createItem(body: CreateItemBody): ApiResponse[ItemOut] {.gcsafe.} =
  apiResponse(ItemOut(id: 100, name: body.name), statusCode = 201)

let api = initApiRouter("Router Style API", "1.0.0")
let readSecurity = oauth2(config)
let writeSecurity = oauth2(config, ["items:write"])

api.registerOAuth2(config)
api.get( "/items/@id", readItem, summary = "Read item", tags = ["items"], security = readSecurity)
api.post( "/items", createItem, summary = "Create item", tags = ["items"], responseStatus = 201, security = writeSecurity)
api.mountOpenApi()
```

Use `withSecurity` for route groups:

```nim
withSecurity(api, oauth2(config, ["items:read"])):
  api.add(readItem)
  api.add(listItems)
  withSecurity(api, oauth2(config, ["items:write"])):
    api.add(createItem)
```

An explicit route security argument overrides an outer scope:

```nim
withSecurity(api, oauth2(config, ["items:read"])):
  api.add(publicHealth, security = noSecurity())
```

The same security metadata is used twice: the runtime wrapper validates bearer
tokens and the OpenAPI generator emits `components.securitySchemes` plus per-route
`security` requirements.

## `sarcophagus/oauth2`

`sarcophagus/oauth2` is the main facade. The implementation is split into:

- `sarcophagus/oauth2/core` for protocol logic such as token issuance,
  authorization-code exchange, and resource-server validation.
- `sarcophagus/oauth2/common` for typed API payloads, callbacks, and error
  response helpers.
- `sarcophagus/oauth2/mummy_support` for raw Mummy handlers, router registration,
  and route-wrapping macros.


Typical setup:

```nim
let tokenConfig = initBearerTokenConfig(
  issuer = "example-server",
  audience = "example-api",
  keys = [SigningKey(kid: "v1", secret: "change-me")],
)

let oauthConfig = initOAuth2Config(
  realm = "example",
  tokenConfig = tokenConfig,
  clients = [
    initOAuth2Client(
      clientId = "example-cli",
      clientSecret = "secret",
      allowedScopes = ["items:read", "items:write"],
      defaultScopes = ["items:read"],
    )
  ],
)
```

Token issuance:

```nim
let result = issueClientCredentialsToken(
  oauthConfig,
  authorizationHeader = "Basic ZXhhbXBsZS1jbGk6c2VjcmV0",
  contentType = "application/x-www-form-urlencoded",
  requestBody = "grant_type=client_credentials&scope=items%3Aread",
)
```

Resource validation:

```nim
let validation = validateOAuth2BearerToken(
  oauthConfig,
  authorizationHeader = "Bearer " & result.response.accessToken,
  requiredScopes = ["items:read"],
)
```

Typed TAPIS registration is the first-class OAuth2 setup:

- `api.registerOAuth2(config)` mounts the token endpoint.
- `api.registerOAuth2AuthorizationCode(...)` mounts the browser authorization
  endpoint and token endpoint for authorization-code login.
- `security = oauth2(...)` and `withSecurity(...)` keep OpenAPI metadata in sync
  with runtime bearer-token enforcement.

For non-TAPIS handlers, use the same names on a plain Mummy `Router`:

- `oauth2TokenHandler(config)` returns a raw token endpoint handler.
- `oauth2AuthorizeHandler(...)` returns a raw authorization endpoint.
- `router.registerOAuth2(config)` mounts the token endpoint at `/oauth/token`.
- `router.registerOAuth2AuthorizationCode(...)` mounts raw authorization-code
  endpoints.
- `requireOAuth2BearerAuth(request, config, scopes)` validates a request in place.
- `oauth2(handler, config, scopes)` wraps a raw handler.
- `withOAuth2(config, scopes):` rewrites raw Mummy route registrations in a block.

## `sarcophagus/security/secret_hashing`

`sarcophagus/security/secret_hashing` uses BearSSL to provide generic secret
hashing. The default policy is PBKDF2-HMAC-SHA256 for human-chosen passwords and
other potentially weak secrets. A fast HMAC-SHA256 policy is also available for
high-entropy machine secrets such as generated OAuth client secrets.

PBKDF2 hashes are stored as:

```text
pbkdf2-sha256$iterations$saltHex$digestHex
```

Fast machine-secret hashes are stored as:

```text
hmac-sha256$saltHex$digestHex
```

Typical use:

```nim
import sarcophagus/security/secret_hashing

let storedHash = hashSecret("client-secret")

doAssert verifySecret("client-secret", storedHash)
doAssert not verifySecret("wrong-secret", storedHash)
```

For generated machine credentials, opt into fast hashing:

```nim
let policy = fastSecretHashPolicy()
let storedHash = hashSecret(randomSecret(), policy)
```

Use `needsSecretRehash` after successful verification when you raise iteration
counts or salt sizes:

```nim
if verifySecret(candidateSecret, storedHash):
  if needsSecretRehash(storedHash):
    let upgradedHash = hashSecret(candidateSecret)
    discard upgradedHash # persist this over the old hash
```

Custom policies let an application tune generation and accepted legacy bounds:

```nim
let policy = SecretHashPolicy(
  algorithm: secretHashPbkdf2Sha256,
  prefix: SecretHashPrefix,
  iterations: 750_000,
  minIterations: SecretHashMinIterations,
  maxIterations: SecretHashMaxIterations,
  saltBytes: SecretHashSaltBytes,
)

let storedHash = hashSecret("client-secret", policy)
doAssert verifySecret("client-secret", storedHash, policy)
```

## `sarcophagus/oauth2/hashed_clients`

`sarcophagus/oauth2/hashed_clients` adds reusable OAuth2 client
credential plumbing for applications that store hashed client secrets instead of
plaintext secrets. Storage is callback-based, so an application can back it with
SQLite, Postgres, flat files, or another store.

The older `sarcophagus/security/oauth2_hashed_clients` import path remains as a
compatibility facade.

For setup tools, seed a client and persist the resulting `HashedOAuth2Client`:

```nim
import sarcophagus/oauth2/hashed_clients

let credentials = seedHashedOAuth2Client(
  proc(client: HashedOAuth2Client) {.gcsafe.} =
    persistClient(client), # application-owned storage
  clientId = "reader-app",
  scopes = ["items:read", "items:write"],
  defaultScopes = ["items:read"],
)

echo credentials.clientId
echo credentials.clientSecret # show once to the operator
```

At runtime, mount a token endpoint using a loader callback:

```nim
router.registerHashedOAuth2(
  oauthConfig,
  proc(clientId: string): Option[HashedOAuth2Client] {.gcsafe.} =
    loadClientFromDb(clientId),
)
```

Typed API routers support the same endpoint registration:

```nim
api.registerHashedOAuth2(
  oauthConfig,
  proc(clientId: string): Option[HashedOAuth2Client] {.gcsafe.} =
    loadClientFromDb(clientId),
)
```

The token endpoint verifies `client_secret` with `verifySecret`, rejects disabled
clients, mints the same Sarcophagus bearer tokens as `sarcophagus/oauth2`, and
can emit best-effort audit events through `onAudit`.

For generated OAuth client secrets, use `fastSecretHashPolicy()` when seeding and
when registering the token endpoint:

```nim
let policy = fastSecretHashPolicy()

discard seedHashedOAuth2Client(
  persistClient,
  clientId = "reader-app",
  scopes = ["items:read"],
  policy = policy,
)

router.registerHashedOAuth2(
  oauthConfig,
  loadClientFromDb,
  policy = policy,
)
```

Existing PBKDF2 client hashes still verify under the fast policy because the
stored prefix selects the verification algorithm. `needsSecretRehash` returns
true for those legacy hashes so they can be rotated to the fast format.

## `sarcophagus/core/jwt_bearer_tokens`

The bearer-token module mints and validates signed HS256 JWT bearer tokens. OAuth2
uses this module internally, but it is also usable directly for service-to-service
tokens.

```nim
let config = initBearerTokenConfig(
  issuer = "example-server",
  audience = "example-api",
  keys = [SigningKey(kid: "v1", secret: "change-me")],
)

let token = mintBearerToken(
  config,
  initBearerTokenSpec(
    subject = "worker-1",
    scopes = ["jobs:read"],
    ttlSeconds = 300,
  ),
)

let validation = validateBearerToken(config, token, requiredScopes = ["jobs:read"])
doAssert validation.ok
```

Important helpers:

- `parseScopeList` accepts space, comma, tab, and newline separated scopes.
- `scopeListToString` normalizes scopes for token claims.
- `hasAllScopes` checks whether a token satisfies required scopes.
- `parseSigningKeys` parses `kid:secret,kid2:secret2` strings for configuration.

Use stable `kid` values and rotate by adding new keys, changing `activeKid`, then
removing retired keys after issued tokens expire.

## Development

Use Atlas for dependencies:

```sh
atlas install
nim test
```

Run a single test with:

```sh
nim r tests/ttapis.nim
```
