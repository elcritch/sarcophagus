# Sarcophagus

Sarcophagus is a higher-level API layer for [Mummy](https://github.com/guzba/mummy).
Its TAPIS modules turn typed Nim procs into HTTP handlers, JSON/CBOR codecs,
OpenAPI route metadata, and OAuth2-protected endpoints.

## First Example: Secure TAPIS Goto Service

The most complete example is `examples/tapis_secure`. It builds a small "goto"
service with:

- flat FastAPI-style handler parameters
- `tapi` proc pragmas for route metadata
- scoped OAuth2 security around groups of routes
- generated `/swagger.json`
- typed JSON error responses

Run it with:

```sh
atlas install
nim c -r examples/tapis_secure/runner.nim
```

The server is defined by annotating ordinary Nim procs:

```nim
import std/[json, options]

import mummy

import sarcophagus/[core/jwt_bearer_tokens, core/oauth2, tapis]

type
  Goto = object
    slug*: string
    url*: string
    title*: string
    visits*: int

proc resolveGoto(slug: string, preview: Option[bool]): Goto {.
  gcsafe, tapi(get, "/go/@slug", summary = "Resolve a goto slug", tags = ["goto"])
.} =
  # `slug` comes from the path. `preview` comes from the query string.
  Goto(slug: slug, url: "https://example.test", title: "Example", visits: 1)
```

Registration uses `api.add` and can be scoped:

```nim
let authConfig = oauthConfig()
let readSecurity = oauth2(authConfig, ["goto:read"])
let writeSecurity = oauth2(authConfig, ["goto:write"])

let api = initApiRouter("Sarcophagus TAPIS Secure Goto Example", "1.0.0")

api.registerOAuth2(authConfig)
api.add(resolveGoto)
withSecurity(api, readSecurity):
  api.add(listGotos)
  api.add(inspectGoto)
  withSecurity(api, writeSecurity):
    api.add(saveGoto)
    api.add(deleteGoto)

api.mountOpenApi()
newServer(api.router).serve(Port(9083), address = "127.0.0.1")
```

`registerOAuth2` mounts the standard client-credentials token endpoint using the
OAuth2 helper from `sarcophagus/oauth2`:

```nim
api.registerOAuth2(authConfig)
```

## `sarcophagus/tapis`

`sarcophagus/tapis` is the typed API layer. It exports the TAPIS router, typed
encoding/decoding helpers, OpenAPI helpers, and TAPIS security helpers.

Core pieces:

- `initApiRouter(title, version, config)` creates a typed Mummy router wrapper.
- `tapi(method, path, ...)` marks a proc as an API endpoint.
- `api.add(handler)` registers a `tapi`-annotated proc.
- `api.registerOAuth2(config)` mounts the standard `/oauth/token` endpoint.
- `api.mountOpenApi()` mounts `/swagger.json`.
- `ApiResponse[T]` lets a handler set status codes and headers.
- `raiseApiError(status, message, code, details)` produces structured error JSON.

Flat handler style keeps simple APIs concise:

```nim
proc readItem(id: int, verbose: Option[bool]): ItemOut {.
  gcsafe, tapi(get, "/items/@id", summary = "Read item")
.} =
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

proc listItems(params: Params[ListItemsParams]): ItemList {.
  gcsafe, tapi(get, "/items", summary = "List items")
.} =
  discard
```

For request bodies, `post`, `put`, and `patch` decode the body into the single
handler input type:

```nim
type CreateItemBody = object
  name*: string
  count*: int

proc createItem(body: CreateItemBody): ApiResponse[ItemOut] {.
  gcsafe, tapi(post, "/items", summary = "Create item", responseStatus = 201)
.} =
  apiResponse(ItemOut(name: body.name, count: body.count), statusCode = 201)
```

Use `ApiRequest[Params, Body]` when a route needs both path/query parameters and
a request body:

```nim
type ItemPath = object
  id*: int

proc updateItem(input: ApiRequest[ItemPath, CreateItemBody]): ItemOut {.
  gcsafe, tapi(put, "/items/@id", summary = "Update item")
.} =
  ItemOut(id: input.params.id, name: input.body.name, count: input.body.count)
```

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

If a route only needs a valid bearer token and does not require specific scopes,
omit the scope list:

```nim
type UserInfo = object
  status*: string
  message*: string

proc health(): HealthResponse {.
  gcsafe, tapi(get, "/health", summary = "Health check", tags = ["system"])
.} =
  HealthResponse(status: "ok")

proc currentUser(): UserInfo {.
  gcsafe, tapi(get, "/me", summary = "Current authenticated user", tags = ["users"])
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

## `sarcophagus/core/oauth2` And `sarcophagus/oauth2`

`sarcophagus/core/oauth2` is the protocol core. It implements the client
credentials grant and resource-server validation over Sarcophagus bearer tokens.

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

`sarcophagus/oauth2` contains Mummy-oriented helpers for non-TAPIS handlers:

- `oauth2TokenHandler(config)` returns a raw Mummy token endpoint handler.
- `registerOAuth2(router, config)` mounts that token endpoint at `/oauth/token`.
- `requireOAuth2BearerAuth(request, config, scopes)` validates a request in place.
- `oauth2(handler, config, scopes)` wraps a raw handler.
- `withOAuth2(config, scopes):` rewrites raw Mummy route registrations in a block.

For TAPIS routes, prefer `security = oauth2(...)` or `withSecurity(...)` so
OpenAPI metadata stays in sync with runtime enforcement.

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
