# User Login And API Token Security

Sarcophagus supports two separate authentication surfaces:

- Web pages use an application-owned login session, usually an `HttpOnly` cookie.
- JSON endpoints use OAuth2 bearer access tokens in the `Authorization` header.

Keep those surfaces separate. A route under `/api` should require
`Authorization: Bearer ...` even when the request also has a browser session
cookie. This avoids accidental cookie authentication and keeps CSRF protections
focused on browser form/page flows.

## OAuth2 Authorization Code Flow

User login support is added with the OAuth2 authorization-code flow and PKCE:

1. The application authenticates a browser user with its own login page.
2. A client sends the browser to `/oauth/authorize`.
3. The authorization endpoint uses a callback to read the current logged-in user.
4. Sarcophagus validates `client_id`, `redirect_uri`, scopes, and PKCE fields.
5. Sarcophagus stores a short-lived authorization code through an application
   callback.
6. The browser is redirected to the client's `redirect_uri` with `code` and
   optional `state`.
7. The client exchanges the code at `/oauth/token`.
8. JSON endpoints continue to use `oauth2(config, scopes)` and validate the
   returned bearer token.

## Client Setup

Register clients with explicit redirect URIs:

```nim
let oauthConfig = initOAuth2Config(
  realm = "app",
  tokenConfig = tokenConfig,
  clients = [
    initOAuth2Client(
      clientId = "browser-client",
      clientSecret = "",
      allowedScopes = ["items:read", "items:write"],
      defaultScopes = ["items:read"],
      redirectUris = ["https://client.example/callback"],
      requirePkce = true,
    )
  ],
)
```

Use an empty `clientSecret` for public clients. Confidential clients may keep a
secret and authenticate at `/oauth/token` with HTTP Basic or request-body client
credentials.

## Authorization Code Storage

Production applications should provide durable, concurrency-safe callbacks:

```nim
let saveCode: OAuth2AuthorizationCodeSaver =
  proc(code: OAuth2AuthorizationCode) {.gcsafe.} =
    # Persist code by code.code with its expiry.
    discard

let consumeCode: OAuth2AuthorizationCodeConsumer =
  proc(code: string): Option[OAuth2AuthorizationCode] {.gcsafe.} =
    # Atomically fetch and mark the code as consumed.
    none(OAuth2AuthorizationCode)
```

`consumeCode` must be atomic. A code is single-use, so two concurrent exchanges
must not both receive the same active code.

For tests and examples, Sarcophagus provides `newInMemoryOAuth2AuthorizationCodeStore`.

## Current User Callback

The authorization endpoint does not own your login system. It asks the
application for the currently logged-in user:

```nim
let currentUser: OAuth2CurrentUserLoader =
  proc(headers: ApiHeaders): Option[OAuth2User] {.gcsafe.} =
    let session = loadSessionFromCookie(headers.cookieValue("app_session"))
    if session.isNone:
      return none(OAuth2User)
    some(OAuth2User(subject: session.get.userId, scopes: @["items:read"]))
```

If the callback returns `none`, the authorization endpoint redirects to the
configured login URL.

## Route Registration

Register the browser authorization endpoint and an extended token endpoint on the
typed API router:

```nim
api.registerOAuth2AuthorizationCode(
  oauthConfig,
  saveCode,
  consumeCode,
  currentUser,
  loginUrl = "/login",
)
```

Plain Mummy applications use the same overload on a `Router`:

```nim
router.registerOAuth2AuthorizationCode(
  oauthConfig,
  saveCode,
  consumeCode,
  currentUser,
  loginUrl = "/login",
)
```

Protect HTML pages with your session middleware:

```nim
router.get("/dashboard", sessionAuth(dashboardHandler, sessionConfig))
```

Protect JSON endpoints with bearer tokens:

```nim
router.get("/api/items", oauth2(listItems, oauthConfig, ["items:read"]))
router.post("/api/items", oauth2(createItem, oauthConfig, ["items:write"]))
```

Existing client-credentials clients can keep using `/oauth/token`:

```text
grant_type=client_credentials&scope=items:read
```

Authorization-code clients exchange:

```text
grant_type=authorization_code
code=...
redirect_uri=https://client.example/callback
client_id=browser-client
code_verifier=...
```

## OpenAPI

For machine-to-machine APIs, keep the existing client-credentials security:

```nim
security = oauth2(oauthConfig, ["items:read"])
```

For browser/user-login APIs, emit authorization-code metadata:

```nim
security = oauth2AuthorizationCode(oauthConfig, ["items:read"])
```

The runtime enforcement is the same: API routes still validate bearer access
tokens. The OpenAPI flow only tells clients how to obtain those tokens.

## Security Defaults

- Use exact `redirect_uri` matching.
- Require PKCE for public clients.
- Prefer `code_challenge_method=S256`.
- Keep authorization codes short-lived, usually 60-300 seconds.
- Store authorization codes server-side and consume them atomically.
- Mark session cookies `HttpOnly`, `Secure`, and `SameSite=Lax` or stricter.
- Keep JSON endpoints bearer-token only.
