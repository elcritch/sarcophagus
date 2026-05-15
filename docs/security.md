# Security Guide

Sarcophagus supports several security-related building blocks:

- OAuth2 bearer-token APIs
- OAuth2 authorization-code login for browser clients
- hashed OAuth2 client secrets
- signed cookies
- browser login sessions
- password-based login session minting
- request IDs and tracing headers

This guide explains how those pieces fit together and how to use them safely.

## What This Guide Covers

- protecting machine APIs with OAuth2 bearer tokens
- safely wiring browser login flows
- using signed cookies and session cookies correctly
- separating browser auth from API auth
- handling secrets, tracing, rate limits, and common mistakes

## Security Model

Sarcophagus is designed around two distinct request types:

1. Browser page or form requests, which usually authenticate with an
   `HttpOnly` cookie.
2. API requests, which usually authenticate with `Authorization: Bearer ...`.

Keep those surfaces separate.

- Use cookies for browser login state.
- Use bearer tokens for JSON APIs.
- Do not silently treat a browser session cookie as API authentication unless
  you have deliberately built a cookie-authenticated API and handled CSRF.

That separation avoids accidental cookie auth on machine APIs and keeps CSRF
defenses focused on browser flows.

If you are unsure which model to use:

- use OAuth2 bearer tokens for CLI, mobile, service, and SPA API calls
- use `HttpOnly` cookies for browser page/session state
- only mix the two when you have deliberately designed the boundary

## Practical Checklist

- Serve authentication, cookies, and OAuth2 endpoints only over HTTPS.
- Use strong signing secrets and rotate them deliberately.
- Keep access tokens and authorization codes short-lived.
- Use exact redirect URI matching.
- Require PKCE for public/browser clients.
- Mark browser login cookies `HttpOnly` and `Secure`.
- Use `SameSite=Lax` by default for browser session cookies.
- Hash stored client secrets and passwords; do not persist plaintext secrets.
- Prefer bearer auth for APIs and cookie auth for browser pages.
- Add request IDs or `traceparent` propagation for auditability.
- Be conservative with CORS, especially when credentials are enabled.

## OAuth2 Overview

Sarcophagus uses signed HS256 JWT bearer tokens internally. OAuth2 support is
split across:

- `sarcophagus/oauth2/core` for token issuance and validation logic
- `sarcophagus/oauth2/mummy_support` for raw Mummy handlers
- `sarcophagus/tapis` and `sarcophagus/tapis_security` for typed TAPIS routes

Typical setup starts with a bearer-token config and an OAuth2 config:

```nim
import sarcophagus/oauth2

let tokenConfig = initBearerTokenConfig(
  issuer = "example-server",
  audience = "example-api",
  keys = [SigningKey(kid: "v1", secret: "replace-with-a-strong-secret")],
)

let oauthConfig = initOAuth2Config(
  realm = "example",
  tokenConfig = tokenConfig,
  clients = [
    initOAuth2Client(
      clientId = "example-cli",
      clientSecret = "replace-this-too",
      allowedScopes = ["items:read", "items:write"],
      defaultScopes = ["items:read"],
    )
  ],
)
```

## Secure OAuth2 For APIs

For machine-to-machine APIs, use bearer tokens and scope checks.

Typed TAPIS routes:

```nim
import sarcophagus/tapis

let api = initApiRouter("Items API", "1.0.0")
api.registerOAuth2(oauthConfig)

api.get(
  "/items/@id",
  readItem,
  summary = "Read item",
  security = oauth2(oauthConfig, ["items:read"]),
)

api.post(
  "/items",
  createItem,
  summary = "Create item",
  responseStatus = 201,
  security = oauth2(oauthConfig, ["items:write"]),
)
```

Route groups:

```nim
withSecurity(api, oauth2(oauthConfig, ["items:read"])):
  api.add(readItem)
  api.add(listItems)
```

Raw Mummy handlers:

```nim
import mummy
import mummy/routers
import sarcophagus/oauth2

var router: Router
router.registerOAuth2(oauthConfig)
router.get("/items", oauth2(listItems, oauthConfig, ["items:read"]))
```

Use narrow scopes, not one broad `"admin"` scope for everything.

## OAuth2 Client Credentials

Client-credentials flow is the default fit for service-to-service access.

Guidance:

- Use generated secrets, not human-chosen ones.
- Store hashed client secrets, not plaintext.
- Keep scopes narrow and default scopes minimal.
- Rotate secrets by issuing a replacement and expiring the old one.

If you are storing client records yourself, prefer hashed clients:

```nim
import std/options
import sarcophagus/oauth2/hashed_clients

let policy = fastSecretHashPolicy()

discard seedHashedOAuth2Client(
  proc(client: HashedOAuth2Client) {.gcsafe.} =
    persistClient(client),
  clientId = "reader-app",
  scopes = ["items:read"],
  policy = policy,
)

api.registerHashedOAuth2(
  oauthConfig,
  proc(clientId: string): Option[HashedOAuth2Client] {.gcsafe.} =
    loadClient(clientId),
  policy = policy,
)
```

Use `fastSecretHashPolicy()` for generated machine secrets. Use the default
PBKDF2 policy for human passwords.

## OAuth2 Authorization Code For Browser Clients

Use authorization-code plus PKCE when a browser or public client needs to log a
user in and obtain API bearer tokens.

Browser flow:

1. Your application authenticates the browser user with its own login system.
2. The browser is sent to `/oauth/authorize`.
3. Sarcophagus loads the current user through your callback.
4. Sarcophagus validates client, redirect URI, scopes, and PKCE.
5. Sarcophagus issues a short-lived authorization code.
6. The client exchanges the code at `/oauth/token`.
7. The client uses the returned bearer token for API calls.

Client setup:

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

Use an empty secret for public clients. Require PKCE. Prefer
`code_challenge_method=S256`.

Authorization-code registration on TAPIS:

```nim
api.registerOAuth2AuthorizationCode(
  oauthConfig,
  saveCode,
  consumeCode,
  currentUser,
  loginUrl = "/login",
)
```

Your callbacks must be safe:

- `saveCode` should persist short-lived codes with expiry.
- `consumeCode` must atomically fetch and invalidate a code.
- `currentUser` should only return a user when your browser session is valid.

Current-user callback shape:

```nim
let currentUser: OAuth2CurrentUserLoader =
  proc(headers: ApiHeaders): Option[OAuth2User] {.gcsafe.} =
    let sessionToken = headers.headerCookieValue("app_session")
    let session = validatePasswordLoginSession(loginConfig, sessionToken)
    if not session.ok:
      return none(OAuth2User)

    some(
      OAuth2User(
        subject: session.session.subject,
        displayName: "Logged In User",
        scopes: session.session.scopes,
      )
    )
```

Operational guidance:

- Keep authorization codes short-lived, usually 60-300 seconds.
- Match redirect URIs exactly.
- Never skip PKCE for public clients.
- Keep browser login state separate from bearer-token API auth.
- Treat the authorization endpoint like part of your browser login surface:
  it should only succeed when the user already has a valid first-party session.

## Browser Login Example

The most common browser flow is:

1. verify username/password
2. set an `HttpOnly` session cookie
3. load the current user from that cookie on later requests
4. clear the cookie on logout

Example using `password_login` plus the browser-login helpers:

```nim
import std/options
import sarcophagus/tapis
import sarcophagus/security/[browser_login, password_login]

type
  LoginBody = object
    username*: string
    password*: string

  LoginResponse = object
    ok*: bool

  MeResponse = object
    subject*: string
    displayName*: string

let cookieConfig = initBrowserLoginCookieConfig("app_session")

proc loadUser(session: PasswordLoginSession): Option[PasswordLoginUser] {.gcsafe.} =
  loadUserBySubject(session.subject)

proc login(body: LoginBody): ApiResponse[LoginResponse] =
  let login = authenticateBrowserLogin(
    loginConfig,
    cookieConfig,
    verifier,
    username = body.username,
    password = body.password,
  )
  browserLoginResponse(login, LoginResponse(ok: true))

proc me(): MeResponse =
  let user = requireBrowserLoginUser()
  MeResponse(subject: user.subject, displayName: user.displayName)

proc logout(): ApiResponse[LoginResponse] =
  browserLogoutResponse(cookieConfig, LoginResponse(ok: true))

let api = initApiRouter("Browser App", "1.0.0")
api.post("/login", login)
api.get(
  "/me",
  me,
  middlewares = [
    browserLoginMiddleware(
      loginConfig,
      cookieConfig,
      required = true,
      loadUser = loadUser,
    )
  ],
)
api.post("/logout", logout)
```

This pattern keeps the browser cookie as a transport for a signed login token.
The token is already integrity-protected by `password_login`; the cookie
attributes make browser handling safer. The middleware validates the session
cookie before the handler runs and exposes the current session through
`currentBrowserLoginSession()`, `requireBrowserLoginSession()`,
`currentBrowserLoginUser()`, and `requireBrowserLoginUser()`.

## Signed Cookies

Signed cookies protect integrity, not secrecy.

A signed cookie value is still visible to the browser, but the browser cannot
change it without invalidating the signature.

That means:

- good for session identifiers and low-sensitivity state
- not appropriate for storing secrets in plaintext
- do not confuse signing with encryption

Basic signing:

```nim
import sarcophagus/cookies

let config = initSignedCookieConfig("replace-with-a-strong-secret")
let signed = signCookieValue("session", "user-123", config)

doAssert verifySignedCookieValue("session", signed, config).get() == "user-123"
```

Signed `Set-Cookie` header:

```nim
let header = signedCookieHeader(
  "session",
  "user-123",
  initSignedCookieConfig("replace-with-a-strong-secret"),
)
```

## Cookie Attributes And Safe Defaults

Sarcophagus cookie helpers default to browser-session-friendly values:

- `Path=/`
- `Secure=true`
- `HttpOnly=true`
- `SameSite=Lax`

These defaults are good for most first-party login sessions.

Example:

```nim
let options = cookieOptions(
  path = "/",
  secure = true,
  httpOnly = true,
  sameSite = cookieSameSiteLax,
)

let header = setCookieHeader("theme", "moss", options)
```

Notes:

- `HttpOnly` prevents frontend JavaScript from reading the cookie.
- `Secure` means the cookie is only sent over HTTPS.
- `SameSite=Lax` reduces CSRF risk for normal browser navigation flows.
- `SameSite=None` requires `Secure=true` and should only be used deliberately.

## Browser User Logins

There are two common browser-login patterns.

### Pattern 1: Signed Opaque Session Cookie

Store a short session identifier or user reference in a signed cookie and load
server-side state on each request.

This is good when you want explicit server-side logout or revocation.

```nim
let sessionConfig = initSessionCookieConfig(
  "sid",
  "replace-with-a-strong-secret",
  ttlSeconds = 3600,
)

let setCookie = sessionCookieHeader("session-123", sessionConfig)
```

Later:

```nim
let sessionId = request.requestSessionValue(sessionConfig)
if sessionId.isSome():
  let currentUser = loadUserForSession(sessionId.get())
```

### Pattern 2: Signed Login Token Stored In A Cookie

`sarcophagus/security/password_login` already mints a signed login session token.
You can transport that token in an `HttpOnly` cookie.

That looks like:

```nim
import sarcophagus/security/[browser_login, password_login]

let cookieConfig = initBrowserLoginCookieConfig("app_session")

let login = authenticateBrowserLogin(
  loginConfig,
  cookieConfig,
  verifier,
  username = body.username,
  password = body.password,
)

let response = browserLoginResponse(login, LoginResponse(ok: true))
```

Later:

```nim
let session = requireBrowserLoginSession()
echo session.subject
```

This works because the `password_login` token is already signed. In that case,
the cookie is a transport container, not the thing providing integrity.

### Signed Session Cookie vs Password Login Token

These are related but not the same:

- `sessionCookieHeader(...)` signs a cookie value directly
- `authenticatePasswordLogin(...)` mints a signed login token you can carry in a cookie
- `authenticateBrowserLogin(...)` wraps that login result and attaches the cookie header

Do not stack both unless you have a specific reason. Most applications should
pick one:

- signed opaque cookie for server-managed session IDs
- password-login token in cookie for stateless browser sessions

## Which Login Pattern Should You Use?

Use a signed opaque cookie when:

- you want a simple browser session ID
- you expect to look up session state server-side
- you want easier revocation or forced logout

Use `password_login` session tokens in cookies when:

- you want stateless signed browser sessions
- you already use `PasswordLoginConfig`
- you are comfortable validating the token on each request

If you need immediate revocation for all sessions without waiting for expiry,
server-side session storage is usually the better fit.

## Password Login Guidance

`sarcophagus/security/password_login` is a login-session primitive, not a full
UI flow. It verifies credentials, mints signed session tokens, and validates
them later.

Safe usage pattern:

1. Verify credentials with `authenticateBrowserLogin`.
2. Return `browserLoginResponse` to set the `HttpOnly` cookie.
3. Add `browserLoginMiddleware` to browser-authenticated routes.
4. Load the current session with `requireBrowserLoginSession`.
5. Return `browserLogoutResponse` to clear the cookie on logout.

Use the default PBKDF2-based secret hashing for human passwords.

```nim
let policy = defaultSecretHashPolicy()
let account = seedPasswordLoginAccount(
  username = "alice",
  password = "correct horse battery staple",
  policy = policy,
)
```

Do not use `fastSecretHashPolicy()` for human-chosen passwords.

### Rate Limits, MFA, And Audit Context

`password_login` can enforce more than basic username/password checks. The
request-aware verifier path lets you attach IP, user-agent, request ID, tenant,
and custom metadata before deciding whether to allow, deny, rate-limit, or
require MFA.

```nim
let context = passwordLoginContext(
  remoteAddress = forwardedForOrRemoteIp,
  userAgent = request.headers["User-Agent"],
  requestId = currentRequestId(),
)

let result = authenticatePasswordLogin(
  loginConfig,
  decisionVerifier,
  context,
  username = body.username,
  password = body.password,
)
```

Use this path when you need:

- per-user or per-IP login throttling
- tenant-aware login policy
- audit trails tied to request IDs
- staged authentication flows such as MFA

## CORS And Cookies

Cookie-authenticated browser requests and CORS need extra care.

If you allow cross-origin credentialed requests:

- do not use `allowedOrigins = ["*"]`
- explicitly list trusted origins
- set `allowCredentials = true`
- understand that cookies reintroduce CSRF concerns

Example:

```nim
api.useCors(
  corsConfig(
    allowedOrigins = ["https://app.example"],
    allowCredentials = true,
    allowedHeaders = ["Content-Type", "Authorization"],
  )
)
```

For most API clients, bearer tokens are a better fit than cross-site cookies.

## CSRF Guidance

If a browser automatically sends a credential cookie, cross-site request forgery
becomes relevant.

Baseline guidance:

- keep browser sessions on `SameSite=Lax` unless cross-site behavior is required
- prefer bearer tokens over cookies for cross-origin API requests
- require explicit CSRF defenses if you use `SameSite=None` or credentialed CORS
- do not assume CORS alone protects state-changing browser requests

Common mitigations include:

- synchronizer CSRF tokens
- double-submit CSRF cookies
- strict `Origin` / `Referer` validation on sensitive POST routes

## Request IDs And Auditability

Use TAPIS request identity support on security-sensitive services:

```nim
api.useRequestIdentity()
```

That propagates:

- `X-Request-ID`
- `traceparent`

and includes them in TAPIS request and error logs. This is useful for incident
response, login audit trails, and correlating browser, API, and upstream proxy
logs.

## Secret Management

Treat the following as secrets:

- JWT signing keys
- OAuth2 client secrets
- signed-cookie secrets
- password-login signing keys

Guidance:

- load them from environment variables or a secret manager
- do not commit them to source control
- use separate secrets for separate concerns
- rotate by introducing a new key, moving traffic, then retiring the old one
- version keys deliberately and keep old verification keys around long enough
  for in-flight sessions or tokens to expire cleanly

Avoid reusing one secret string for JWTs, cookies, and client-secret hashing.

## Common Mistakes

- Using cookies to authenticate JSON APIs without thinking about CSRF.
- Storing plaintext secrets in signed cookies.
- Using `SameSite=None` without understanding the cross-site impact.
- Letting browser login cookies silently authorize `/api` routes.
- Storing plaintext OAuth client secrets in the database.
- Using fast secret hashing for user passwords.
- Using long-lived authorization codes or access tokens.
- Forgetting PKCE for public clients.
- Using broad wildcard CORS with credentials.

## Suggested Production Baseline

- `api.useRequestIdentity()` on internet-facing services
- conservative `api.useCors(...)` configuration, or none unless needed
- exact OAuth2 redirect URIs and PKCE for public clients
- hashed OAuth2 client secrets in persistent storage
- `HttpOnly`, `Secure`, `SameSite=Lax` browser session cookies
- short-lived auth codes and access tokens
- explicit logout that clears the cookie and, if applicable, invalidates
  server-side session state
- log redaction for cookies, bearer tokens, and client secrets

## Related APIs

- `sarcophagus/tapis`
- `sarcophagus/tapis_security`
- `sarcophagus/oauth2`
- `sarcophagus/oauth2/hashed_clients`
- `sarcophagus/security/browser_login`
- `sarcophagus/security/password_login`
- `sarcophagus/security/secret_hashing`
- `sarcophagus/cookies`
