import std/[json, options, times]

import mummy

import ../cookies
import ../core/[tapis_runtime, typed_api]
import ../core/jwt_bearer_tokens
import ./password_login

type
  BrowserLoginCookieConfig* = object
    cookieName*: string
    options*: CookieOptions

  BrowserLoginResult* = object
    login*: PasswordLoginResult
    setCookie*: Option[ApiHeader]

  PasswordLoginSessionUserLoader* =
    proc(session: PasswordLoginSession): Option[PasswordLoginUser] {.gcsafe.}

var activeBrowserLoginSession {.threadvar.}: Option[PasswordLoginSession]
var activeBrowserLoginUser {.threadvar.}: Option[PasswordLoginUser]

proc initBrowserLoginCookieConfig*(
    cookieName = "app_session",
    path = "/",
    domain = "",
    secure = true,
    httpOnly = true,
    sameSite = cookieSameSiteLax,
): BrowserLoginCookieConfig =
  if cookieName.len == 0:
    raise newException(ValueError, "browser login cookie name must not be empty")

  BrowserLoginCookieConfig(
    cookieName: cookieName,
    options: cookieOptions(
      path = path,
      domain = domain,
      secure = secure,
      httpOnly = httpOnly,
      sameSite = sameSite,
    ),
  )

proc currentBrowserLoginSession*(): Option[PasswordLoginSession] =
  activeBrowserLoginSession

proc currentBrowserLoginUser*(): Option[PasswordLoginUser] =
  activeBrowserLoginUser

proc clearCurrentBrowserLoginState() =
  activeBrowserLoginSession = none(PasswordLoginSession)
  activeBrowserLoginUser = none(PasswordLoginUser)

proc requireBrowserLoginSession*(): PasswordLoginSession =
  let session = currentBrowserLoginSession()
  if session.isNone():
    raiseApiError(401, "Not logged in", "not_logged_in")
  session.get()

proc requireBrowserLoginUser*(): PasswordLoginUser =
  let user = currentBrowserLoginUser()
  if user.isNone():
    raiseApiError(401, "Not logged in", "not_logged_in")
  user.get()

proc browserLoginCookieHeader*(
    login: PasswordLoginResult, config: BrowserLoginCookieConfig, now = nowUnix()
): ApiHeader =
  if not login.ok:
    raise
      newException(ValueError, "cannot create browser login cookie for failed login")

  var options = config.options
  let ttlSeconds = max(0'i64, login.expiresAt - now).int
  options.maxAgeSeconds = some(ttlSeconds)
  options.expiresAt = some(fromUnix(login.expiresAt))
  setCookieHeader(config.cookieName, login.sessionToken, options)

proc clearBrowserLoginCookieHeader*(config: BrowserLoginCookieConfig): ApiHeader =
  clearCookieHeader(config.cookieName, config.options)

proc authenticateBrowserLogin*(
    config: PasswordLoginConfig,
    cookieConfig: BrowserLoginCookieConfig,
    verifyCredentials: PasswordLoginDecisionVerifier,
    username, password: string,
    context = passwordLoginContext(),
    now = nowUnix(),
): BrowserLoginResult =
  result.login = authenticatePasswordLogin(
    config, verifyCredentials, username, password, context, now
  )
  if result.login.ok:
    result.setCookie = some(browserLoginCookieHeader(result.login, cookieConfig, now))

proc authenticateBrowserLogin*(
    config: PasswordLoginConfig,
    cookieConfig: BrowserLoginCookieConfig,
    verifyCredentials: PasswordLoginVerifier,
    username, password: string,
    now = nowUnix(),
): BrowserLoginResult =
  result.login =
    authenticatePasswordLogin(config, verifyCredentials, username, password, now)
  if result.login.ok:
    result.setCookie = some(browserLoginCookieHeader(result.login, cookieConfig, now))

proc browserLoginResponse*[T](
    login: BrowserLoginResult,
    body: sink T,
    statusCode = 200,
    headers: openArray[ApiHeader] = [],
): ApiResponse[T] =
  if not login.login.ok:
    raiseApiError(
      login.login.failure.statusCode, login.login.failure.message,
      login.login.failure.code,
    )

  result = apiResponse(body, statusCode = statusCode, headers = headers)
  if login.setCookie.isSome():
    result.headers.add(login.setCookie.get())

proc browserLogoutResponse*[T](
    config: BrowserLoginCookieConfig,
    body: sink T,
    statusCode = 200,
    headers: openArray[ApiHeader] = [],
): ApiResponse[T] =
  result = apiResponse(body, statusCode = statusCode, headers = headers)
  result.headers.add(clearBrowserLoginCookieHeader(config))

proc requestBrowserLoginSession*(
    request: Request,
    loginConfig: PasswordLoginConfig,
    cookieConfig: BrowserLoginCookieConfig,
    now = nowUnix(),
): PasswordLoginSessionResult =
  let sessionToken = request.requestCookieValue(cookieConfig.cookieName)
  if sessionToken.len == 0:
    return PasswordLoginSessionResult(
      ok: false,
      failure: PasswordLoginFailure(
        statusCode: 401, code: "not_logged_in", message: "Not logged in"
      ),
    )

  validatePasswordLoginSession(loginConfig, sessionToken, now)

proc requestBrowserLoginUser*(
    request: Request,
    loginConfig: PasswordLoginConfig,
    cookieConfig: BrowserLoginCookieConfig,
    loadUser: PasswordLoginSessionUserLoader,
    now = nowUnix(),
): Option[PasswordLoginUser] =
  let session = requestBrowserLoginSession(request, loginConfig, cookieConfig, now)
  if not session.ok:
    return none(PasswordLoginUser)
  loadUser(session.session)

proc loadCurrentBrowserLoginUser*(
    loadUser: PasswordLoginSessionUserLoader
): Option[PasswordLoginUser] =
  let cached = currentBrowserLoginUser()
  if cached.isSome():
    return cached

  let session = currentBrowserLoginSession()
  if session.isNone():
    return none(PasswordLoginUser)
  loadUser(session.get())

proc browserLoginFailureBody(
    failure: PasswordLoginFailure, config: ApiConfig
): JsonNode =
  apiErrorBody(newApiError(failure.statusCode, failure.message, failure.code), config)

proc browserLoginFailure(statusCode: int, code, message: string): PasswordLoginFailure =
  PasswordLoginFailure(statusCode: statusCode, code: code, message: message)

proc respondBrowserLoginFailure(
    context: RouteContext,
    failure: PasswordLoginFailure,
    clearCookie: Option[ApiHeader] = none(ApiHeader),
) =
  let format = responseFormat(context.request.headers["Accept"], context.config)
  var headers = context.responseHeaders
  headers["Content-Type"] = formatContentType(format)
  if clearCookie.isSome():
    headers.toBase.add(clearCookie.get())

  let body = encodeApi(browserLoginFailureBody(failure, context.config), format)
  context.responseStatus = failure.statusCode
  if context.request.httpMethod == "HEAD":
    headers["Content-Length"] = $body.len
    context.request.respond(failure.statusCode, headers)
  else:
    context.request.respond(failure.statusCode, headers, body)

proc browserLoginMiddleware*(
    loginConfig: PasswordLoginConfig,
    cookieConfig: BrowserLoginCookieConfig = initBrowserLoginCookieConfig(),
    required = false,
    clearInvalidCookie = true,
    loadUser: PasswordLoginSessionUserLoader = nil,
): ApiMiddleware =
  result.name = "browserLogin"
  result.before = proc(context: RouteContext): ApiMiddlewareResult {.gcsafe.} =
    clearCurrentBrowserLoginState()

    let session = requestBrowserLoginSession(context.request, loginConfig, cookieConfig)
    if not session.ok:
      if required:
        let clearCookie =
          if clearInvalidCookie and session.failure.code != "not_logged_in":
            some(clearBrowserLoginCookieHeader(cookieConfig))
          else:
            none(ApiHeader)
        context.respondBrowserLoginFailure(session.failure, clearCookie)
        return amHandled
      if clearInvalidCookie and session.failure.code != "not_logged_in":
        context.setResponseHeader(
          clearBrowserLoginCookieHeader(cookieConfig).name,
          clearBrowserLoginCookieHeader(cookieConfig).value,
        )
      return amContinue

    activeBrowserLoginSession = some(session.session)
    if loadUser != nil:
      activeBrowserLoginUser = loadUser(session.session)
      if required and activeBrowserLoginUser.isNone():
        context.respondBrowserLoginFailure(
          browserLoginFailure(401, "not_logged_in", "Not logged in"),
          if clearInvalidCookie:
            some(clearBrowserLoginCookieHeader(cookieConfig))
          else:
            none(ApiHeader),
        )
        return amHandled
    amContinue
  result.after = proc(context: RouteContext) {.gcsafe.} =
    discard context
    clearCurrentBrowserLoginState()
