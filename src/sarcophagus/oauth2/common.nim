import std/[options, strutils]

import ../core/typed_api
import ./core

export typed_api

type
  OAuth2User* = object
    ## Logged-in browser user returned by an application-owned session callback.
    subject*: string
    displayName*: string
    scopes*: seq[string]

  OAuth2CurrentUserLoader* = proc(headers: ApiHeaders): Option[OAuth2User] {.gcsafe.}
    ## Callback used by `/oauth/authorize` to read the current logged-in user.

  OAuth2TokenPayload* = object ## HTTP JSON body returned by OAuth2 token endpoints.
    access_token*: string
    token_type*: string
    expires_in*: int
    scope*: string

  OAuth2FailurePayload* = object ## OAuth2 error details serialized in error responses.
    error*: string
    error_description*: string
    error_uri*: string

  OAuth2ErrorResponse* = object ## JSON returned by OAuth2 error responses.
    status*: string
    error*: OAuth2FailurePayload

  OAuth2ApiError* = ApiResponse[OAuth2ErrorResponse]

  OAuth2ErrorResponder* = proc(failure: OAuth2Failure): OAuth2ApiError {.gcsafe.}
    ## Callback used to build OAuth2 error responses.

proc valueFor(values: ApiHeaders, name: string, caseInsensitive = false): string =
  for value in values:
    if value.name == name or (caseInsensitive and cmpIgnoreCase(value.name, name) == 0):
      return value.value

proc headerValue*(headers: ApiHeaders, name: string): string =
  ## Returns one header value from typed API headers.
  headers.valueFor(name, caseInsensitive = true)

proc cookieValue*(headers: ApiHeaders, name: string): string =
  ## Returns one Cookie header value from typed API headers.
  for part in headers.headerValue("Cookie").split(';'):
    let pieces = part.strip().split('=', maxsplit = 1)
    if pieces.len == 2 and pieces[0] == name:
      return pieces[1]

proc to*(
    response: OAuth2TokenResponse, tp: typedesc[OAuth2TokenPayload]
): OAuth2TokenPayload =
  OAuth2TokenPayload(
    access_token: response.accessToken,
    token_type: response.tokenType,
    expires_in: response.expiresIn,
    scope: response.scope,
  )

proc to*(
    failure: OAuth2Failure, tp: typedesc[OAuth2FailurePayload]
): OAuth2FailurePayload =
  OAuth2FailurePayload(
    error: failure.error,
    error_description: failure.errorDescription,
    error_uri: failure.errorUri,
  )

proc oauth2ErrorResponse*(
    statusCode: int, failure: OAuth2Failure, headers: ApiHeaders = @[]
): OAuth2ApiError =
  ## Builds a typed OAuth2 error response.
  apiResponse(
    OAuth2ErrorResponse(status: "error", error: failure.to(OAuth2FailurePayload)),
    statusCode,
    headers,
  )

proc oauth2MethodNotAllowedResponse*(allow: string): OAuth2ApiError =
  oauth2ErrorResponse(
    405, OAuth2Failure(statusCode: 405, error: "invalid_request"), @[("Allow", allow)]
  )

proc defaultOAuth2ErrorResponder*(failure: OAuth2Failure): OAuth2ApiError {.gcsafe.} =
  ## Builds the default JSON response for OAuth2 resource-server failures.
  var headers: ApiHeaders
  if failure.wwwAuthenticate.len > 0:
    headers.add(("WWW-Authenticate", failure.wwwAuthenticate))
  oauth2ErrorResponse(failure.statusCode, failure, headers)

proc defaultOAuth2TokenErrorResponder*(
    failure: OAuth2Failure
): OAuth2ApiError {.gcsafe.} =
  ## Builds the default JSON response for OAuth2 token endpoint failures.
  ##
  ## The response includes `Cache-Control: no-store` and `Pragma: no-cache`.
  var headers: ApiHeaders
  headers.add(("Cache-Control", "no-store"))
  headers.add(("Pragma", "no-cache"))
  if failure.wwwAuthenticate.len > 0:
    headers.add(("WWW-Authenticate", failure.wwwAuthenticate))
  oauth2ErrorResponse(failure.statusCode, failure, headers)

proc defaultOAuth2AuthorizeErrorResponder*(
    failure: OAuth2Failure
): OAuth2ApiError {.gcsafe.} =
  ## Builds the default JSON response for OAuth2 authorization endpoint failures.
  oauth2ErrorResponse(failure.statusCode, failure)
