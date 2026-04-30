import std/unittest

import sarcophagus/logging

suite "logging facade":
  test "structured logging calls compile":
    let
      status = 200
      elapsedMs = 12.5

    trace "request trace", route = "/health", status = status
    debug "request debug", route = "/health", status
    info "request complete", route = "/health", status = status
    notice "request noticed", route = "/health", elapsedMs = elapsedMs
    warn "request slow", route = "/health", elapsedMs = elapsedMs
    error "request failed", route = "/health", status = 500
    fatal "server stopped", reason = "test"

    check true

  test "none backend does not evaluate fields":
    proc failIfEvaluated(): string =
      raise newException(AssertionDefect, "log field was evaluated")

    when sarcophagusLogBackend == "none":
      info "skipped", value = failIfEvaluated()

    check true
