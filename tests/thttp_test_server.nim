import std/[httpclient, net, unittest]

import mummy
import http_test_server

proc firstHandler(request: Request) {.gcsafe.} =
  request.respond(200, body = "first")

proc secondHandler(request: Request) {.gcsafe.} =
  request.respond(200, body = "second")

suite "HTTP test server ports":
  test "concurrent servers reserve distinct ports across repeated startups":
    # Keep another listener alive throughout startup, as on a busy CI runner.
    let occupied = newSocket()
    defer:
      occupied.close()
    occupied.bindAddr(Port(0), "127.0.0.1")
    occupied.listen()
    let occupiedPort = occupied.getLocalAddr()[1]

    for iteration in 0 ..< 10:
      let first = newServer(firstHandler, workerThreads = 1)
      var firstThread: Thread[ServerThreadArgs]
      createThread(
        firstThread, serveServer, ServerThreadArgs(server: first, address: "127.0.0.1")
      )
      defer:
        first.close()
        joinThread(firstThread)
      let firstPort = first.testPort()

      let second = newServer(secondHandler, workerThreads = 1)
      var secondThread: Thread[ServerThreadArgs]
      createThread(
        secondThread,
        serveServer,
        ServerThreadArgs(server: second, address: "127.0.0.1"),
      )
      defer:
        second.close()
        joinThread(secondThread)
      let secondPort = second.testPort()

      check firstPort != Port(0)
      check secondPort != Port(0)
      check firstPort != secondPort
      check firstPort != occupiedPort
      check secondPort != occupiedPort

      let client = newHttpClient(timeout = 5_000)
      defer:
        client.close()
      check client.getContent("http://127.0.0.1:" & $firstPort) == "first"
      check client.getContent("http://127.0.0.1:" & $secondPort) == "second"
