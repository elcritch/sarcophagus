## Shared HTTP integration test setup. Port zero lets the OS reserve a free
## port for the actual listening socket, without a probe/close/rebind race.
import std/[importutils, nativesockets]
import mummy

type ServerThreadArgs* = object
  server*: Server
  address*: string

proc serveServer*(args: ServerThreadArgs) {.thread.} =
  args.server.serve(Port(0), address = args.address)

proc testPort*(server: Server): Port =
  server.waitUntilReady()
  # Mummy has no public accessor for the bound port. Keep this test-only
  # dependency on its socket representation isolated here.
  privateAccess(typeof(server[]))
  nativesockets.getLocalAddr(server.socket, AF_INET)[1]
