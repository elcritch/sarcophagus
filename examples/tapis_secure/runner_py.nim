import std/[httpclient, os, osproc, strformat, strutils]

proc repoRoot(): string =
  currentSourcePath.parentDir().parentDir().parentDir()

proc compileServer(repoDir: string, serverBinary: string) =
  let serverSource = repoDir / "examples" / "tapis_secure" / "server.nim"
  let compileResult = execCmdEx(
    "nim c -o:" & quoteShell(serverBinary) & " " & quoteShell(serverSource),
    options = {poUsePath, poStdErrToStdOut},
  )
  if compileResult.exitCode != 0:
    echo compileResult.output
    quit("failed to compile examples/tapis_secure/server.nim", QuitFailure)

proc waitUntilReady(baseUrl: string) =
  var client = newHttpClient(timeout = 500)
  defer:
    client.close()

  for attempt in 0 ..< 30:
    try:
      let response = client.get(baseUrl & "/health")
      if response.code.int == 200:
        return
    except CatchableError:
      discard
    sleep(200)

  quit("secure example server did not become ready", QuitFailure)

proc runPythonClient(repoDir, baseUrl: string) =
  let runner = repoDir / "examples" / "tapis_secure" / "runner.py"
  let command = "uv run " & quoteShell(runner) & " --base-url " & quoteShell(baseUrl)
  let result = execCmdEx(command, options = {poUsePath, poStdErrToStdOut})
  echo result.output
  if result.exitCode != 0:
    quit("python oauth2 client runner failed", QuitFailure)

proc main() =
  let repoDir = repoRoot()
  let serverBinary = repoDir / "examples" / "tapis_secure" / "server_bin"
  let port = 9084
  let baseUrl = fmt"http://127.0.0.1:{port}"

  compileServer(repoDir, serverBinary)
  defer:
    if fileExists(serverBinary):
      removeFile(serverBinary)

  let serverProc = startProcess(
    serverBinary,
    workingDir = repoDir,
    args = [$port],
    options = {poParentStreams, poStdErrToStdOut},
  )
  defer:
    if serverProc.running():
      terminate(serverProc)
      discard serverProc.waitForExit(3_000)
    serverProc.close()

  waitUntilReady(baseUrl)
  runPythonClient(repoDir, baseUrl)

when isMainModule:
  main()
