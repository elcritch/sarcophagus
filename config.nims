import std/[os, strutils]

switch("mm", "arc")
switch("threads", "on")

task test, "run unit tests":
  for testFile in listFiles("tests/"):
    if testFile.endsWith(".nim") and testFile.splitFile().name.startsWith("t"):
      exec("nim c -r " & quoteShell(testFile))
