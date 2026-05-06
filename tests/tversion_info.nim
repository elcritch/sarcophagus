import std/[os, strutils, unittest]

import sarcophagus/version_info

defineProjectVersion("sarcophagus", n = 1)

suite "version_info":
  test "finds the project root from a source path":
    const root = projectRootFromSource(currentSourcePath(), 2)
    check root.lastPathPart() == "sarcophagus"

  test "builds the project nimble file path":
    check projectNimbleFile(ProjectRootDir, "sarcophagus") == ProjectNimbleFile
    check ProjectNimbleFile.lastPathPart() == "sarcophagus.nimble"

  test "reads the package version from the project nimble file":
    check ProjectPackageVersion != "0.0.0"
    check ProjectPackageVersion.len > 0

  test "formats package version and commit":
    check formatProjectVersion("1.2.3", "abc123") == "1.2.3 (sha: abc123)"
    check ProjectVersion.startsWith(ProjectPackageVersion & " (sha: ")
    check ProjectVersion.endsWith(")")
