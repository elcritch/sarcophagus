## Compile-time project version helpers.
##
## These procs are intentionally package-agnostic. A project can define its own
## constants by invoking `defineProjectVersion` with its package name.

import std/[os, strutils]

proc parentDirs*(path: string, count: Natural): string {.compileTime.} =
  ## Return `path` after walking up `count` parent directories.
  result = path
  for _ in 0 ..< count:
    result = result.parentDir()

proc projectRootFromSource*(
    sourcePath: string, levelsUp: Natural
): string {.compileTime.} =
  ## Return a project root by walking up from a source file path.
  ##
  ## Example: `projectRootFromSource(currentSourcePath(), 2)` for a module in
  ## `src/`, or `3` for a module in `src/pkg/`.
  parentDirs(sourcePath, levelsUp)

proc projectNimbleFile*(projectRoot, projectName: string): string {.compileTime.} =
  ## Return the nimble path for `projectName` in a project root.
  ##
  ## This follows the common layout where `myproject/myproject.nimble` lives
  ## at the repository root.
  projectRoot / (projectName & ".nimble")

proc hasGitRepo*(projectRoot: string): bool {.compileTime.} =
  ## Return whether `projectRoot` looks like a git checkout.
  ##
  ## Worktrees use a `.git` file, normal checkouts use a `.git` directory.
  dirExists(projectRoot / ".git") or fileExists(projectRoot / ".git")

proc packageVersionFromNimble*(
    nimbleFile: string,
    isDirty = false,
    defaultVersion = "0.0.0",
    dirtySuffix = "+dirty",
): string {.compileTime.} =
  ## Read the `version = "..."`
  ## value from a nimble file, optionally appending `dirtySuffix`.
  result = defaultVersion
  if fileExists(nimbleFile):
    for line in readFile(nimbleFile).splitLines():
      let stripped = line.strip()
      if not stripped.startsWith("version") or "=" notin stripped:
        continue

      let parts = stripped.split("=", maxsplit = 1)
      if parts.len == 2 and parts[0].strip() == "version":
        result = parts[1].strip()
        if result.len >= 2:
          let first = result[0]
          let last = result[^1]
          if (first == '"' and last == '"') or (first == '\'' and last == '\''):
            result = result[1 .. ^2]
        break

  if isDirty:
    result.add dirtySuffix

proc gitIsDirty*(projectRoot: string): bool {.compileTime.} =
  ## Return whether git reports uncommitted changes for `projectRoot`.
  if hasGitRepo(projectRoot):
    staticExec("git -C " & quoteShell(projectRoot) & " status --porcelain").strip().len >
      0
  else:
    false

proc gitCommit*(projectRoot: string, unknown = "unknown"): string {.compileTime.} =
  ## Return the current git commit SHA for `projectRoot`.
  if hasGitRepo(projectRoot):
    staticExec("git -C " & quoteShell(projectRoot) & " log -n 1 --format=%H").strip()
  else:
    unknown

proc formatProjectVersion*(packageVersion, commit: string): string {.compileTime.} =
  ## Format a package version and git commit as a user-facing version string.
  packageVersion & " (sha: " & commit & ")"

template defineProjectVersion*(projectName: static[string], n: static[Positive] = 2) =
  ## Define generic `Project*` constants for a package.
  ##
  ## `n` is counted from the `src` directory. Use `1` for
  ## `src/version_info.nim`, or `2` for `src/pkg/version_info.nim`.
  const
    ProjectRootDir* {.inject.} =
      projectRootFromSource(instantiationInfo(fullPaths = true).filename, n + 1)
    ProjectNimbleFile* {.inject.} = projectNimbleFile(ProjectRootDir, projectName)
    ProjectIsDirty* {.inject.} = gitIsDirty(ProjectRootDir)
    ProjectPackageVersion* {.inject.} =
      packageVersionFromNimble(ProjectNimbleFile, ProjectIsDirty)
    ProjectCommit* {.inject.} = gitCommit(ProjectRootDir)
    ProjectVersion* {.inject.} =
      formatProjectVersion(ProjectPackageVersion, ProjectCommit)
