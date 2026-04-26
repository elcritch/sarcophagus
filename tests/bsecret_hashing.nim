import std/[strformat, times]

import sarcophagus/security/secret_hashing

type BenchCase = object
  name: string
  policy: SecretHashPolicy
  hashRounds: int
  verifyRounds: int

proc pbkdf2Policy(iterations: int): SecretHashPolicy =
  SecretHashPolicy(
    algorithm: secretHashPbkdf2Sha256,
    prefix: SecretHashPrefix,
    iterations: iterations,
    minIterations: min(iterations, SecretHashMinIterations),
    maxIterations: SecretHashMaxIterations,
    saltBytes: SecretHashSaltBytes,
  )

proc elapsedSeconds(start: float): float =
  epochTime() - start

proc nsPerOp(seconds: float, rounds: int): float =
  seconds * 1_000_000_000'f64 / float(rounds)

proc opsPerSecond(seconds: float, rounds: int): float =
  float(rounds) / seconds

proc report(label: string, rounds: int, seconds: float) =
  echo &"{label:<28} {rounds:>8} ops  {seconds:>8.4f} s  " &
    &"{nsPerOp(seconds, rounds):>12.0f} ns/op  {opsPerSecond(seconds, rounds):>10.2f} ops/s"

proc benchHash(name, secret: string, policy: SecretHashPolicy, rounds: int): string =
  var totalLen = 0
  let started = epochTime()
  for _ in 0 ..< rounds:
    result = hashSecret(secret, policy)
    totalLen += result.len
  report(name & " hash", rounds, elapsedSeconds(started))
  doAssert totalLen > 0

proc benchVerify(
    name, secret, storedHash: string, policy: SecretHashPolicy, rounds: int
) =
  var verified = 0
  let started = epochTime()
  for _ in 0 ..< rounds:
    if verifySecret(secret, storedHash, policy):
      inc verified
  report(name & " verify", rounds, elapsedSeconds(started))
  doAssert verified == rounds

when isMainModule:
  let secret = randomSecret()
  let cases = [
    BenchCase(
      name: "pbkdf2-sha256 600k",
      policy: defaultSecretHashPolicy(),
      hashRounds: 3,
      verifyRounds: 5,
    ),
    BenchCase(
      name: "pbkdf2-sha256 120k",
      policy: pbkdf2Policy(120_000),
      hashRounds: 10,
      verifyRounds: 20,
    ),
    BenchCase(
      name: "hmac-sha256 fast",
      policy: fastSecretHashPolicy(),
      hashRounds: 20_000,
      verifyRounds: 100_000,
    ),
  ]

  echo "Secret hashing benchmark"
  echo "Nim: ", NimVersion
  echo "Secret bytes: ", secret.len div 2
  echo ""
  echo "Operation                       Rounds      Time        ns/op       ops/s"
  echo "--------------------------------------------------------------------------"

  for benchCase in cases:
    let storedHash =
      benchHash(benchCase.name, secret, benchCase.policy, benchCase.hashRounds)
    benchVerify(
      benchCase.name, secret, storedHash, benchCase.policy, benchCase.verifyRounds
    )
