import std/[strutils, unittest]

import sarcophagus/security/secret_hashing

const TestIterations = 1_000

proc testPolicy(iterations = TestIterations): SecretHashPolicy =
  SecretHashPolicy(
    prefix: SecretHashPrefix,
    iterations: iterations,
    minIterations: 1,
    maxIterations: 20_000,
    saltBytes: 16,
  )

suite "secret hashing":
  test "hashes and verifies secrets":
    let policy = testPolicy()
    let secret = "client-secret"
    let secretHash = hashSecret(secret, policy)
    let parts = secretHash.split('$')

    check secretHash != secret
    check parts.len == 4
    check parts[0] == SecretHashPrefix
    check parts[1] == $policy.iterations
    check parts[2].len == policy.saltBytes * 2
    check parts[2].isLowerHex()
    check parts[3].len == SecretHashDigestBytes * 2
    check parts[3].isLowerHex()
    check verifySecret(secret, secretHash, policy)
    check not verifySecret("wrong-" & secret, secretHash, policy)
    check not needsSecretRehash(secretHash, policy)

  test "hashes use unique salts":
    let policy = testPolicy()
    let secret = "same-secret"
    let firstHash = hashSecret(secret, policy)
    let secondHash = hashSecret(secret, policy)

    check firstHash != secondHash
    check verifySecret(secret, firstHash, policy)
    check verifySecret(secret, secondHash, policy)

  test "parses valid hashes":
    let policy = testPolicy()
    let secretHash = hashSecret("parse-me", policy)
    let parsed = parseSecretHash(secretHash, policy)

    check parsed.ok
    check parsed.prefix == policy.prefix
    check parsed.iterations == policy.iterations
    check parsed.salt.len == policy.saltBytes * 2
    check parsed.digest.len == SecretHashDigestBytes * 2

  test "verifies legacy default minimum iteration hashes":
    let secret = "legacy-secret"
    let salt = "0123456789abcdef0123456789abcdef"
    let digest = "2e67c731630fe0443e1f3077644be57c3d19b677cb8be16fd4092836c3c0d095"
    let secretHash =
      SecretHashPrefix & "$" & $SecretHashMinIterations & "$" & salt & "$" & digest

    check verifySecret(secret, secretHash)
    check needsSecretRehash(secretHash)

  test "detects hashes that need rehashing":
    let oldPolicy = testPolicy(iterations = 500)
    let currentPolicy = testPolicy(iterations = 1_000)
    let secretHash = hashSecret("rotate-me", oldPolicy)

    check verifySecret("rotate-me", secretHash, currentPolicy)
    check needsSecretRehash(secretHash, currentPolicy)

  test "rejects malformed hashes":
    let policy = testPolicy()
    let digest = "a".repeat(SecretHashDigestBytes * 2)
    let salt = "b".repeat(policy.saltBytes * 2)
    let oversizedSalt = "b".repeat((SecretHashMaxSaltBytes + 1) * 2)

    check not verifySecret("secret", "", policy)
    check not verifySecret("secret", "sha256$1000$" & salt & "$" & digest, policy)
    check not verifySecret(
      "secret", SecretHashPrefix & "$nope$" & salt & "$" & digest, policy
    )
    check not verifySecret(
      "secret", SecretHashPrefix & "$0$" & salt & "$" & digest, policy
    )
    check not verifySecret(
      "secret",
      SecretHashPrefix & "$" & $(policy.maxIterations + 1) & "$" & salt & "$" & digest,
      policy,
    )
    check not verifySecret(
      "secret", SecretHashPrefix & "$" & $policy.iterations & "$$" & digest, policy
    )
    check not verifySecret(
      "secret", SecretHashPrefix & "$" & $policy.iterations & "$" & salt & "$", policy
    )
    check not verifySecret(
      "secret",
      SecretHashPrefix & "$" & $policy.iterations & "$not-hex$" & digest,
      policy,
    )
    check not verifySecret(
      "secret",
      SecretHashPrefix & "$" & $policy.iterations & "$" & salt & "$not-hex",
      policy,
    )
    check not verifySecret(
      "secret",
      SecretHashPrefix & "$" & $policy.iterations & "$" & oversizedSalt & "$" & digest,
      policy,
    )
    check needsSecretRehash("", policy)

  test "requires non-empty secrets and valid policies":
    let policy = testPolicy()
    let invalidPolicy = SecretHashPolicy(
      prefix: SecretHashPrefix,
      iterations: 0,
      minIterations: 0,
      maxIterations: 1,
      saltBytes: 16,
    )

    expect ValueError:
      discard hashSecret("", policy)
    expect ValueError:
      discard hashSecret("   ", policy)
    expect ValueError:
      discard hashSecret("secret", SecretHashPolicy(prefix: "", iterations: 1))
    expect ValueError:
      discard hashSecret(
        "secret",
        SecretHashPolicy(
          prefix: SecretHashPrefix,
          iterations: 1,
          minIterations: 1,
          maxIterations: 1,
          saltBytes: SecretHashMaxSaltBytes + 1,
        ),
      )
    expect ValueError:
      discard pbkdf2Sha256("secret", "salt", 0, invalidPolicy)
    check not verifySecret("", hashSecret("not-empty", policy), policy)
    check not verifySecret("   ", hashSecret("not-empty", policy), policy)
    check not verifySecret(
      "secret",
      SecretHashPrefix & "$0$" & "a".repeat(policy.saltBytes * 2) & "$" &
        "b".repeat(SecretHashDigestBytes * 2),
      invalidPolicy,
    )
    check not parseSecretHash(
      SecretHashPrefix & "$0$" & "a".repeat(policy.saltBytes * 2) & "$" &
        "b".repeat(SecretHashDigestBytes * 2),
      invalidPolicy,
    ).ok

  test "generates random secrets":
    let firstSecret = randomSecret()
    let secondSecret = randomSecret()

    check firstSecret.len == 64
    check secondSecret.len == 64
    check firstSecret.isLowerHex()
    check secondSecret.isLowerHex()
    check firstSecret != secondSecret
    check randomSecret(byteCount = 16).len == 32
