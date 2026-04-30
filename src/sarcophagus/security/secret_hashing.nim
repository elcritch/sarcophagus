import std/[strutils, sysrand]

import bearssl/[hash, hmac]
import chroniclers

const
  SecretHashPrefix* = "pbkdf2-sha256"
    ## Default algorithm marker stored at the front of encoded secret hashes.
  FastSecretHashPrefix* = "hmac-sha256"
    ## Fast algorithm marker for high-entropy machine secret hashes.
  SecretHashIterations* = 600_000
    ## Default PBKDF2-SHA256 iteration count for newly generated hashes.
  SecretHashMinIterations* = 120_000
    ## Minimum accepted iteration count when verifying existing hashes.
  SecretHashMaxIterations* = 2_000_000
    ## Maximum accepted iteration count when verifying existing hashes.
  SecretHashMinSaltBytes* = 16
    ## Minimum accepted salt size for compatibility with older hashes.
  SecretHashSaltBytes* = 32 ## Default salt size for newly generated hashes.
  SecretHashMaxSaltBytes* = 64
    ## Maximum accepted salt size when verifying existing hashes.
  SecretHashDigestBytes* = 32 ## PBKDF2-SHA256 output size.

type
  SecretHashAlgorithm* = enum
    secretHashPbkdf2Sha256
    secretHashHmacSha256

  SecretHashPolicy* = object
    ## Parameters for generating and validating encoded secret hashes.
    ##
    ## Use a custom policy to raise the iteration count over time or to accept
    ## legacy hash parameters during a migration.
    algorithm*: SecretHashAlgorithm ## Algorithm used for newly generated hashes.
    prefix*: string ## Algorithm marker expected in encoded hashes.
    iterations*: int ## Iteration count used for newly generated hashes.
    minIterations*: int ## Lowest accepted iteration count when parsing an existing hash.
    maxIterations*: int
      ## Highest accepted iteration count when parsing an existing hash.
    saltBytes*: int ## Salt size used for newly generated hashes.

  SecretHashParts* = object ## Parsed components of an encoded secret hash.
    ok*: bool ## True when parsing and policy validation succeeded.
    prefix*: string ## Algorithm marker from the encoded hash.
    algorithm*: SecretHashAlgorithm ## Algorithm selected by the encoded prefix.
    iterations*: int ## Iteration count from the encoded hash.
    salt*: string ## Lowercase hex-encoded salt.
    digest*: string ## Lowercase hex-encoded digest.

proc defaultSecretHashPolicy*(): SecretHashPolicy =
  ## Returns the default PBKDF2-SHA256 policy used by `hashSecret`.
  SecretHashPolicy(
    algorithm: secretHashPbkdf2Sha256,
    prefix: SecretHashPrefix,
    iterations: SecretHashIterations,
    minIterations: SecretHashMinIterations,
    maxIterations: SecretHashMaxIterations,
    saltBytes: SecretHashSaltBytes,
  )

proc fastSecretHashPolicy*(saltBytes = SecretHashSaltBytes): SecretHashPolicy =
  ## Returns a fast HMAC-SHA256 policy for high-entropy machine secrets.
  ##
  ## This is appropriate for generated OAuth client secrets, API keys, and other
  ## random bearer-style secrets. Keep PBKDF2 for human-chosen passwords.
  SecretHashPolicy(
    algorithm: secretHashHmacSha256, prefix: FastSecretHashPrefix, saltBytes: saltBytes
  )

proc requireNonEmpty(value, fieldName: string) =
  if value.strip().len == 0:
    raise newException(ValueError, fieldName & " is required")

proc requireValidPolicy(policy: SecretHashPolicy) =
  if policy.prefix.strip().len == 0:
    raise newException(ValueError, "secret hash prefix is required")
  if policy.saltBytes <= 0:
    raise newException(ValueError, "secret hash salt bytes must be positive")
  if policy.saltBytes > SecretHashMaxSaltBytes:
    raise newException(ValueError, "secret hash salt bytes are out of range")

  case policy.algorithm
  of secretHashPbkdf2Sha256:
    if policy.minIterations <= 0 or policy.maxIterations < policy.minIterations:
      raise newException(ValueError, "secret hash iteration bounds are invalid")
    if policy.iterations < policy.minIterations or
        policy.iterations > policy.maxIterations:
      raise newException(ValueError, "secret hash iterations are out of range")
  of secretHashHmacSha256:
    discard

proc requireValidIterations(iterations: int, policy: SecretHashPolicy) =
  if iterations < policy.minIterations or iterations > policy.maxIterations:
    raise newException(ValueError, "secret hash iterations are out of range")

proc policyIsValid(policy: SecretHashPolicy): bool =
  try:
    requireValidPolicy(policy)
    true
  except ValueError:
    false

proc constantTimeEquals*(lhs, rhs: string): bool =
  ## Compares strings without early exit.
  ##
  ## The loop length depends on the shorter input length, so callers should
  ## still validate encoded hash structure before comparing digests.
  var diff = lhs.len xor rhs.len
  let compareLen = min(lhs.len, rhs.len)
  for idx in 0 ..< compareLen:
    diff = diff or (ord(lhs[idx]) xor ord(rhs[idx]))
  diff == 0

proc hexEncode*(bytes: openArray[byte]): string =
  ## Encodes bytes as lowercase hexadecimal.
  result = newStringOfCap(bytes.len * 2)
  for value in bytes:
    result.add(toHex(int(value), 2).toLowerAscii())

proc isLowerHex*(value: string): bool =
  ## Returns true when `value` is non-empty lowercase hexadecimal.
  if value.len == 0:
    return false
  for ch in value:
    if ch notin {'0' .. '9', 'a' .. 'f'}:
      return false
  true

proc randomHex*(byteCount: int): string =
  ## Generates `byteCount` cryptographically secure random bytes as lowercase hex.
  if byteCount <= 0:
    raise newException(ValueError, "random byte count must be positive")

  var bytes = newSeq[byte](byteCount)
  if not urandom(bytes):
    raise newException(OSError, "failed to generate secure random bytes")
  hexEncode(bytes)

proc hmacSha256(
    key: string, data: openArray[byte]
): array[SecretHashDigestBytes, byte] =
  var keyContext: HmacKeyContext
  let keyPtr =
    if key.len == 0:
      nil
    else:
      cast[pointer](unsafeAddr key[0])
  hmacKeyInit(keyContext, addr sha256Vtable, keyPtr, csize_t(key.len))

  var context: HmacContext
  hmacInit(context, keyContext, sha256SIZE)
  if data.len > 0:
    hmacUpdate(context, cast[pointer](unsafeAddr data[0]), csize_t(data.len))
  discard hmacOut(context, addr result[0])

proc stringBytes(value: string): seq[byte] =
  result = newSeq[byte](value.len)
  for idx, ch in value:
    result[idx] = byte(ord(ch))

proc fastHmacSha256*(secret, salt: string): string =
  ## Computes a fast HMAC-SHA256 digest for a high-entropy machine secret.
  hexEncode(hmacSha256(salt, stringBytes(secret)))

proc pbkdf2Sha256*(
    secret, salt: string, iterations: int, policy = defaultSecretHashPolicy()
): array[SecretHashDigestBytes, byte] =
  ## Derives a PBKDF2-HMAC-SHA256 digest.
  ##
  ## This is exported for callers that need the primitive directly. Most code
  ## should prefer `hashSecret` and `verifySecret`, which handle salts, encoded
  ## hash format, and constant-time digest comparison.
  if policy.algorithm != secretHashPbkdf2Sha256:
    raise newException(ValueError, "PBKDF2 requires a PBKDF2 secret hash policy")
  requireValidPolicy(policy)
  requireValidIterations(iterations, policy)

  var blockInput = newSeq[byte](salt.len + 4)
  for idx, ch in salt:
    blockInput[idx] = byte(ord(ch))
  blockInput[^1] = 1

  var previous = hmacSha256(secret, blockInput)
  result = previous

  for _ in 2 .. iterations:
    previous = hmacSha256(secret, previous)
    for idx in 0 ..< result.len:
      result[idx] = result[idx] xor previous[idx]

proc secretDigest*(
    secret, salt: string, iterations: int, policy = defaultSecretHashPolicy()
): string =
  ## Derives a PBKDF2-HMAC-SHA256 digest and returns it as lowercase hex.
  hexEncode(pbkdf2Sha256(secret, salt, iterations, policy))

proc parseSecretHash*(
    secretHash: string, policy = defaultSecretHashPolicy()
): SecretHashParts =
  ## Parses and validates an encoded secret hash against `policy`.
  ##
  ## The accepted format is `prefix$iterations$saltHex$digestHex`. Invalid input
  ## returns `SecretHashParts(ok: false)` instead of raising.
  if not policyIsValid(policy):
    return

  let parts = secretHash.split('$')
  if parts.len notin {3, 4}:
    return

  let algorithm =
    if parts[0] == SecretHashPrefix:
      secretHashPbkdf2Sha256
    elif parts[0] == FastSecretHashPrefix:
      secretHashHmacSha256
    elif parts[0] == policy.prefix:
      policy.algorithm
    else:
      return

  var iterations = 0
  var saltIndex = 1
  var digestIndex = 2
  case algorithm
  of secretHashPbkdf2Sha256:
    if parts.len != 4:
      return
    let pbkdf2Policy =
      if policy.algorithm == secretHashPbkdf2Sha256:
        policy
      else:
        defaultSecretHashPolicy()
    iterations =
      try:
        parseInt(parts[1])
      except ValueError:
        return
    if iterations < pbkdf2Policy.minIterations or iterations > pbkdf2Policy.maxIterations:
      return
    saltIndex = 2
    digestIndex = 3
  of secretHashHmacSha256:
    if parts.len != 3:
      return

  let minSaltHexLength = min(policy.saltBytes, SecretHashMinSaltBytes) * 2
  let maxSaltHexLength = max(policy.saltBytes, SecretHashMaxSaltBytes) * 2
  if parts[saltIndex].len < minSaltHexLength or parts[saltIndex].len mod 2 != 0 or
      parts[saltIndex].len > maxSaltHexLength or not parts[saltIndex].isLowerHex():
    return
  if parts[digestIndex].len != SecretHashDigestBytes * 2 or
      not parts[digestIndex].isLowerHex():
    return

  SecretHashParts(
    ok: true,
    prefix: parts[0],
    algorithm: algorithm,
    iterations: iterations,
    salt: parts[saltIndex],
    digest: parts[digestIndex],
  )

proc hashSecret*(secret: string, policy = defaultSecretHashPolicy()): string =
  ## Hashes a non-empty secret using PBKDF2-HMAC-SHA256.
  ##
  ## The returned value includes the policy prefix, iteration count, random salt,
  ## and digest. Store this encoded value instead of storing the original secret.
  requireNonEmpty(secret, "secret")
  requireValidPolicy(policy)

  let salt = randomHex(policy.saltBytes)
  trace "secret hash generated",
    algorithm = $policy.algorithm,
    prefix = policy.prefix,
    iterations = policy.iterations,
    saltBytes = policy.saltBytes
  case policy.algorithm
  of secretHashPbkdf2Sha256:
    policy.prefix & "$" & $policy.iterations & "$" & salt & "$" &
      secretDigest(secret, salt, policy.iterations, policy)
  of secretHashHmacSha256:
    policy.prefix & "$" & salt & "$" & fastHmacSha256(secret, salt)

proc verifySecret*(
    secret, secretHash: string, policy = defaultSecretHashPolicy()
): bool =
  ## Verifies `secret` against an encoded hash.
  ##
  ## Returns false for empty secrets, malformed hashes, unsupported policy
  ## parameters, and digest mismatches.
  if secret.strip().len == 0:
    debug "secret verification failed", reason = "empty_secret"
    return false

  let parsed = parseSecretHash(secretHash, policy)
  if not parsed.ok:
    debug "secret verification failed", reason = "invalid_hash"
    return false

  let digest =
    case parsed.algorithm
    of secretHashPbkdf2Sha256:
      secretDigest(
        secret,
        parsed.salt,
        parsed.iterations,
        SecretHashPolicy(
          algorithm: secretHashPbkdf2Sha256,
          prefix: SecretHashPrefix,
          iterations: parsed.iterations,
          minIterations: parsed.iterations,
          maxIterations: parsed.iterations,
          saltBytes: parsed.salt.len div 2,
        ),
      )
    of secretHashHmacSha256:
      fastHmacSha256(secret, parsed.salt)
  result = constantTimeEquals(digest, parsed.digest)
  if result:
    trace "secret verification succeeded",
      algorithm = $parsed.algorithm,
      prefix = parsed.prefix,
      iterations = parsed.iterations
  else:
    debug "secret verification failed",
      reason = "digest_mismatch",
      algorithm = $parsed.algorithm,
      prefix = parsed.prefix,
      iterations = parsed.iterations

proc needsSecretRehash*(secretHash: string, policy = defaultSecretHashPolicy()): bool =
  ## Returns true when an encoded hash should be regenerated under `policy`.
  ##
  ## Malformed hashes, hashes with too few iterations, and hashes with shorter
  ## salts than the policy's current salt size all need rehashing.
  let parsed = parseSecretHash(secretHash, policy)
  if not parsed.ok:
    debug "secret rehash needed", reason = "invalid_hash"
    return true

  result =
    parsed.algorithm != policy.algorithm or parsed.prefix != policy.prefix or
    parsed.iterations < policy.iterations or parsed.salt.len < policy.saltBytes * 2
  if result:
    debug "secret rehash needed",
      algorithm = $parsed.algorithm,
      prefix = parsed.prefix,
      iterations = parsed.iterations,
      saltBytes = parsed.salt.len div 2

proc randomSecret*(byteCount = 32): string =
  ## Generates a random secret as lowercase hex.
  randomHex(byteCount)
