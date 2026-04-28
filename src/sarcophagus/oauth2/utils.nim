import std/[base64, strutils, sysrand]

proc bytesToString(bytes: openArray[byte]): string =
  result = newString(bytes.len)
  for idx, value in bytes:
    result[idx] = char(value)

proc base64UrlEncodeBytes*(bytes: openArray[byte]): string =
  result = encode(bytes.bytesToString())
  result = result.replace('+', '-')
  result = result.replace('/', '_')
  result = result.replace("=", "")

proc randomUrlSafeSecret*(byteCount: int): string =
  if byteCount <= 0:
    raise newException(ValueError, "random byte count must be positive")

  var bytes = newSeq[byte](byteCount)
  if not urandom(bytes):
    raise newException(OSError, "failed to generate secure random bytes")
  base64UrlEncodeBytes(bytes)

proc decodeHexNibble(c: char): int =
  case c
  of '0' .. '9':
    ord(c) - ord('0')
  of 'a' .. 'f':
    10 + ord(c) - ord('a')
  of 'A' .. 'F':
    10 + ord(c) - ord('A')
  else:
    -1

proc decodeFormComponent*(input: string): string =
  result = newStringOfCap(input.len)
  var idx = 0
  while idx < input.len:
    case input[idx]
    of '+':
      result.add(' ')
    of '%':
      if idx + 2 >= input.len:
        raise newException(ValueError, "invalid percent encoding")
      let hi = decodeHexNibble(input[idx + 1])
      let lo = decodeHexNibble(input[idx + 2])
      if hi < 0 or lo < 0:
        raise newException(ValueError, "invalid percent encoding")
      result.add(char((hi shl 4) or lo))
      idx += 2
    else:
      result.add(input[idx])
    inc idx

proc sanitizeHeaderValue*(input: string): string =
  for ch in input:
    if ch == '"' or ch == '\\':
      result.add('\\')
      result.add(ch)
    elif ch >= ' ' and ch <= '~':
      result.add(ch)
