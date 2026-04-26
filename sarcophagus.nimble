version       = "0.4.0"
author        = "Jaremy Creechley"
description   = "mummy higher level api wrapper"
license       = "BSD-2-Clause"
srcDir        = "src"

requires "nim >= 2.0.0"
requires "mummy"
requires "jwt >= 0.3"
requires "bearssl >= 0.2.8"
requires "gh:yglukhov/bearssl_pkey_decoder#546f8d9b"

feature "cbor":
  requires "cborious"

feature "jsony":
  requires "jsony"

feature "msgpack":
  requires "msgpack4nim"

