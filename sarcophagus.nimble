version       = "0.10.0"
author        = "Jaremy Creechley"
description   = "mummy higher level api wrapper"
license       = "Apache-2.0"
srcDir        = "src"

requires "nim >= 2.0.0"
requires "mummy"
requires "jwt >= 0.3"
requires "bearssl >= 0.2.8"
requires "https://github.com/yglukhov/bearssl_pkey_decoder#546f8d9b"
requires "https://github.com/elcritch/chroniclers"

feature "dev":
  requires "karax"

feature "cbor":
  requires "cborious"

feature "jsony":
  requires "jsony"

feature "msgpack":
  requires "msgpack4nim"

feature "chronicles":
  requires "https://github.com/elcritch/chroniclers[chronicles] >= 0.2.1"
