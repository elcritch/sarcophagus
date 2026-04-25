version       = "0.3.0"
author        = "Jaremy Creechley"
description   = "mummy higher level api wrapper"
license       = "BSD-2-Clause"
srcDir        = "src"

requires "nim >= 2.0.0"
requires "mummy"
requires "https://github.com/elcritch/nim-jwt#fix-upstream"

feature "cbor":
  requires "cborious"

feature "jsony":
  requires "jsony"

