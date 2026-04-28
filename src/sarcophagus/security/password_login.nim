## Callback-driven username/password login core.
##
## This module intentionally does not own user storage or HTTP routing. Use the
## callback types from `password_login_core` to plug in an application account
## store, mint signed browser session tokens, and validate those sessions.

import ./password_login_core

export password_login_core
