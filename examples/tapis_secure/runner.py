# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "requests-oauthlib>=2.0.0",
# ]
# ///

import argparse
import json
import os
import sys
from typing import Any

import requests
from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session


CLIENT_ID = "goto-cli"
CLIENT_SECRET = "goto-secret"


def print_response(label: str, response: requests.Response) -> None:
    print()
    print(f"== {label}")
    print(f"status: {response.status_code}")
    content_type = response.headers.get("content-type")
    if content_type:
        print(f"content-type: {content_type}")
    www_authenticate = response.headers.get("www-authenticate")
    if www_authenticate:
        print(f"www-authenticate: {www_authenticate}")

    try:
        body: Any = response.json()
    except ValueError:
        print(f"body: {response.text}")
    else:
        print("body:", json.dumps(body, sort_keys=True))


def require_status(response: requests.Response, expected: int, label: str) -> None:
    if response.status_code != expected:
        print_response(label, response)
        raise SystemExit(f"{label} returned {response.status_code}, expected {expected}")


def oauth_client(base_url: str, scope: str) -> OAuth2Session:
    # The example server is intentionally local HTTP; production OAuth2 should use HTTPS.
    os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")

    token_url = f"{base_url}/oauth/token"
    client = BackendApplicationClient(client_id=CLIENT_ID)
    session = OAuth2Session(client=client)
    token = session.fetch_token(
        token_url=token_url,
        auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET),
        scope=[scope],
    )
    print()
    print(f"== oauth2 client credentials token for {scope}")
    print("token_type:", token.get("token_type"))
    print("expires_in:", token.get("expires_in"))
    print("scope:", token.get("scope"))
    return session


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a Python OAuth2 client against examples/tapis_secure/server.nim"
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:9083")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    print(f"Python OAuth2 client talking to {base_url}")

    health = requests.get(f"{base_url}/health", timeout=5)
    print_response("public health route", health)
    require_status(health, 200, "public health route")

    resolved = requests.get(
        f"{base_url}/go/docs", params={"preview": "true"}, timeout=5
    )
    print_response("public goto resolver", resolved)
    require_status(resolved, 200, "public goto resolver")

    unauthenticated = requests.get(f"{base_url}/admin/gotos", timeout=5)
    print_response("scoped route without bearer token", unauthenticated)
    require_status(unauthenticated, 401, "scoped route without bearer token")

    read_client = oauth_client(base_url, "goto:read")
    write_client = oauth_client(base_url, "goto:write")

    protected_list = read_client.get(
        f"{base_url}/admin/gotos", params={"limit": 2}, timeout=5
    )
    print_response("read-scoped admin list", protected_list)
    require_status(protected_list, 200, "read-scoped admin list")

    out_of_scope = read_client.get(
        f"{base_url}/admin/gotos/new/save",
        params={"url": "https://example.test/notes"},
        timeout=5,
    )
    print_response("write route with read-only token", out_of_scope)
    require_status(out_of_scope, 403, "write route with read-only token")

    saved = write_client.get(
        f"{base_url}/admin/gotos/new/save",
        params={"url": "https://example.test/notes", "title": "Notes"},
        timeout=5,
    )
    print_response("write-scoped save", saved)
    require_status(saved, 200, "write-scoped save")

    deleted = write_client.get(f"{base_url}/admin/gotos/new/delete", timeout=5)
    print_response("write-scoped delete", deleted)
    require_status(deleted, 200, "write-scoped delete")

    swagger = requests.get(f"{base_url}/swagger.json", timeout=5)
    require_status(swagger, 200, "openapi")
    spec = swagger.json()
    print()
    print("== openapi")
    print("title:", spec["info"]["title"])
    print("paths:", ", ".join(spec["paths"].keys()))
    print("security schemes:", ", ".join(spec["components"]["securitySchemes"].keys()))
    print(
        "admin list security:",
        json.dumps(spec["paths"]["/admin/gotos"]["get"]["security"]),
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
