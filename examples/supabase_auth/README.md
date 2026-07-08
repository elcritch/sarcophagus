# Supabase Auth Example

This example protects Sarcophagus routes with JWT access tokens issued by
Supabase Auth. Sarcophagus does not mint or exchange Supabase tokens here; it
validates incoming `Authorization: Bearer ...` tokens against the Supabase Auth
issuer and JWKS endpoint derived from `SUPABASE_PROJECT_URL`.

Routes:

- `GET /health` is public.
- `GET /reports` and `GET /reports/sync` are TAPIS routes protected by
  `jwtBearer(...)` and require `role:authenticated`.
- `GET /whoami` is a raw Mummy route protected by the same verifier and returns
  selected validated JWT claims.
- `GET /swagger.json` exposes OpenAPI metadata for the TAPIS routes.

## Run

```sh
cd examples/supabase_auth
SUPABASE_PROJECT_URL="https://<project-ref>.supabase.co" nim r server.nim
```

Then call the public route:

```sh
curl http://127.0.0.1:9084/health
```

Protected routes need a Supabase Auth access token:

```sh
curl \
  -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \
  http://127.0.0.1:9084/reports

curl \
  -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \
  http://127.0.0.1:9084/whoami
```

The token must be issued by the configured project and include Supabase's
standard authenticated role claim. By default the verifier maps `role`,
`client_id`, and `user_id` claims into authorization scopes such as
`role:authenticated`.

## Runner

The runner compiles the server, starts it on port `9084`, exercises the public
and unauthenticated protected paths, and prints the OpenAPI security metadata:

```sh
nim r examples/supabase_auth/runner.nim
```

To also exercise authenticated paths:

```sh
SUPABASE_PROJECT_URL="https://<project-ref>.supabase.co" \
SUPABASE_ACCESS_TOKEN="<access-token>" \
nim r examples/supabase_auth/runner.nim
```
