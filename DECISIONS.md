# Decisions

Choices the spec left open, and the few places where the implementation goes beyond or departs from [SPEC.md](SPEC.md). Each entry gives the decision and the reason. Entries marked **Deviation** change or extend something the spec states; all the others fill in a gap.

## Project layout and crates

- **D1. Package names.** `crates/core` is the package `clang-auth-core` (library `clang_auth_core`), because a crate named `core` would shadow Rust's built-in `core` library. `crates/service` is the package `service`, so `cargo run -p service` works as §10.1 says. Its binary is `clang-auth-service`. `crates/cli` is `clang-auth-cli` and builds the binary `clang-auth` (§8).
- **D2. Dependency choices** (§2 leaves them open):
  | Concern | Crate | Why |
  |---|---|---|
  | JWT signing | `jsonwebtoken` 9 (ring backend) | Widely used, supports ES256 and JWK decoding for tests. ring cross-compiles cleanly with cargo-lambda/zig. |
  | P-256 keys, JWKS coordinates | `p256` 0.13 (RustCrypto) | Generates and parses PKCS#8/SEC1/SPKI PEM, and exposes the x/y coordinates for JWKS. |
  | Password hashing | `argon2` 0.5 (RustCrypto) | Pure Rust, PHC strings, constant-time verify. |
  | Constant-time compare | `subtle` | The standard choice. |
  | MongoDB | `mongodb` 3 + `bson` 2 (chrono feature) | Official driver (fixed by §2). |
  | SSM | `aws-sdk-ssm` + `aws-config` | Official SDK. Only called when `*_SSM_PARAM` vars are set. |
  | Logging | `tracing` + `tracing-subscriber` (JSON) | Structured fields, spans for request IDs. |
  | CLI | `clap` 4 (derive), `reqwest` 0.12 (rustls), `toml` | |
  | HTML | none: `format!` plus a 10-line escape function (`crates/service/src/html.rs`) | Five tiny pages don't justify a templating engine, and the code shows exactly what reaches the browser. |
  | Cookies | none: hand-written `Set-Cookie` (`crates/service/src/cookies.rs`) | Every attribute in §5 is visible in one place. |
  | `.env` loading | `dotenvy` | Local only; never in Lambda. |

  I picked established major versions over the newest ones (for example `jsonwebtoken` 9 rather than 11), favouring well-known, stable APIs.
- **D3. Release profile.** `opt-level = "s"`, LTO, one codegen unit, `strip`, `panic = "abort"`. This gives a smaller binary and so a faster Lambda cold start.
- **D4. Example app** uses **Hono** and runs TypeScript directly with Node's built-in type stripping (Node ≥ 22.18), so there is no build step. Tests use `node:test`.

## Configuration

- **D5. SSM convention.** For each secret variable (`MONGODB_URI`, `ADMIN_API_KEY_HASH`, `SIGNING_KEY`, `SIGNING_KEYS_RETIRED`) you can set `<VAR>_SSM_PARAM=<parameter name>` instead of the value. At cold start the service makes one `GetParameters` call with decryption. The SAM template uses this for the three secrets and for the optional retired keys (D6). CloudFormation dynamic references can't inject SecureString values into Lambda environment variables, and plain environment variables would expose the secrets in the Lambda console.
- **D6. Retired signing keys** come from the optional SSM parameter `/clang-auth/signing-keys-retired` (a plain `String`, since public keys aren't secret). If it doesn't exist, the list is empty. Rotation is then a couple of `aws ssm` commands plus a container refresh, with no multi-line PEM passed through `sam deploy` parameters. Locally, `SIGNING_KEYS_RETIRED` takes the PEM directly; newlines may be written as `
`.
- **D7. Signing key formats.** PKCS#8 (`BEGIN PRIVATE KEY`) or SEC1 (`BEGIN EC PRIVATE KEY`, what `openssl ecparam` prints). If neither `SIGNING_KEY` nor `SIGNING_KEY_PATH` is set **and not in Lambda**, a key is generated at `.dev-keys/signing-key.pem` (mode 0600) and reused. In Lambda a missing key is a startup error.
- **D8. Extra settings.** `ARGON2_M_KIB`, `ARGON2_T`, `ARGON2_P` (§11 says "configurable"). The service refuses to start below the OWASP minimums. `LOG_FORMAT=json` turns on JSON logs locally; Lambda always uses JSON. `CLANG_AUTH_CONFIG` overrides the CLI config path.
- **D9. Startup validation.** `COOKIE_DOMAIN` must be a parent of the `AUTH_BASE_URL` host, and `ADMIN_API_KEY_HASH` must be 64 hex characters. Mistakes here would otherwise fail silently in the browser.
- **D10. Local listener.** The service binds `127.0.0.1` and `::1` (not `0.0.0.0`). `*.localtest.me` resolves to both, browsers may use either, and nothing should be exposed to the LAN.

## Auth flow

- **D11. Deviation (extension): CSRF token for `Origin: null`.**
  - *Problem:* §11 requires `Referrer-Policy: no-referrer` on HTML pages. With that policy, browsers send **`Origin: null`** (and no `Referer`) when the page submits its own forms, so the §6.1 Origin/Referer check alone would reject our own login, setup and logout forms.
  - *Kept as specified:* a foreign `Origin`, or a foreign `Referer` when `Origin` is missing, is always rejected.
  - *Added:* when the browser reports no usable origin, the request is accepted only if the form's hidden `csrf` field matches the `ca_csrf` cookie. That cookie is random, `HttpOnly`, host-only and `SameSite=Strict`, and set when a form is shown. A cross-site page can't make the browser send a `SameSite=Strict` cookie, so it can't pass. (This pattern is called a *double-submit token*.) Requests with neither an origin nor a token are rejected.
  - *Rejected alternative:* weakening `Referrer-Policy`.
- **D12. "No cookies set" on failed login** means no *auth* cookies (`ca_session`, `ca_access`). The re-rendered form may set `ca_csrf` (D11) if the visitor didn't have one. The tests assert that no auth cookie is set.
- **D13. Status codes.** Every redirect is `302 Found`, including after `POST /login` (§15 asks for 302). Failed login is `401` with the form. "No access" is `403` with the page; the user's cookies are still set (§4.1 step 5: "still logged in"). Invalid or expired invite links are `400`. A CSRF rejection is `403`.
- **D14. Redirect targets.** The service redirects to its own re-write of the parsed URL, never the raw input. It also rejects input with surrounding whitespace, control characters, embedded credentials (`https://good@evil`), or more than 2048 bytes. URL parsers silently strip some of these, and when the browser and the service read a URL differently, open redirects slip through.
- **D15. The JWT `apps` claim contains every grant the user has**, not only the app being logged into. The same access-token cookie is shared by all apps on the domain (§5.2), so it has to describe all of them. `name` is `null` when unset.
- **D16. `kid`** is the RFC 7638 JWK thumbprint of the public key. It is stable across restarts, unique per key, and needs no extra configuration.
- **D17. Rate limiting.**
  - A 15-minute window starts at the first failure for a key (`email:<email>` or `ip:<ip>`). Blocked attempts don't extend it.
  - While a key is at its limit (5 for an email, 20 for an IP), attempts are refused *before* the password is checked, so the correct password fails too (§15).
  - The IP is API Gateway's `sourceIp` in Lambda and the socket peer locally. `X-Forwarded-For` is ignored because clients can forge it.
  - Expiry is checked in the query as well as by the TTL index, because MongoDB only deletes expired documents about once a minute.
- **D18. Timing.** Unknown emails and users without a password still run one Argon2 verification against a dummy hash, so response time doesn't reveal whether an account exists. Disabled users run the real verification. All three get the same response (§6.1).
- **D19. Session sliding.** Each use (`GET /login`, `GET /`, refresh, `/api/me`) moves `expires_at` to `min(now + SESSION_TTL, absolute_expires_at)` and re-sends the session cookie with a matching `Max-Age`, except on `/api/me`, which slides the stored record but doesn't re-send the cookie. `user_agent` is truncated to 256 characters.
- **D20. Refresh CSRF.** `POST /api/session/refresh` sets a cookie, so it gets the CSRF origin check: callers must be a registered app origin or the auth host. Others get `403` with no CORS headers. A preflight from an unregistered origin gets `204` with no `Access-Control-Allow-*` headers, which the browser treats as a refusal.
- **D21. Logout** also accepts `redirect_uri` in the query string. When the request says `Accept: application/json`, logout returns `200 {"status":"signed_out"}` with CORS headers instead of a redirect, for apps that log out with `fetch()`.
- **D22. JWKS** is served with `Access-Control-Allow-Origin: *` so static SPAs can fetch it. It's public data.

## Invites and passwords

- **D23. Both setup and reset revoke all existing sessions** on completion. §4.5 requires it for resets; for a first-time setup there are normally no sessions anyway.
- **D24.** The new password is hashed *before* the invite is consumed, and consumption is a single atomic `findOneAndUpdate` (`used_at: null`, `expires_at > now`). Two concurrent submissions can't both succeed, and a policy error doesn't burn the link.
- **D25.** "Invalidates earlier unused invites" is done by **deleting** them. Invites for disabled or deleted users are refused.
- **D26.** The setup form has an optional `password_confirm` field. If present it must match. Length is counted in Unicode characters, not bytes.

## Admin API and CLI

- **D27.** `:id` accepts a 24-hex ObjectId or an email (§6.2 "MAY"). Roles are trimmed and de-duplicated, must be 1–64 characters, and an empty role list is allowed (access with no roles). Unknown apps in `POST /admin/users` grants give `400`; `PUT .../grants/:slug` for an unknown app gives `404`.
- **D28.** When `ALLOW_TOKEN_MINT=false`, `POST /admin/tokens` is **not routed at all**, so it returns `404` even without an API key. `ttl` may be a duration string (`"1h"`) or a number of seconds. Disabled users can't have tokens minted.
- **D29.** Admin responses: users are `{id, email, name, status, has_password, grants:[{app, roles, granted_at}], created_at, updated_at}`, plus `active_sessions` on `GET /admin/users/:id`. Create user returns `{user, setup_link, expires_at}`, reset returns `{user_id, reset_link, expires_at}`, and deletes return small JSON confirmations.
- **D30. CLI.** Config precedence is flags, then environment variables, then a `.env` in the current directory, then `~/.config/clang-auth/config.toml`. Destructive commands (`app delete`, `user delete`) require `--yes` when stdin isn't a terminal. `app update --add-origin/--remove-origin` does a GET then a PATCH on the client side, which isn't atomic; that's fine for a single admin. `token mint` prints only the token, so `$(clang-auth token mint …)` works. `clang-auth app show <slug>` is an extra command.
- **D31. Seed** is a service subcommand (`cargo run -p service -- seed`) that writes to MongoDB directly. It is idempotent and resets the dev user's password to `devpassword123` on every run, so the documented credentials always work. The "known local admin key" (`dev-admin-key-change-me`) is configuration: its hash is in `.env.example`, and seed confirms when it is in use.
- **D32. Extra service subcommands:** `migrate` (indexes), `gen-signing-key`, `public-key`, `gen-admin-key`, `hash-admin-key`. Operators can do all key setup without OpenSSL.

## Persistence

- **D33. Indexes** are created at startup (awaited locally; in Lambda run in the background so the first request isn't delayed) and by `migrate`. Index creation is idempotent. TTL indexes use `expireAfterSeconds: 0` on `expires_at`.
- **D34.** The MongoDB pool is capped at 5 connections per container. Combined with reserved concurrency 5 (one request per container at a time), that keeps total connections far below Atlas M0's limit.

## Observability

- **D35.** Request log lines contain method, **path without query string** (setup links carry the token in the query), status, latency, and request ID. Audit events are `info` lines with an `event` field. Emails appear in `login_failure` events, for diagnosing lockouts. They are not secrets under §11, but they are personal data.
- **D36.** Lambda `LoggingConfig.LogFormat` is `Text`, because the application already writes one JSON object per line.

## Infrastructure

- **D37.** The HTTP API's default `execute-api` endpoint is disabled (`DisableExecuteApiEndpoint: true`), so the service is only reachable on the custom domain its cookies are scoped to. The stack creates the Route 53 alias record. `HostedZoneId` and `CertificateArn` are required parameters, as §11 allows.
- **D38.** `samconfig.toml` sits at the repo root and points at `infra/template.yaml`. It sets `beta_features = true` because SAM still marks the `rust-cargolambda` build method as beta.
