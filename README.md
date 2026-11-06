# clang-auth

One login for all your personal apps. Users sign in once at `auth.example.com` and are then signed in to every `*.example.com` app you've given them access to.

- **Apps check logins themselves.** Each app verifies a short-lived signed token in a cookie, with no call to the auth service per request.
- **Invite-only.** There's no sign-up page. You create users and manage access with a command-line tool.
- **Cheap.** Runs on AWS Lambda and MongoDB Atlas's free tier for about $1/month.
- Written in Rust (axum), following [SPEC.md](SPEC.md).

> **Requirement: every app must be on a subdomain of one domain** (`recipes.example.com`, `budget.example.com`, …). Apps on other domains can't receive the login cookie. To move existing apps, see [docs/migrating-apps.md](docs/migrating-apps.md).

## Quickstart (local development)

You need Docker, Rust (stable), and Node.js ≥ 22.18 for the example app. No AWS account is required.

```sh
git clone <this repo> && cd service-clang-auth-claude
cp .env.example .env                      # working local defaults
docker compose up -d                      # MongoDB on localhost:27017
cargo run -p service -- seed              # app "demo", user dev@localtest.me
cargo run -p service                      # auth service on http://auth.localtest.me:4000
```

In a second terminal, start the example app:

```sh
cd examples/node-app && npm install && npm start   # http://demo.localtest.me:3000
```

Then:

1. Open <http://demo.localtest.me:3000>. You're redirected to the auth service's login page.
2. Sign in as **`dev@localtest.me`** / **`devpassword123`**.
3. You land back on the demo app, which shows *Signed in as Dev User (dev@localtest.me)*.
4. Click **Sign out**. Reload, and you're asked to sign in again.

The same steps, scripted, are in `scripts/smoke.sh` (`make smoke`).

`*.localtest.me` is public DNS that points at `127.0.0.1`, so the two "subdomains" share cookies with no `/etc/hosts` edits. If it doesn't resolve for you, see [troubleshooting](docs/integration-guide.md#troubleshooting).

**Local admin key:** `dev-admin-key-change-me` (its SHA-256 is in `.env.example`). The CLI picks it up from `.env`:

```bash
cargo run -q -p clang-auth-cli -- app list
```

Useful targets: `make test` (all tests; needs MongoDB running), `make lint`, `make check-template`, `make build-lambda` (`sam build`, arm64), `make docs-check`.

## Documentation

| Doc | For |
|---|---|
| [docs/how-it-works.md](docs/how-it-works.md) | Understanding the auth concepts, flows, and security decisions (start here if auth is new to you) |
| [docs/integration-guide.md](docs/integration-guide.md) | Adding login to an app, and testing it |
| [docs/migrating-apps.md](docs/migrating-apps.md) | Moving existing apps from their own domains onto subdomains of your root domain, one at a time |
| [docs/operations.md](docs/operations.md) | Deploying to AWS, cost guardrails, key rotation, incident response |
| [docs/cli.md](docs/cli.md) | Every `clang-auth` admin command |
| [DECISIONS.md](DECISIONS.md) | Choices the spec left open, and where the implementation deviates from it |
| [SPEC.md](SPEC.md) | The original specification |

## Repository layout

```text
crates/core      domain logic: models, MongoDB store, passwords, tokens, origin checks (no HTTP)
crates/service   axum router, HTML pages, local server + Lambda entrypoint, seed/migrate
crates/cli       the clang-auth admin CLI (talks to the admin HTTP API only)
examples/node-app  minimal Hono + jose consumer app with tests
infra/template.yaml  SAM template (Lambda arm64 + HTTP API + log group)
scripts/         smoke test, template checks, doc-example runner
```
