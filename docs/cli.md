# `clang-auth` CLI reference

`clang-auth` is the admin tool for the auth service. It talks **only** to the admin HTTP API (`/admin/*`) with your admin API key. It never connects to MongoDB, so the same binary manages your laptop's dev service and production.

## Quick reference

| I want to… | Command |
|---|---|
| Register an app | [`clang-auth app create <slug> --name <name> --origin <url>`](#app-create-slug---name-name---origin-url---origin-url) |
| See apps | [`clang-auth app list`](#app-list) · [`app show <slug>`](#app-show-slug) |
| Change an app's name or origins | [`clang-auth app update <slug> …`](#app-update-slug---name----add-origin----remove-origin-) |
| Invite a new user | [`clang-auth user create <email> --grant <slug>:<role>`](#user-create-email---name----grant-slugrolerole) |
| See users | [`clang-auth user list [--app <slug>]`](#user-list---app-slug) · [`user show <email>`](#user-show-emailid) |
| Reset a forgotten password | [`clang-auth user reset <email>`](#user-reset-emailid) |
| Give or change access | [`clang-auth grant set <email> <slug> --role <role>`](#grant-set-emailid-slug---role-role) |
| Remove access to one app | [`clang-auth grant remove <email> <slug>`](#grant-remove-emailid-slug) |
| Sign someone out everywhere | [`clang-auth session revoke <email>`](#session-revoke-emailid) |
| Block or unblock someone | [`clang-auth user disable <email>`](#user-disable-emailid--user-enable-emailid) · `user enable <email>` |
| Delete a user or app | [`clang-auth user delete <email> --yes`](#deleting-things) · `app delete <slug> --yes` |
| Get a test token (dev only) | [`clang-auth token mint <email> [--ttl 1h]`](#token-mint-emailid---ttl-1h) |

## Install and configure

```sh
cargo install --path crates/cli          # puts `clang-auth` on your PATH
# or, without installing:
alias clang-auth='cargo run -q -p clang-auth-cli --'
```

The CLI needs two settings: the service URL and the admin key. It looks for them in this order (first match wins):

1. Flags: `--url https://auth.example.com --key …`
2. Environment variables: `CLANG_AUTH_URL`, `CLANG_AUTH_ADMIN_KEY`
3. A `.env` file in the current directory (the repo's `.env.example` sets both for local dev)
4. `~/.config/clang-auth/config.toml` (or the path in `CLANG_AUTH_CONFIG`):

   ```toml
   url = "https://auth.example.com"
   admin_key = "the raw key, not its hash"
   ```

For local development, `cp .env.example .env` is enough: it points at `http://auth.localtest.me:4000` with the dev key `dev-admin-key-change-me`.

Every command accepts `--json` for machine-readable output (the raw API response). Destructive commands (`app delete`, `user delete`) ask for confirmation. Pass `--yes` (or `-y`) to skip the prompt, which you must do in scripts.

> All `bash` examples below were run against the local dev setup (`scripts/run-doc-examples.sh` re-runs them). Outputs are real but IDs, tokens, and timestamps will differ for you.

## Apps

An **app** is something that uses the auth service, identified by a short slug. Its **origins** are the exact `scheme://host[:port]` values the service will redirect to and accept cross-origin requests from.

### `app create <slug> --name <name> --origin <url> [--origin <url>...]`

```bash
clang-auth app create recipes --name Recipes --origin https://recipes.example.com
```

```text
Created app: recipes
  name:    Recipes
  origin:  https://recipes.example.com
```

Slugs are 2–32 characters of `a-z`, `0-9`, and `-`. Origins are normalised (lowercased, default port and trailing `/` removed) and must not contain a path. `http://` origins are rejected unless the server runs with `ALLOW_INSECURE_ORIGINS=true` (local dev only).

### `app list`

```bash
clang-auth app list
```

```text
SLUG                 NAME                     ORIGINS
demo                 Demo app                 http://demo.localtest.me:3000
recipes              Recipes                  https://recipes.example.com
```

### `app update <slug> [--name ..] [--add-origin ..] [--remove-origin ..]`

```bash
clang-auth app update recipes --name 'Recipe Box' --add-origin https://www.recipes.example.com
```

```text
Updated app: recipes
  name:    Recipe Box
  origin:  https://recipes.example.com
  origin:  https://www.recipes.example.com
```

### `app show <slug>`

```bash
clang-auth app show recipes
clang-auth --json app show demo
```

```text
App: recipes
  name:    Recipe Box
  origin:  https://recipes.example.com
  origin:  https://www.recipes.example.com
{
  "slug": "demo",
  "name": "Demo app",
  "origins": [
    "http://demo.localtest.me:3000"
  ],
  ...
}
```

### `app delete <slug> [--yes]`

Deletes the app **and removes its grants from every user**. Example at the end of this page.

## Users

There is no sign-up page. You create a user, the CLI prints a **one-time setup link**, and you send it to them yourself (chat, email, whatever). The link expires after `INVITE_TTL` (default 72 hours). The user picks a password at that link and is signed in.

### `user create <email> [--name ..] [--grant <slug>[:role,role]]...`

```bash
clang-auth user create alice@example.com --name Alice --grant recipes:admin --grant demo
```

```text
alice@example.com (6aed223d1e0e2a45845b1bc2)
Created user. Send them this one-time setup link (expires 2026-11-09T00:41:33.783911Z):
http://auth.localtest.me:4000/setup?token=<one-time-token>
```

`--grant demo` gives access with no roles. `--grant recipes:admin,editor` gives two roles. Emails are case-insensitive.

### `user list [--app <slug>]`

```bash
clang-auth user list
clang-auth user list --app recipes
```

```text
ID                         EMAIL                          STATUS    GRANTS
6aed223d1e0e2a45845b1bc2   alice@example.com              invited   demo recipes[admin]
6aed1e0fc302db09bd2c79ad   dev@localtest.me               active    demo[admin]
```

`invited` means the user hasn't used their setup link yet.

### `user show <email|id>`

Shows the user, their grants, and how many active sessions they have. Anywhere a command takes a user, it accepts the email or the ID.

```bash
clang-auth user show alice@example.com
```

```text
alice@example.com (6aed223d1e0e2a45845b1bc2)
  name:     Alice
  status:   active
  password: not set (setup pending)
  sessions: 0 active
  grant:    demo → (no roles)
  grant:    recipes → admin
```

### `user reset <email|id>`

Creates a password-reset link. Older unused links for that user stop working. When the user sets a new password, **all their existing sessions are signed out**. The old password keeps working until then.

```bash
clang-auth user reset alice@example.com
```

```text
Send them this one-time password-reset link (expires 2026-11-09T00:41:33.860446Z):
http://auth.localtest.me:4000/setup?token=<one-time-token>
```

### `user disable <email|id>` / `user enable <email|id>`

Disabling blocks login and **revokes all sessions** immediately. Access tokens already issued stay valid until they expire (at most `ACCESS_TOKEN_TTL`, 15 minutes by default). See [how-it-works.md](how-it-works.md#5-known-limitations).

```bash
clang-auth user disable alice@example.com
clang-auth user enable alice@example.com
```

```text
Disabled alice@example.com (all sessions revoked)
Enabled alice@example.com
```

### `user delete <email|id> [--yes]`

Deletes the user with their sessions and invites. Example at the end of this page.

## Grants

A **grant** is one user's access to one app, with a list of free-form roles. The auth service doesn't interpret roles; each app decides what `admin` or `editor` means.

### `grant set <email|id> <slug> [--role <role>]...`

Creates the grant, or replaces its roles if it exists.

```bash
clang-auth grant set alice@example.com recipes --role member --role editor
```

```text
alice@example.com (6aed223d1e0e2a45845b1bc2)
  name:     Alice
  status:   active
  password: not set (setup pending)
  grant:    demo → (no roles)
  grant:    recipes → member, editor
```

### `grant remove <email|id> <slug>`

```bash
clang-auth grant remove alice@example.com demo
```

Grant changes show up in the user's **next** access token, after their next refresh or login (within 15 minutes).

## Sessions

### `session revoke <email|id>`

Signs the user out everywhere by deleting all their sessions. Their next refresh fails and they have to sign in again.

```bash
clang-auth session revoke alice@example.com
```

```text
Revoked 0 session(s) for alice@example.com
```

## Tokens (development only)

### `token mint <email|id> [--ttl 1h]`

Prints a signed access token for a user, so you can call your app with `curl` without going through the browser. The server must run with `ALLOW_TOKEN_MINT=true` (the local `.env.example` does; production never should). Otherwise you get `token minting is disabled on the server`.

```bash
TOKEN=$(clang-auth token mint dev@localtest.me --ttl 1h)
echo "$TOKEN" | cut -c1-40
```

`--json` prints the token together with its decoded claims.

## Deleting things

```bash
clang-auth user delete alice@example.com --yes
clang-auth app delete recipes --yes
```

```text
Deleted user alice@example.com
Deleted app recipes (0 grants removed)
```

Without `--yes`, the CLI asks `… This cannot be undone. [y/N]`. If stdin is not a terminal, it refuses rather than guessing.

## Errors

The CLI exits with status 1 and prints the server's message:

```text
$ clang-auth app create recipes --name X --origin https://x.example.com
error: 409 Conflict: app "recipes" already exists
$ CLANG_AUTH_ADMIN_KEY=wrong clang-auth app list
error: 401 unauthorized: check CLANG_AUTH_ADMIN_KEY
```
