# Integration guide: using clang-auth from your app

How to add clang-auth sign-in to an app. You'll register the app, add about 30 lines of middleware, and get a verified user on every request, with no call to the auth service per request.

**Before you start:** your app must be served from a subdomain of the auth service's domain (for example `recipes.example.com` when the auth service is `auth.example.com`). If it lives on its own domain, start with [migrating-apps.md](migrating-apps.md). New to terms like JWT or `SameSite`? The [glossary in how-it-works.md](how-it-works.md#1-concepts-glossary) explains them.

Contents: [How it works](#how-it-works-in-five-steps) · [1. Register](#1-register-your-app) · [2. Configure](#2-configuration-to-expose) · [3. Middleware](#3-verification-middleware) · [4. Refresh](#4-keeping-the-user-signed-in-refresh) · [5. Logout](#5-logout) · [6. Test without the service](#6-testing-your-app-without-the-auth-service) · [7. Test against a local service](#7-testing-against-a-local-auth-service) · [8. API keys](#8-api-keys-for-scripts-and-local-mcp-servers) · [Troubleshooting](#troubleshooting)

## How it works in five steps

1. A user signs in at `https://auth.example.com`.
2. The auth service sets a cookie, **`ca_access`**, on the parent domain (`Domain=.example.com`), so the browser sends it to every app on a subdomain, including yours.
3. The cookie holds a **JWT**: a signed token, valid for 15 minutes, saying who the user is and their roles in each app.
4. Your app checks the token's signature with the auth service's **public key** (published at `/.well-known/jwks.json`) and reads the user from it.
5. If the cookie is missing or expired, your app sends the browser to `https://auth.example.com/login?redirect_uri=<this URL>`. If the user is still signed in there, they come straight back with a fresh token and never see a form.

## 1. Register your app

An admin registers the app's slug and its exact origins, then grants users access:

```sh
clang-auth app create recipes --name Recipes --origin https://recipes.example.com
clang-auth grant set alice@example.com recipes --role admin
```

The origin must match **exactly**: scheme, host, and port. `https://recipes.example.com` and `https://www.recipes.example.com` are different origins; register both if you serve both. The auth service only redirects back to, and only answers cross-origin requests from, registered origins. That's how it prevents open redirects (see [how-it-works.md §4](how-it-works.md#4-security-decisions-and-threat-model)).

## 2. Configuration to expose

| Variable | Example | Purpose |
|---|---|---|
| `AUTH_BASE_URL` | `https://auth.example.com` | Where to send users to sign in. Also the expected JWT issuer (`iss`). |
| `AUTH_APP_SLUG` | `recipes` | Your slug. A token is only valid for you if `apps` contains it. |
| `AUTH_JWKS_URL` | `https://auth.example.com/.well-known/jwks.json` | Public keys. Defaults to `${AUTH_BASE_URL}/.well-known/jwks.json`. Make it overridable for tests. |

Locally these are `http://auth.localtest.me:4000`, `demo`, and the default JWKS URL.

## 3. Verification middleware

This is the complete middleware used by the example app ([`examples/node-app/src/auth.ts`](../examples/node-app/src/auth.ts)), for [Hono](https://hono.dev) with [`jose`](https://github.com/panva/jose). The logic carries over to Express or any other framework: read the token (the `Authorization: Bearer` header, else the cookie), `jwtVerify`, check `apps[slug]`.

```ts
import type { MiddlewareHandler } from "hono";
import { getCookie } from "hono/cookie";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export interface AuthConfig {
  authBaseUrl: string; // e.g. https://auth.example.com
  appSlug: string; // e.g. "recipes"
  jwksUrl?: string; // default: `${authBaseUrl}/.well-known/jwks.json`
  issuer?: string; // default: authBaseUrl
}

export interface Claims extends JWTPayload {
  sub: string;
  email: string;
  name: string | null;
  apps: Record<string, string[]>;
  /** `["api_key"]` when the token was exchanged from an API key. */
  amr?: string[];
}

export type AuthEnv = { Variables: { user: Claims; roles: string[] } };

export function requireAuth(cfg: AuthConfig): MiddlewareHandler<AuthEnv> {
  const jwks = createRemoteJWKSet(new URL(cfg.jwksUrl ?? `${cfg.authBaseUrl}/.well-known/jwks.json`));
  const verify = async (token: string): Promise<Claims | undefined> => {
    try {
      // Checks the ES256 signature (key chosen by `kid`), `iss` and `exp`.
      const { payload } = await jwtVerify<Claims>(token, jwks, {
        issuer: cfg.issuer ?? cfg.authBaseUrl,
        algorithms: ["ES256"],
        clockTolerance: 30,
      });
      return payload;
    } catch {
      // Expired, forged or signed by an unknown key: treat as signed out.
      return undefined;
    }
  };
  return async (c, next) => {
    // Bearer first. A Bearer request is never redirected to the login page:
    // it gets a 401 so the caller can exchange its API key again.
    const bearer = c.req.header("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (bearer) {
      const claims = await verify(bearer.trim());
      if (!claims) {
        c.header("WWW-Authenticate", 'Bearer error="invalid_token"');
        return c.json({ error: "invalid_token" }, 401);
      }
      const roles = claims.apps?.[cfg.appSlug];
      if (!roles) return c.json({ error: "no_access" }, 403);
      c.set("user", claims);
      c.set("roles", roles);
      return next();
    }
    const token = getCookie(c, "ca_access");
    const claims = token ? await verify(token) : undefined;
    if (!claims) {
      const login = new URL("/login", cfg.authBaseUrl);
      login.searchParams.set("redirect_uri", c.req.url);
      return c.redirect(login.toString(), 302);
    }
    const roles = claims.apps?.[cfg.appSlug];
    if (!roles) return c.text(`You don't have access to ${cfg.appSlug}.`, 403);
    c.set("user", claims);
    c.set("roles", roles);
    await next();
  };
}
```

Use it:

```ts
app.use("*", requireAuth({ authBaseUrl: process.env.AUTH_BASE_URL!, appSlug: process.env.AUTH_APP_SLUG! }));
app.get("/", (c) => c.text(`Hello ${c.get("user").email}, your roles: ${c.get("roles").join(", ")}`));
```

What it checks, and why each check matters:

- **Signature.** Anyone can write a cookie that *looks* like a JWT. Only the auth service has the private key that produces a valid ES256 signature. `algorithms: ["ES256"]` stops an attacker from switching the algorithm (for example to `none`).
- **`iss`.** The token was issued by *your* auth service, not some other service that happens to use JWTs.
- **`exp`.** Tokens live 15 minutes. `clockTolerance: 30` allows for small clock differences between machines.
- **`apps[slug]`.** A valid token for a user who has no grant for *your* app is still a "no". Return `403` rather than redirecting, because redirecting would loop: the user is signed in, they just aren't allowed.
- **Bearer before cookie, and no redirect for Bearer.** Scripts and local MCP servers send `Authorization: Bearer <token>` ([§8](#8-api-keys-for-scripts-and-local-mcp-servers)). A bad Bearer token gets `401` JSON, so the caller knows to exchange its key again; redirecting a script to an HTML login page helps no one. A bad Bearer header doesn't fall back to the cookie.

`createRemoteJWKSet` fetches the JWKS once and caches it. When it sees an unknown `kid` (after a key rotation) it re-fetches automatically.

The token tells you `sub` (stable user ID; use this as your foreign key, not the email), `email`, `name` (may be `null`), and `apps`, which maps each slug to the user's roles there.

## 4. Keeping the user signed in (refresh)

The access token expires every 15 minutes. How you get a new one depends on the request:

- **Full page loads:** nothing extra. Your middleware redirects to `/login?redirect_uri=…`, the auth service sees its own session cookie, issues a fresh `ca_access`, and redirects straight back. The user sees at most a flicker.
- **`fetch()`/XHR from your frontend:** a redirect in the middle of an API call doesn't help. Call the refresh endpoint and retry:

  ```ts
  async function api(path: string, init?: RequestInit) {
    let res = await fetch(path, init);
    if (res.status === 401 || res.redirected) {
      const r = await fetch(`${AUTH_BASE_URL}/api/session/refresh`, { method: "POST", credentials: "include" });
      if (r.ok) res = await fetch(path, init);           // new ca_access cookie is set
      else window.location.href = `${AUTH_BASE_URL}/login?redirect_uri=${encodeURIComponent(location.href)}`;
    }
    return res;
  }
  ```

  For API routes, have your middleware return `401` instead of a redirect, so the frontend can tell what happened. `credentials: "include"` is required, otherwise the browser won't send the auth host's session cookie. The auth service answers with CORS headers only for registered origins.

- **Static SPA with no backend:** `GET ${AUTH_BASE_URL}/api/me` with `credentials: "include"` returns the current claims as JSON, or `401`.

Here is the refresh call with curl, using a cookie jar in place of the browser:

```bash
JAR=$(mktemp)
curl -s -c "$JAR" -o /dev/null -X POST http://auth.localtest.me:4000/login \
  -H 'Origin: http://auth.localtest.me:4000' \
  --data-urlencode email=dev@localtest.me --data-urlencode password=devpassword123
curl -s -b "$JAR" -X POST http://auth.localtest.me:4000/api/session/refresh \
  -H 'Origin: http://demo.localtest.me:3000' -D - -o /dev/null | grep -i -E '^(HTTP|access-control-allow)'
```

```text
HTTP/1.1 200 OK
access-control-allow-origin: http://demo.localtest.me:3000
access-control-allow-credentials: true
```

## 5. Logout

Render a form that posts to the auth service:

```html
<form method="post" action="https://auth.example.com/logout">
  <input type="hidden" name="redirect_uri" value="https://recipes.example.com/" />
  <button type="submit">Sign out</button>
</form>
```

This ends the session at the auth service and clears both cookies, so the user is signed out of **all** apps on the domain. From `fetch()`, send `POST /logout` with `credentials: "include"` and `Accept: application/json` to get `200 {"status":"signed_out"}` instead of a redirect.

## 6. Testing your app without the auth service

Your tests shouldn't need a running auth service. The trick is that verification only needs a public key and a claim shape, both of which you can fake:

1. Make the JWKS URL and issuer configurable (step 2).
2. In test setup, generate a throwaway ES256 keypair and serve its public half as a JWKS from a tiny local HTTP server.
3. Sign tokens with the private half, using the same claims the real service uses ([SPEC §5.3](../SPEC.md#53-jwt-claims)).

From [`examples/node-app/test/auth.test.ts`](../examples/node-app/test/auth.test.ts):

```ts
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const { publicKey, privateKey } = await generateKeyPair("ES256");
const jwk = { ...(await exportJWK(publicKey)), kid: "test-key", alg: "ES256", use: "sig" };
// serve { keys: [jwk] } from http://127.0.0.1:<port>/jwks.json, pass that as jwksUrl

const token = await new SignJWT({ email: "me@example.com", name: "Me", apps: { demo: ["admin"] } })
  .setProtectedHeader({ alg: "ES256", kid: "test-key" })
  .setSubject("user-1")
  .setIssuer("https://auth.test")
  .setIssuedAt()
  .setJti(crypto.randomUUID())
  .setExpirationTime("15m")
  .sign(privateKey);

const res = await app.request("http://demo.test/", { headers: { cookie: `ca_access=${token}` } });
```

The example app's tests cover a valid token, a missing token (redirect), an expired token, no grant (403), the wrong issuer, an unknown key, and a forged signature:

```bash
(cd examples/node-app && npm test 2>&1 | grep -E '^ℹ (tests|pass|fail)')
```

## 7. Testing against a local auth service

Run the local service ([README quickstart](../README.md#quickstart-local-development)). Then either:

**Use the seed user in a browser.** Open your app, get redirected to `http://auth.localtest.me:4000/login`, and sign in as `dev@localtest.me` / `devpassword123`. The seed only grants the `demo` app, so add yourself to yours with `clang-auth grant set dev@localtest.me <your-slug> --role admin`.

**Or mint a token and use curl.** No browser needed:

```bash
TOKEN=$(clang-auth token mint dev@localtest.me --ttl 1h)
curl -s http://demo.localtest.me:3000/api/whoami -H "Cookie: ca_access=$TOKEN"; echo
```

```text
{"user":{"iss":"http://auth.localtest.me:4000","sub":"6aed1e0f…","email":"dev@localtest.me","name":"Dev User","apps":{"demo":["admin"]},"iat":…,"exp":…,"jti":"…"},"roles":["admin"]}
```

The public keys your middleware will fetch:

```bash
curl -s http://auth.localtest.me:4000/.well-known/jwks.json | head -c 120; echo
```

## 8. API keys for scripts and local MCP servers

A local MCP server (or any script) can't sign in with a browser. Instead, a user creates an **API key** for one app on the auth service, and the script trades it for a normal access token.

```text
1. User (signed in) → https://auth.example.com/keys → creates a key for "recipes" → ca_key_…  (shown once)
2. Script → POST https://auth.example.com/api/token   Authorization: Bearer ca_key_…
          ← {"token": "<JWT>", "token_type": "Bearer", "expires_in": 900}
3. Script → your app   Authorization: Bearer <JWT>
4. Your app verifies it with the same middleware as a browser request (§3)
```

**What your app needs:** only Bearer support in the middleware, which the §3 middleware already has. No key table, no shared secret, no call to the auth service.

**What the token contains:** the same claims as a browser token, with three differences:

- `apps` holds **only the key's app**. A leaked recipes key can't be used against any other app.
- The roles are the ones the user ticked when creating the key, **limited to their current grant**. An admin can make a key that acts with no roles, which is the default. If the admin later demotes the user, the key is demoted too. Promoting the user never promotes a key beyond what it was created with.
- `amr: ["api_key"]` marks it as non-interactive. Browser tokens have no `amr`. Use it if you want stricter rules for scripts than for people, for example no `DELETE`:

  ```ts
  if (c.get("user").amr?.includes("api_key") && c.req.method === "DELETE") return c.json({ error: "forbidden" }, 403);
  ```

**When it stops working.** The exchange checks everything every time: the key exists and hasn't expired, the user is active, and the user still has a grant for the app. Revoking the key, disabling the user or removing the grant takes effect at the next exchange, within 15 minutes (one access-token lifetime). All failures return the same `401 invalid_api_key`.

**Linking to it from your app.** Send users to `https://auth.example.com/keys?app=<your-slug>` to show only your app's form.

**The script side.** [`examples/node-app/src/api-key-client.ts`](../examples/node-app/src/api-key-client.ts) exchanges the key, caches the token until a minute before it expires (about one exchange per 15 minutes), shares one exchange between concurrent calls, and on a `401` from your app exchanges again and retries once:

```ts
import { apiKeyClient } from "./api-key-client.ts";

const auth = apiKeyClient({ authBaseUrl: process.env.AUTH_BASE_URL!, apiKey: process.env.CLANG_AUTH_API_KEY! });
const res = await auth.fetch("https://recipes.example.com/api/recipes", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ title: "Pancakes" }),
});
```

Store the key like any other secret: in the MCP server's environment (for example `.env`, git-ignored), never in the repo. `POST /api/token` sends no CORS headers, so a web page can't use a key from the browser; it's for servers and scripts only.

By hand, with a key from `/keys`:

```sh
TOKEN=$(curl -s -X POST https://auth.example.com/api/token -H "Authorization: Bearer $CLANG_AUTH_API_KEY" | jq -r .token)
curl -s https://recipes.example.com/api/whoami -H "Authorization: Bearer $TOKEN"
```

## Troubleshooting

**The cookie isn't sent to my app.**
- Your app must be on a subdomain of `COOKIE_DOMAIN`. `.example.com` covers `recipes.example.com` but not `example.org` or `recipes.example.com.au`.
- In production the cookie is `Secure`, so it is only sent over `https://`. Locally the dev config sets `COOKIE_SECURE=false`.
- `SameSite=Lax` sends the cookie on same-site requests and top-level navigations. All `*.example.com` subdomains are the same "site", so this works across your apps. If your frontend is on a *different* registrable domain (for example a `*.vercel.app` preview URL), the cookie won't reach it; that is a non-goal (SPEC §1).
- Check the browser devtools under Application → Cookies → `ca_access`. Its domain should read `.example.com`.

**CORS errors calling `/api/session/refresh` or `/api/me`.**
- The page's origin must be registered for an app, **exactly** (scheme, host, and port). `clang-auth app show <slug>` lists them. `http://localhost:3000` is not `http://demo.localtest.me:3000`.
- You must pass `credentials: "include"`. Without it, the browser drops the session cookie and the response's `Set-Cookie`.
- A response with no `Access-Control-Allow-Origin` header means the origin isn't registered. The service deliberately never answers with `*` for credentialed endpoints.

**Tokens are rejected with "exp" or "iat" errors even though they're fresh.** That's clock skew: your server's clock disagrees with the auth service's. Keep NTP enabled. The example middleware tolerates 30 seconds (`clockTolerance`).

**Token rejected after a key rotation.** `createRemoteJWKSet` re-fetches when it sees a new `kid`, but a hand-rolled cache might not. Re-fetch the JWKS whenever a token's `kid` isn't in your cached copy.

**A script gets `401 invalid_api_key` from `/api/token`.** The key was revoked or has expired, the user is disabled, or their grant for the key's app was removed. `clang-auth key list <email>` shows the user's keys and when each was last used.

**A script gets redirected to `/login` instead of a `401`.** Your middleware isn't reading the `Authorization` header. See §3.

**`localtest.me` problems.**
- `*.localtest.me` is a public DNS name that resolves to `127.0.0.1` (and `::1`), so it needs working DNS. Offline, add `127.0.0.1 auth.localtest.me demo.localtest.me` to `/etc/hosts`.
- Some routers and corporate DNS resolvers block DNS answers that point at `127.0.0.1` ("DNS rebinding protection"). Use the `/etc/hosts` line above, or a public resolver.
- Browsers may connect over IPv6 (`::1`). The service and example app listen on both loopback addresses. If another program holds port 4000 or 3000 on the address your browser picks, you'll reach that program instead. Check with `lsof -nP -iTCP:4000 -sTCP:LISTEN`.
- Don't use `localhost` for apps. Cookies set with `Domain=.localtest.me` are not sent to `localhost`.
