# Migrating apps onto one domain

A playbook for moving existing apps, one at a time, from their own domains (`recipes.dev`, `budget-tracker.app`, …) to subdomains of one root domain (`recipes.example.com`, `budget.example.com`, …) so they can share clang-auth's single sign-on.

**Only apps that need sign-in have to move.** Public sites, APIs secured some other way (API keys, webhooks), and anything without user accounts can stay on their current domains indefinitely. Start by sorting your apps into "needs auth" and "doesn't" ([§8](#8-tracking-sheet) has a column for it).

**Why a single domain is needed:** clang-auth hands each app the signed-in user through one cookie, `ca_access`, set on the parent domain (`Domain=.example.com`). Browsers only send that cookie to subdomains of that domain. An app on any other domain never receives it. [how-it-works.md](how-it-works.md) explains the mechanism; [integration-guide.md](integration-guide.md) covers the code. This document covers moving an app so that code can work.

Contents:

1. [One-time setup](#1-one-time-setup)
2. [Choosing the pilot app](#2-choosing-the-pilot-app)
3. [Per-app checklist](#3-per-app-checklist)
4. [Apps that already have users](#4-apps-that-already-have-users)
5. [Notes by app type](#5-notes-by-app-type)
6. [Rollback](#6-rollback)
7. [Security rules for a shared domain](#7-security-rules-for-a-shared-domain)
8. [Tracking sheet](#8-tracking-sheet)

---

## 1. One-time setup

Do this once, before the first app.

1. **Choose the root domain.** Pick one you'll keep for years: every migrated app's URL depends on it, and moving again means repeating this whole process. A short personal domain works well. This guide uses `example.com` as the root. Avoid using a domain that also hosts things you don't control (see [§7](#7-security-rules-for-a-shared-domain)).
2. **Host its DNS in Route 53.** The SAM stack creates the `auth.` record and the TLS custom domain there ($0.50/month for the hosted zone). Existing records for other services can move too; Route 53 can hold any record type. If the domain is registered elsewhere, create the hosted zone and point the registrar's nameservers at the four Route 53 nameservers it lists.
3. **Decide the naming convention** now, so URLs stay predictable:
   - One subdomain per app, named after its clang-auth slug: `recipes.example.com` ↔ slug `recipes`.
   - `auth.example.com` is reserved for clang-auth.
   - Reserve a pattern for non-production deployments if you want them to authenticate, for example `recipes-preview.example.com` ([§5](#previews-and-staging)).
4. **Deploy clang-auth** following [operations.md §2](operations.md#2-first-time-setup), with `DomainName=auth.example.com` and `CookieDomain=.example.com`.
5. **Create your own account** and confirm login works before touching any app:

   ```sh
   clang-auth user create you@example.com --name "Your Name"
   # open the setup link, set a password, check you land on "Signed in as …"
   ```

---

## 2. Choosing the pilot app

Migrate one app first and live with it for a week or two before doing the rest. A good pilot is:

- **Low stakes:** you're the main or only user, so a mistake costs nobody else.
- **Server-rendered or with its own backend**, so the middleware from the integration guide drops straight in. Static SPAs work too but need more changes ([§5](#static-single-page-apps-no-backend)).
- **Light on external integrations:** few OAuth callbacks, webhooks or email links that name the old domain.
- **Without an existing user system**, or with a trivial one ([§4](#4-apps-that-already-have-users)).

Skip apps with lots of existing users, payment webhooks, or SEO traffic until the pilot has shaken out the process.

---

## 3. Per-app checklist

Each step says what to do and why. Steps 1–5 can happen while the app keeps serving on its old domain; nothing changes for users until step 6.

### Step 1: Inventory everything that names the old domain

Changing domain changes the app's **origin**, and browsers isolate almost everything by origin. Before moving, list what refers to the old domain:

| Look for | Where | Why it matters |
|---|---|---|
| Hard-coded URLs | Code, config, env vars (`APP_URL`, `NEXT_PUBLIC_SITE_URL`, `BASE_URL`, …) | Absolute links and redirects would point back to the old domain |
| OAuth / social-login callback URLs | Google Cloud console, GitHub OAuth apps, and similar | Providers reject callbacks to unregistered URLs |
| Webhook endpoints | Stripe, GitHub, Slack, payment or email providers | Events would keep going to the old domain |
| CORS allowlists, CSP `connect-src` and `frame-ancestors` | App config, API gateways | Browser requests from the new origin would be blocked |
| Links in sent emails | Email templates, scheduled jobs | Old links must keep working (step 6 redirects handle this) |
| PWA manifest and service worker scope | `manifest.json`, `sw.js` | Installed PWAs are tied to the old origin |
| SEO | `<link rel="canonical">`, sitemap, Google Search Console | The new domain needs its own Search Console property |
| Analytics | Plausible, GA and similar site settings | The domain is often part of the site configuration |
| Client-side storage | localStorage, IndexedDB, cookies | **Doesn't move.** Users start empty on the new origin ([step 6](#step-6-cut-over)) |

```sh
# A quick sweep of the codebase:
grep -rn --exclude-dir={node_modules,.git,dist,.next,target} 'old-domain\.example' .
```

### Step 2: Add the subdomain to the app's host

1. In the app's hosting dashboard, add `recipes.example.com` as a custom domain **alongside** the old domain, not instead of it.
2. Create the DNS record the host asks for in Route 53. That's usually a `CNAME` to a host-specific target (see the table), or an `A`/`AAAA` record for your own server.
3. Wait for TLS. Netlify, Vercel, Render, Fly and Amplify issue the certificate automatically once DNS resolves. For other AWS options, request an ACM certificate first (DNS validation, as in [operations.md §2.3](operations.md#23-tls-certificate-acm)).

A Lambda function URL can't take a custom domain on its own; put it behind CloudFront or API Gateway.

| Host | Where | Typical DNS record |
|---|---|---|
| Vercel | Project → Settings → Domains | `CNAME` to the target Vercel shows |
| Netlify | Site → Domain management → Add a domain | `CNAME` to `<site>.netlify.app` |
| Cloudflare Pages | Project → Custom domains | `CNAME` to `<project>.pages.dev` (if DNS stays in Route 53) |
| Fly.io | `fly certs add recipes.example.com` | `CNAME` to `<app>.fly.dev` |
| Render | Service → Settings → Custom Domains | `CNAME` to `<service>.onrender.com` |
| AWS Amplify Hosting | App → Hosting → Custom domains | Created for you when the Route 53 zone is in the same account |
| AWS CloudFront (+ S3) | Distribution → Alternate domain names, plus an ACM certificate **in `us-east-1`** | Route 53 alias `A`/`AAAA` to the distribution |
| AWS API Gateway | Custom domain name + API mapping, plus an ACM certificate in the API's region | Route 53 alias `A`/`AAAA` to the custom domain's target |
| AWS ALB / ECS / EC2 behind a load balancer | ACM certificate on the HTTPS listener | Route 53 alias `A`/`AAAA` to the load balancer |
| Own server / VPS (including a bare EC2 instance) | Your reverse proxy (Caddy, nginx) | `A`/`AAAA` to the server's IP; Caddy obtains TLS automatically |

```sh
# Example: a CNAME in Route 53 (use the target your host shows)
aws route53 change-resource-record-sets --hosted-zone-id Z0123456789ABC --change-batch '{
  "Changes":[{"Action":"CREATE","ResourceRecordSet":{
    "Name":"recipes.example.com","Type":"CNAME","TTL":300,
    "ResourceRecords":[{"Value":"cname.vercel-dns.com"}]}}]}'
```

Check that `https://recipes.example.com` serves the app (still without clang-auth) before moving on.

### Step 3: Register the app with clang-auth

```sh
clang-auth app create recipes --name Recipes --origin https://recipes.example.com
clang-auth grant set you@example.com recipes --role admin
```

The origin must match exactly: `https`, no trailing path, and every hostname the app is served from (add `--origin https://www.recipes.example.com` if you serve both).

### Step 4: Integrate the middleware

Follow [integration-guide.md](integration-guide.md): set `AUTH_BASE_URL=https://auth.example.com` and `AUTH_APP_SLUG=recipes`, then add the verification middleware.

**Put the integration behind a switch** (for example `AUTH_MODE=legacy|clang-auth`) so you can deploy the code before the cutover and roll back without a redeploy ([§6](#6-rollback)). Keep the app's old auth working in `legacy` mode until the cutover is done.

Test locally first. Run the app as `http://<slug>.localtest.me:<port>`, register that origin in your local clang-auth (`ALLOW_INSECURE_ORIGINS=true` is on in `.env.example`), and use the seed user or `clang-auth token mint` ([integration guide §7](integration-guide.md#7-testing-against-a-local-auth-service)). Production and local registrations are separate, because each environment has its own database.

### Step 5: Update external references

Using the step 1 inventory, add (don't replace) the new domain everywhere you can:

- Add the new callback URLs to OAuth providers, keeping the old ones until step 8.
- Add a second webhook endpoint on the new domain, or move webhooks at cutover if the provider only allows one.
- Add the new origin to CORS and CSP settings.
- Update `APP_URL`-style environment variables in a way that takes effect at cutover (for example, set them in the same deploy that flips `AUTH_MODE`).

### Step 6: Cut over

1. Deploy with `AUTH_MODE=clang-auth` and the new `APP_URL`.
2. **Redirect the old domain to the new one** with a permanent `301`, **keeping the path and query string**, so bookmarks, emailed links, and search results keep working. Every host above has a "redirect domain" setting, or use a rewrite rule. Test with:

   ```sh
   curl -sI https://recipes.dev/some/page?x=1 | grep -i -E '^(HTTP|location)'
   # HTTP/2 301
   # location: https://recipes.example.com/some/page?x=1
   ```

3. **Tell your users** (even if that's just you) that they'll sign in once at the new address, and that anything the app stored in the browser (drafts, preferences, offline data) stays on the old origin. If that data matters, export it before the cutover, or have the old version sync it to the server first.

### Step 7: Verify

- [ ] Signed out: `https://recipes.example.com` redirects to `https://auth.example.com/login?redirect_uri=…`.
- [ ] Sign in, and you're sent back to the page you asked for.
- [ ] A user without a grant gets the app's `403`, not a redirect loop.
- [ ] Wait more than 15 minutes (or delete the `ca_access` cookie in devtools), reload, and you're still signed in without seeing the form. That's the silent refresh.
- [ ] Sign out, and you're signed out of the app *and* of other migrated apps.
- [ ] `https://recipes.dev/anything` → `301` to the same path on the new domain.
- [ ] OAuth logins, webhooks, and emails work from the new domain.
- [ ] Devtools → Application → Cookies shows `ca_access` with domain `.example.com`, `HttpOnly`, `Secure`.

### Step 8: Clean up (after a few weeks)

- Remove the `legacy` auth code path and its secrets.
- Remove the old OAuth callbacks and webhook endpoints.
- Keep the **old domain registered and redirecting** for as long as old links might be in circulation. Letting it lapse lets someone else buy it and receive your traffic.
- Keep the old domain's DNS pointing only at the redirect. Never leave a record pointing at a deprovisioned service ([§7](#7-security-rules-for-a-shared-domain)).

---

## 4. Apps that already have users

If the app has its own user table, you need to link each existing account to a clang-auth identity, so people keep their data.

1. **Create clang-auth users for existing accounts.** For a handful, use the CLI. For more, script it from an export. Each run prints a setup link to send:

   ```sh
   # emails.txt: one email per line, exported from the app's user table
   while read -r email; do
     clang-auth --json user create "$email" --grant recipes:member \
       | jq -r '[.user.email, .setup_link] | @tsv'
   done < emails.txt > setup-links.tsv
   ```

   Links expire after 72 hours (`INVITE_TTL`). `clang-auth user reset <email>` issues a new one.

2. **Link accounts on first login.** Add a column such as `clang_auth_sub` to the app's user table. In the code that runs after the middleware has verified the token:

   ```ts
   const claims = c.get("user");
   let user = await db.users.findOne({ clang_auth_sub: claims.sub });
   if (!user) {
     // First clang-auth login: link the existing account by email, once.
     user = await db.users.findOneAndUpdate(
       { email: claims.email.toLowerCase(), clang_auth_sub: null },
       { $set: { clang_auth_sub: claims.sub } },
     );
   }
   if (!user) user = await db.users.insertOne({ email: claims.email, clang_auth_sub: claims.sub /* … */ });
   ```

   From then on, look users up by `sub`, never by email. `sub` is the clang-auth user ID and never changes; emails can. Linking by email is safe here because only an admin can create a clang-auth user and the user had to receive the setup link at that address, but link **once** and then rely on `sub`.

3. **Map roles.** Translate the app's existing roles to grant roles (`--grant recipes:admin`). Read them from `c.get("roles")` instead of the local table, or keep the local table as the source of truth and use the grant only for access. Pick one source of truth per app.

4. **Retire the old passwords.** After the cutover, stop accepting the app's own passwords and delete the hashes, so the old auth system can't be attacked.

---

## 5. Notes by app type

### Server-rendered apps and apps with a backend

The standard case: the [integration guide](integration-guide.md) middleware runs on every request. For API routes called with `fetch()`, return `401` instead of redirecting, and let the frontend call `POST /api/session/refresh` ([integration guide §4](integration-guide.md#4-keeping-the-user-signed-in-refresh)).

### Static single-page apps (no backend)

There's no server to verify the cookie. The page asks the auth service directly:

```ts
const res = await fetch("https://auth.example.com/api/me", { credentials: "include" });
if (res.status === 401) location.href = `https://auth.example.com/login?redirect_uri=${encodeURIComponent(location.href)}`;
const user = await res.json(); // { sub, email, name, apps, … }
```

This works because the SPA and the auth service are now the same *site*, so the browser sends the auth host's session cookie. That is the reason this only works after the move. Remember that hiding UI in the browser is not security. Any API the SPA calls must verify `ca_access` itself.

### Apps with their own APIs on another subdomain

`api.recipes.example.com` also receives `ca_access` (it's under `.example.com`), so the API verifies the same token with the same middleware. Register the frontend's origin, not the API's, with clang-auth. The API's CORS settings must allow the frontend with credentials.

### The apex domain

`example.com` itself (no subdomain) also receives `ca_access`, so it can be an app too: register `https://example.com` as its origin.

### Previews and staging

Preview URLs on the host's own domain (`*.vercel.app`, `*.netlify.app`, …) are a different site, so they **never** receive the cookie. Options:

- Give previews or staging a subdomain under your root (for example a fixed `recipes-staging.example.com`) and register it as an extra origin of the app, or as a separate app such as `recipes-staging`.
- Leave previews unauthenticated, or behind the host's own password protection, and test auth only on staging.
- For automated tests, use the throwaway-key approach ([integration guide §6](integration-guide.md#6-testing-your-app-without-the-auth-service)). No auth service needed.

---

## 6. Rollback

If something goes wrong after the cutover:

1. Set `AUTH_MODE=legacy` (step 4) and redeploy or restart. The app uses its old auth again.
2. If you need the old domain back as primary, remove the `301` redirect. The old origin's cookies and local data are still in users' browsers, since nothing deleted them.
3. Leave the clang-auth app registration in place. It's harmless when unused, and you'll want it for the retry.

This is why steps 2–5 *add* the new domain instead of replacing the old one: until step 8, going back is a configuration change.

---

## 7. Security rules for a shared domain

Putting apps under one domain makes them one trust zone. Every subdomain receives the `ca_access` token, which lists all of a user's grants ([how-it-works.md §4](how-it-works.md#4-security-decisions-and-threat-model)), and any subdomain can set cookies for the parent domain. That leads to three rules.

1. **Only put apps you control under the root domain.** No subdomain may serve content other people can upload or script: no user-generated pages, no "bring your own HTML" hosting, no third-party SaaS that renders arbitrary customer content on your subdomain. A single XSS-able or attacker-controlled subdomain sees every user's access token for every app.
2. **Never leave a dangling DNS record.** Suppose you delete an app on Vercel or Netlify but leave its `CNAME` in Route 53. Someone else can often claim that hostname on the same platform. This is a *subdomain takeover*: they'd receive your users' tokens and could set cookies across the domain.

   When you remove an app, go in this order:
   1. Delete the DNS record.
   2. Delete the hosting project.
   3. Remove the registration: `clang-auth app delete <slug>`.

   Review the hosted zone occasionally:

   ```sh
   aws route53 list-resource-record-sets --hosted-zone-id Z0123456789ABC \
     --query "ResourceRecordSets[?Type=='CNAME'].[Name, ResourceRecords[0].Value]" --output table
   ```

3. **Keep apps on HTTPS only.** The cookies are `Secure`, but an `http://` page on any subdomain could still be tampered with in transit. Enable "always HTTPS" or HSTS on every app. Once *every* subdomain is HTTPS-only, consider `Strict-Transport-Security: max-age=31536000; includeSubDomains` on the root domain.

If any of these rules can't hold for an app, for example it must live on a client's domain, or it hosts other people's content, keep it off the shared domain. That's the case cross-domain sign-on (OIDC, [SPEC §13](../SPEC.md#13-future-explicitly-out-of-mvp-for-direction-only)) is for.

---

## 8. Tracking sheet

Copy this into an issue or note and fill it in as you go:

```text
| App      | Needs auth? | Old domain           | New subdomain          | Slug    | Has users? | Host   | Inventory | DNS | Registered | Code (AUTH_MODE) | Cut over | Verified | Old auth removed |
|----------|-------------|----------------------|------------------------|---------|------------|--------|-----------|-----|------------|------------------|----------|----------|------------------|
| Recipes  | yes         | recipes.dev          | recipes.example.com   | recipes | no         | Vercel | [x]       | [x] | [x]        | [x]              | [ ]      | [ ]      | [ ]              |
| Budget   | yes         | budget-tracker.app   | budget.example.com    | budget  | yes (12)   | Render | [ ]       | [ ] | [ ]        | [ ]              | [ ]      | [ ]      | [ ]              |
| Blog     | no          | myblog.com           | (stays)                | -       | -          | Netlify| -         | -   | -          | -                | -        | -        | -                |
```
