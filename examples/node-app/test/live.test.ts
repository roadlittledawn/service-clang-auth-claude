// Against a running local auth service (docker compose up -d; seed; cargo run -p service).
// Skipped automatically when the service isn't reachable.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { createApp } from "../src/app.ts";

const AUTH = process.env.AUTH_BASE_URL ?? "http://auth.localtest.me:4000";
const ADMIN_KEY = process.env.CLANG_AUTH_ADMIN_KEY ?? "dev-admin-key-change-me";

async function reachable(): Promise<boolean> {
  try {
    const res = await fetch(`${AUTH}/health`, { signal: AbortSignal.timeout(1500) });
    return res.ok && (await res.json()).status === "ok";
  } catch {
    return false;
  }
}

const skip = (await reachable()) ? false : `auth service not running at ${AUTH}`;

test("minted token verifies with jose against the real JWKS", { skip }, async () => {
  const res = await fetch(`${AUTH}/admin/tokens`, {
    method: "POST",
    headers: { authorization: `Bearer ${ADMIN_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({ email: "dev@localtest.me", ttl: "10m" }),
  });
  assert.equal(res.status, 200, await res.clone().text());
  const { token } = await res.json();
  const jwks = createRemoteJWKSet(new URL(`${AUTH}/.well-known/jwks.json`));
  const { payload, protectedHeader } = await jwtVerify(token, jwks, { issuer: AUTH, algorithms: ["ES256"] });
  assert.ok(protectedHeader.kid);
  assert.equal(payload.email, "dev@localtest.me");
  assert.equal((payload.exp ?? 0) - (payload.iat ?? 0), 600);
  assert.deepEqual((payload as any).apps.demo, ["admin"]);
});

test("seed user logs in and the demo app shows them", { skip }, async () => {
  const login = await fetch(`${AUTH}/login`, {
    method: "POST",
    redirect: "manual",
    headers: { origin: AUTH, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      email: "dev@localtest.me",
      password: "devpassword123",
      redirect_uri: "http://demo.localtest.me:3000/",
    }),
  });
  assert.equal(login.status, 302);
  assert.equal(login.headers.get("location"), "http://demo.localtest.me:3000/");
  const access = login.headers.getSetCookie().find((c) => c.startsWith("ca_access="))!;
  assert.match(access, /Domain=\.localtest\.me/);
  const jwt = access.split(";")[0].slice("ca_access=".length);

  const app = createApp({ authBaseUrl: AUTH, appSlug: "demo", appUrl: "http://demo.localtest.me:3000" });
  const page = await app.request("http://demo.localtest.me:3000/", { headers: { cookie: `ca_access=${jwt}` } });
  assert.equal(page.status, 200);
  assert.match(await page.text(), /dev@localtest\.me/);
});

test("an API key created on /keys calls the demo app with a scoped Bearer token", { skip }, async () => {
  const cookieOf = (res: Response, name: string) =>
    res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`))!.split(";")[0];
  const login = await fetch(`${AUTH}/login`, {
    method: "POST",
    redirect: "manual",
    headers: { origin: AUTH, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email: "dev@localtest.me", password: "devpassword123", redirect_uri: "" }),
  });
  assert.equal(login.status, 302);
  const session = cookieOf(login, "ca_session");

  // Create a key with no roles, as the /keys form would (Origin = auth host).
  const create = await fetch(`${AUTH}/keys`, {
    method: "POST",
    headers: { origin: AUTH, cookie: session, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ app: "demo", name: `live test ${Date.now()}`, expires: "30" }),
  });
  assert.equal(create.status, 200, await create.clone().text());
  const html = await create.text();
  const apiKey = html.match(/ca_key_[A-Za-z0-9_-]+/)![0];

  const { apiKeyClient } = await import("../src/api-key-client.ts");
  const client = apiKeyClient({ authBaseUrl: AUTH, apiKey });
  const app = createApp({ authBaseUrl: AUTH, appSlug: "demo", appUrl: "http://demo.localtest.me:3000" });
  const who = await (
    await app.request("http://demo.localtest.me:3000/api/whoami", {
      headers: { authorization: `Bearer ${await client.token()}` },
    })
  ).json();
  assert.equal(who.user.email, "dev@localtest.me");
  assert.deepEqual(who.roles, [], "dev is admin on demo, but the key was given no roles");
  assert.deepEqual(who.user.amr, ["api_key"]);
  assert.deepEqual(Object.keys(who.user.apps), ["demo"]);

  // Clean up: revoke the key through the page.
  const id = [...html.matchAll(/name="key_id" value="([^"]+)"/g)].map((m) => m[1])[0];
  const revoke = await fetch(`${AUTH}/keys/revoke`, {
    method: "POST",
    redirect: "manual",
    headers: { origin: AUTH, cookie: session, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ key_id: id }),
  });
  assert.equal(revoke.status, 302);
});
