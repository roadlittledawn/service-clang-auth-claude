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
