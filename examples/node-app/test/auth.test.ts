// Testing an app WITHOUT running the auth service: generate a throwaway
// ES256 keypair, serve it as a JWKS from a local HTTP server, and sign tokens
// with the same claim shape clang-auth uses (SPEC §5.3).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { createApp } from "../src/app.ts";

const ISSUER = "https://auth.test";
let jwksServer: Server;
let privateKey: CryptoKey;
let app: ReturnType<typeof createApp>;

before(async () => {
  const keys = await generateKeyPair("ES256");
  privateKey = keys.privateKey;
  const jwk = { ...(await exportJWK(keys.publicKey)), kid: "test-key", alg: "ES256", use: "sig" };
  jwksServer = createServer((_, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  await new Promise<void>((r) => jwksServer.listen(0, "127.0.0.1", r));
  const { port } = jwksServer.address() as AddressInfo;
  app = createApp({
    authBaseUrl: ISSUER,
    appSlug: "demo",
    appUrl: "http://demo.test",
    jwksUrl: `http://127.0.0.1:${port}/jwks.json`,
  });
});

after(() => jwksServer.close());

async function token(opts: { apps?: Record<string, string[]>; exp?: string | number; iss?: string; key?: CryptoKey; kid?: string } = {}) {
  return new SignJWT({ email: "me@example.com", name: "Me", apps: opts.apps ?? { demo: ["admin"] } })
    .setProtectedHeader({ alg: "ES256", kid: opts.kid ?? "test-key" })
    .setSubject("user-1")
    .setIssuer(opts.iss ?? ISSUER)
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .setExpirationTime(opts.exp ?? "15m")
    .sign(opts.key ?? privateKey);
}

const get = (path: string, jwt?: string) =>
  app.request(`http://demo.test${path}`, { headers: jwt ? { cookie: `ca_access=${jwt}` } : {} });

test("valid token shows the user", async () => {
  const res = await get("/", await token());
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.match(body, /Signed in as <strong>Me<\/strong>/);
  assert.match(body, /action="https:\/\/auth.test\/logout"/);
  const who = await (await get("/api/whoami", await token())).json();
  assert.deepEqual(who.roles, ["admin"]);
});

test("missing token redirects to login with redirect_uri", async () => {
  const res = await get("/some/page?x=1");
  assert.equal(res.status, 302);
  const loc = new URL(res.headers.get("location")!);
  assert.equal(loc.origin + loc.pathname, "https://auth.test/login");
  assert.equal(loc.searchParams.get("redirect_uri"), "http://demo.test/some/page?x=1");
});

test("expired token redirects to login", async () => {
  const res = await get("/", await token({ exp: Math.floor(Date.now() / 1000) - 120 }));
  assert.equal(res.status, 302);
});

test("no grant for this app returns 403", async () => {
  const res = await get("/", await token({ apps: { other: ["admin"] } }));
  assert.equal(res.status, 403);
});

test("wrong issuer, unknown key or wrong signature is rejected", async () => {
  assert.equal((await get("/", await token({ iss: "https://evil.test" }))).status, 302);
  const stranger = (await generateKeyPair("ES256")).privateKey;
  assert.equal((await get("/", await token({ key: stranger, kid: "other-key" }))).status, 302);
  assert.equal((await get("/", await token({ key: stranger }))).status, 302, "known kid, wrong key");
  assert.equal((await get("/", "not.a.jwt")).status, 302);
});

test("health is public", async () => {
  assert.equal((await get("/health")).status, 200);
});

const bearer = (path: string, jwt: string, cookieJwt?: string) =>
  app.request(`http://demo.test${path}`, {
    headers: { authorization: `Bearer ${jwt}`, ...(cookieJwt ? { cookie: `ca_access=${cookieJwt}` } : {}) },
  });

test("Bearer token (from an API key) is accepted and exposes amr", async () => {
  const jwt = await new SignJWT({ email: "me@example.com", name: "Me", apps: { demo: [] }, amr: ["api_key"] })
    .setProtectedHeader({ alg: "ES256", kid: "test-key" })
    .setSubject("user-1")
    .setIssuer(ISSUER)
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(privateKey);
  const res = await bearer("/api/whoami", jwt);
  assert.equal(res.status, 200);
  const who = await res.json();
  assert.deepEqual(who.roles, []);
  assert.deepEqual(who.user.amr, ["api_key"]);
});

test("bad Bearer token gets 401 JSON, never a login redirect", async () => {
  for (const jwt of ["not.a.jwt", await token({ iss: "https://evil.test" }), await token({ exp: Math.floor(Date.now() / 1000) - 120 })]) {
    const res = await bearer("/api/whoami", jwt);
    assert.equal(res.status, 401);
    assert.match(res.headers.get("www-authenticate") ?? "", /^Bearer/);
    assert.deepEqual(await res.json(), { error: "invalid_token" });
  }
  // A bad Bearer header doesn't fall back to a valid cookie.
  assert.equal((await bearer("/api/whoami", "not.a.jwt", await token())).status, 401);
});

test("Bearer token without a grant for this app gets 403", async () => {
  const res = await bearer("/api/whoami", await token({ apps: { other: [] } }));
  assert.equal(res.status, 403);
  assert.deepEqual(await res.json(), { error: "no_access" });
});
