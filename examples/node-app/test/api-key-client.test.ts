// The API-key exchange helper used by scripts and local MCP servers.
import { test } from "node:test";
import assert from "node:assert/strict";
import { apiKeyClient, ApiKeyRejectedError } from "../src/api-key-client.ts";

const AUTH = "https://auth.test";

/** A fake fetch: /api/token hands out numbered tokens; the app accepts only `valid`. */
function fake(opts: { keyOk?: boolean; valid?: (t: string) => boolean } = {}) {
  const calls = { exchanges: 0, app: [] as string[] };
  const f: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const auth = new Headers(init?.headers).get("authorization") ?? "";
    if (url.pathname === "/api/token") {
      assert.equal(init?.method, "POST");
      assert.equal(auth, "Bearer ca_key_test");
      if (opts.keyOk === false) return new Response('{"error":{}}', { status: 401 });
      calls.exchanges++;
      return Response.json({ token: `t${calls.exchanges}`, token_type: "Bearer", expires_in: 900 });
    }
    const t = auth.replace("Bearer ", "");
    calls.app.push(t);
    return new Response("ok", { status: (opts.valid ?? (() => true))(t) ? 200 : 401 });
  };
  return { f, calls };
}

test("caches the token across calls and shares concurrent exchanges", async () => {
  const { f, calls } = fake();
  const c = apiKeyClient({ authBaseUrl: AUTH, apiKey: "ca_key_test", fetch: f });
  await Promise.all([c.token(), c.token(), c.token()]);
  await c.fetch("https://app.test/a");
  await c.fetch("https://app.test/b", { headers: { "x-other": "1" } });
  assert.equal(calls.exchanges, 1);
  assert.deepEqual(calls.app, ["t1", "t1"]);
});

test("re-exchanges near expiry", async () => {
  const { f, calls } = fake();
  // A skew larger than the 900 s lifetime makes every token "about to expire".
  const c = apiKeyClient({ authBaseUrl: AUTH, apiKey: "ca_key_test", fetch: f, refreshSkewSeconds: 1000 });
  await c.token();
  await c.token();
  assert.equal(calls.exchanges, 2);
});

test("retries once with a fresh token when the app answers 401", async () => {
  const { f, calls } = fake({ valid: (t) => t !== "t1" });
  const c = apiKeyClient({ authBaseUrl: AUTH, apiKey: "ca_key_test", fetch: f });
  const res = await c.fetch("https://app.test/a");
  assert.equal(res.status, 200);
  assert.deepEqual(calls.app, ["t1", "t2"]);

  const { f: f2, calls: calls2 } = fake({ valid: () => false });
  const c2 = apiKeyClient({ authBaseUrl: AUTH, apiKey: "ca_key_test", fetch: f2 });
  assert.equal((await c2.fetch("https://app.test/a")).status, 401, "only one retry");
  assert.equal(calls2.app.length, 2);
});

test("a rejected key throws ApiKeyRejectedError", async () => {
  const { f } = fake({ keyOk: false });
  const c = apiKeyClient({ authBaseUrl: AUTH, apiKey: "ca_key_test", fetch: f });
  await assert.rejects(c.token(), ApiKeyRejectedError);
});
