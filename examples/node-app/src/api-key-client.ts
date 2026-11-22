// For scripts and local MCP servers: exchange a clang-auth API key for a
// short-lived access token and call an app with it (docs/integration-guide.md).
//
//   const auth = apiKeyClient({ authBaseUrl, apiKey: process.env.CLANG_AUTH_API_KEY! });
//   const res = await auth.fetch("https://cooking.example.com/api/recipes", { method: "POST", ... });
//
// The token is cached until shortly before it expires (tokens live 15
// minutes), so the auth service sees about one request per 15 minutes. If the
// app answers 401, the token is exchanged again once and the request retried,
// so pass a body that can be sent twice (a string, JSON, FormData), not a stream.

export interface ApiKeyClientConfig {
  authBaseUrl: string; // e.g. https://auth.example.com
  apiKey: string; // ca_key_…, created on <authBaseUrl>/keys
  /** Re-exchange this many seconds before expiry. Default 60, capped at half the token's lifetime. */
  refreshSkewSeconds?: number;
  fetch?: typeof fetch;
}

export class ApiKeyRejectedError extends Error {
  constructor() {
    super("clang-auth rejected the API key (revoked, expired, user disabled or grant removed)");
    this.name = "ApiKeyRejectedError";
  }
}

export function apiKeyClient(cfg: ApiKeyClientConfig) {
  const doFetch = cfg.fetch ?? fetch;
  const skew = (cfg.refreshSkewSeconds ?? 60) * 1000;
  let cached: { token: string; refreshAt: number } | undefined;
  let inflight: Promise<string> | undefined;

  async function exchange(): Promise<string> {
    const res = await doFetch(new URL("/api/token", cfg.authBaseUrl), {
      method: "POST",
      headers: { authorization: `Bearer ${cfg.apiKey}` },
    });
    if (res.status === 401) throw new ApiKeyRejectedError();
    if (!res.ok) throw new Error(`clang-auth /api/token failed: ${res.status}`);
    const body = (await res.json()) as { token: string; expires_in: number };
    const lifetime = body.expires_in * 1000;
    // Never refresh earlier than halfway, so short lifetimes still cache.
    cached = { token: body.token, refreshAt: Date.now() + lifetime - Math.min(skew, lifetime / 2) };
    return body.token;
  }

  /** A valid access token, exchanging the API key when needed. */
  async function token(): Promise<string> {
    if (cached && Date.now() < cached.refreshAt) return cached.token;
    // Concurrent callers share one exchange.
    inflight ??= exchange().finally(() => (inflight = undefined));
    return inflight;
  }

  /** `fetch` with `Authorization: Bearer <access token>`; retries once on 401. */
  async function authFetch(input: string | URL, init: RequestInit = {}): Promise<Response> {
    const send = async (t: string) => {
      const headers = new Headers(init.headers);
      headers.set("authorization", `Bearer ${t}`);
      return doFetch(input, { ...init, headers });
    };
    const used = await token();
    const res = await send(used);
    if (res.status !== 401) return res;
    // Drop the token only if it's still the one that failed: when several
    // requests get 401 at once, they then share a single re-exchange.
    if (cached?.token === used) cached = undefined;
    return send(await token());
  }

  return { token, fetch: authFetch };
}
