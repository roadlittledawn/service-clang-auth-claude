// clang-auth verification middleware for Hono (docs/integration-guide.md).
// Verifies the access token (`ca_access` cookie, or `Authorization: Bearer`
// from an API-key exchange) locally against the JWKS: no network call per request.
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
