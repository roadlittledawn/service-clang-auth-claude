// clang-auth verification middleware for Hono (docs/integration-guide.md).
// Verifies the `ca_access` cookie locally against the auth service's JWKS:
// no network call per request (jose caches the keys).
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
}

export type AuthEnv = { Variables: { user: Claims; roles: string[] } };

export function requireAuth(cfg: AuthConfig): MiddlewareHandler<AuthEnv> {
  const jwks = createRemoteJWKSet(new URL(cfg.jwksUrl ?? `${cfg.authBaseUrl}/.well-known/jwks.json`));
  return async (c, next) => {
    const token = getCookie(c, "ca_access");
    let claims: Claims | undefined;
    if (token) {
      try {
        // Checks the ES256 signature (key chosen by `kid`), `iss` and `exp`.
        const { payload } = await jwtVerify<Claims>(token, jwks, {
          issuer: cfg.issuer ?? cfg.authBaseUrl,
          algorithms: ["ES256"],
          clockTolerance: 30,
        });
        claims = payload;
      } catch {
        // Expired, forged or signed by an unknown key: treat as signed out.
      }
    }
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
