// The demo app, separated from server startup so tests can drive it.
import { Hono } from "hono";
import { html } from "hono/html";
import { requireAuth, type AuthConfig, type AuthEnv } from "./auth.ts";

export function createApp(cfg: AuthConfig & { appUrl: string }) {
  const app = new Hono<AuthEnv>();

  app.get("/health", (c) => c.json({ status: "ok" }));

  app.use("*", requireAuth(cfg));

  app.get("/", (c) => {
    const user = c.get("user");
    return c.html(html`<!doctype html>
      <html lang="en">
        <head><meta charset="utf-8"><title>Demo app</title></head>
        <body style="font-family: system-ui; max-width: 40rem; margin: 3rem auto; padding: 0 1rem">
          <h1>Demo app</h1>
          <p>Signed in as <strong>${user.name ?? user.email}</strong> (${user.email}).</p>
          <p>Your roles here: ${c.get("roles").join(", ") || "(none)"}</p>
          <p>Token expires at ${new Date((user.exp ?? 0) * 1000).toISOString()}.</p>
          <form method="post" action="${cfg.authBaseUrl}/logout">
            <input type="hidden" name="redirect_uri" value="${cfg.appUrl}/" />
            <button type="submit">Sign out</button>
          </form>
        </body>
      </html>`);
  });

  app.get("/api/whoami", (c) => c.json({ user: c.get("user"), roles: c.get("roles") }));

  return app;
}
