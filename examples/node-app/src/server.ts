import { serve } from "@hono/node-server";
import { createApp } from "./app.ts";

const authBaseUrl = process.env.AUTH_BASE_URL ?? "http://auth.localtest.me:4000";
const appSlug = process.env.AUTH_APP_SLUG ?? "demo";
const port = Number(process.env.PORT ?? 3000);
const appUrl = process.env.APP_URL ?? `http://demo.localtest.me:${port}`;

const app = createApp({ authBaseUrl, appSlug, appUrl, jwksUrl: process.env.AUTH_JWKS_URL });

// *.localtest.me resolves to both 127.0.0.1 and ::1; listen on both loopbacks.
const hosts = process.env.HOST ? [process.env.HOST] : ["127.0.0.1", "::1"];
for (const hostname of hosts) {
  serve({ fetch: app.fetch, port, hostname });
}
console.log(`demo app on ${appUrl} (auth: ${authBaseUrl}, slug: ${appSlug})`);
