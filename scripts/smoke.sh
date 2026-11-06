#!/usr/bin/env bash
# End-to-end smoke test of the local dev setup (SPEC §15 "fresh clone" item),
# acting like a browser with a cookie jar. Expects, already running:
#   docker compose up -d
#   cargo run -p service -- seed
#   cargo run -p service                    # http://auth.localtest.me:4000
#   (cd examples/node-app && npm start)     # http://demo.localtest.me:3000
set -euo pipefail

AUTH=${AUTH_BASE_URL:-http://auth.localtest.me:4000}
APP=${APP_URL:-http://demo.localtest.me:3000}
JAR=$(mktemp)
trap 'rm -f "$JAR"' EXIT
c() { curl -sS -b "$JAR" -c "$JAR" "$@"; }
pass() { printf '  ok  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; exit 1; }

echo "smoke test: $AUTH and $APP"
# Wait until *clang-auth* answers (over IPv4, and over whichever address
# curl picks by default, as a browser would). Checking the
# JWKS (not just /health) catches another program squatting on the port.
is_clang_auth() { curl -sS -m 2 "$@" "$AUTH/.well-known/jwks.json" 2>/dev/null | grep -q '"kty":"EC"'; }
for _ in $(seq 1 60); do
  is_clang_auth -4 && is_clang_auth && break
  sleep 0.5
done
is_clang_auth || fail "clang-auth is not answering at $AUTH (another program on the port? try: lsof -nP -iTCP:${AUTH##*:} -sTCP:LISTEN)"
[ "$(c "$AUTH/health")" = '{"status":"ok"}' ] && pass "auth service healthy" || fail "auth /health"

# 1. Visiting the app while signed out bounces to the auth login page.
loc=$(c -o /dev/null -w '%{redirect_url}' "$APP/")
case "$loc" in "$AUTH/login?redirect_uri="*) pass "app redirects to login";; *) fail "app redirect: $loc";; esac

# 2. The login page sets the CSRF cookie; submit the form like a browser
#    does from a no-referrer page (Origin: null + csrf field).
page=$(c "$loc")
csrf=$(printf '%s' "$page" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -1)
redirect=$(printf '%s' "$page" | sed -n 's/.*name="redirect_uri" value="\([^"]*\)".*/\1/p' | head -1)
[ -n "$csrf" ] && pass "login form rendered" || fail "no csrf token in login form"
code=$(c -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Origin: null' \
  --data-urlencode "email=dev@localtest.me" --data-urlencode "password=devpassword123" \
  --data-urlencode "redirect_uri=$redirect" --data-urlencode "csrf=$csrf" "$AUTH/login")
[ "$code" = "302 $APP/" ] && pass "login redirects back to the app" || fail "login: $code"

# 3. The app now shows the signed-in user (ca_access cookie on .localtest.me).
c "$APP/" | grep -q "dev@localtest.me" && pass "app shows the logged-in user" || fail "app page"

# 4. Silent refresh from the app's origin.
r=$(c -o /dev/null -w '%{http_code}' -X POST -H "Origin: $APP" "$AUTH/api/session/refresh")
[ "$r" = 200 ] && pass "XHR refresh" || fail "refresh: $r"

# 5. Log out from the app's form; the app bounces to login again.
code=$(c -o /dev/null -w '%{http_code} %{redirect_url}' -H "Origin: $APP" --data-urlencode "redirect_uri=$APP/" "$AUTH/logout")
[ "$code" = "302 $APP/" ] && pass "logout" || fail "logout: $code"
loc=$(c -o /dev/null -w '%{redirect_url}' "$APP/")
case "$loc" in "$AUTH/login"*) pass "signed out of the app";; *) fail "after logout: $loc";; esac
echo "all good"
