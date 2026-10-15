#!/usr/bin/env bash
# End-to-end check against a running stack (`docker compose up -d` first):
# waits for the API, creates a throwaway operator login, and exercises login → /auth/me →
# logout → replayed cookie rejected. Used by CI; safe to run locally, but it REPLACES the
# operator password, so run `quiver-admin set-password` again afterwards.
set -euo pipefail

API="http://127.0.0.1:${QUIVER_API_PORT:-8000}"
JAR="$(mktemp)"
OLD="$(mktemp)"
trap 'rm -f "$JAR" "$OLD"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "Waiting for API at $API ..."
for _ in $(seq 1 60); do
  [ "$(status "$API/health")" = "200" ] && break
  sleep 2
done
[ "$(status "$API/health")" = "200" ] || fail "API never became healthy"

PASSWORD="smoke-$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s\n' "$PASSWORD" | docker compose exec -T api quiver-admin set-password --password-stdin

[ "$(status "$API/auth/me")" = "401" ] || fail "/auth/me reachable without login"
[ "$(status "$API/docs")" = "404" ] || fail "API docs exposed"

login() {
  curl -s -o /dev/null -w '%{http_code}' -c "$JAR" -H 'Content-Type: application/json' \
    -d "{\"username\":\"operator\",\"password\":\"$1\"}" "$API/auth/login"
}
[ "$(login wrong-password-123)" = "401" ] || fail "wrong password accepted"
[ "$(login "$PASSWORD")" = "200" ] || fail "login failed"
[ "$(status -b "$JAR" "$API/auth/me")" = "200" ] || fail "/auth/me rejected a valid session"

cp "$JAR" "$OLD"
[ "$(status -b "$JAR" -X POST "$API/auth/logout")" = "204" ] || fail "logout failed"
[ "$(status -b "$OLD" "$API/auth/me")" = "401" ] || fail "session still valid after logout"

echo "Smoke test passed."
