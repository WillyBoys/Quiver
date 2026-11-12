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

# Engagement + scope round trip (exercises the latest migration inside the real stack).
post() { curl -s -b "$JAR" -H 'Content-Type: application/json' -d "$2" "$API$1"; }
ENG_ID="$(post /engagements '{"name":"smoke test"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')" \
  || fail "could not create engagement"
SCOPE="$(post "/engagements/$ENG_ID/scope" '{"value":"*.Example.COM","reason":"smoke test"}')"
echo "$SCOPE" | grep -q '"value":"\*.example.com"' || fail "scope entry not normalized: $SCOPE"
BAD="$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" -H 'Content-Type: application/json' \
  -d '{"value":"*.com","reason":"smoke test"}' "$API/engagements/$ENG_ID/scope")"
[ "$BAD" = "422" ] || fail "public-suffix wildcard accepted ($BAD)"
curl -s -b "$JAR" "$API/engagements/$ENG_ID/scope/changes" | grep -q '"action":"add"' \
  || fail "scope change not audited"

# Policy gate tables (latest migration): kill switches and scope suggestions.
put() { curl -s -b "$JAR" -X PUT -H 'Content-Type: application/json' -d "$2" "$API$1"; }
put "/engagements/$ENG_ID/kill-switch" '{"engaged":true,"reason":"smoke test"}' \
  | grep -q '"engaged":true' || fail "engagement kill switch did not engage"
put "/engagements/$ENG_ID/kill-switch" '{"engaged":false,"reason":"smoke test"}' \
  | grep -q '"engaged":false' || fail "engagement kill switch did not release"
curl -s -b "$JAR" "$API/kill-switch" | grep -q '"engaged":false' || fail "global kill switch unreadable"
[ "$(curl -s -b "$JAR" "$API/engagements/$ENG_ID/suggestions")" = "[]" ] \
  || fail "suggestions list unexpected"
[ "$(curl -s -b "$JAR" "$API/engagements/$ENG_ID/resolutions")" = "[]" ] \
  || fail "resolutions list unexpected"

# Knowledge graph (read-only API) starts empty.
curl -s -b "$JAR" "$API/engagements/$ENG_ID/entities" | grep -q '"total":0' || fail "entities unexpected"
[ "$(curl -s -b "$JAR" "$API/engagements/$ENG_ID/findings")" = "[]" ] || fail "findings unexpected"
[ "$(curl -s -b "$JAR" "$API/engagements/$ENG_ID/runs")" = "[]" ] || fail "runs unexpected"

# Jobs end to end: API → worker (gate, approval) → executor → result.
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)"; }
put "/engagements/$ENG_ID/authorization" \
  '{"authorized_by":"Smoke","authorizer_organization":"CI","authorized_on":"2026-01-01"}' >/dev/null
post "/engagements/$ENG_ID/scope" '{"value":"203.0.113.0/24","reason":"smoke test"}' >/dev/null
post "/engagements/$ENG_ID/windows" \
  '{"timezone":"UTC","days":[1,2,3,4,5,6,7],"start_time":"00:00","end_time":"00:00"}' >/dev/null
curl -s -b "$JAR" -X PATCH -H 'Content-Type: application/json' -d '{"status":"active"}' \
  "$API/engagements/$ENG_ID" | grep -q '"status":"active"' || fail "engagement did not activate"

job_status() { curl -s -b "$JAR" "$API/engagements/$ENG_ID/jobs/$1" | field '["status"]'; }
wait_for() { # wait_for <job id> <status>
  for _ in $(seq 1 60); do
    s="$(job_status "$1")"
    [ "$s" = "$2" ] && return 0
    sleep 1
  done
  fail "job $1 is '$s', expected '$2': $(curl -s -b "$JAR" "$API/engagements/$ENG_ID/jobs/$1")"
}

JOB="$(post "/engagements/$ENG_ID/jobs" '{"tool":"run_command","params":{"argv":["echo","smoke"]}}' \
  | field '["id"]')" || fail "job not accepted"
wait_for "$JOB" awaiting_approval
APPROVAL="$(curl -s -b "$JAR" "$API/engagements/$ENG_ID/approvals?status=pending" | field '[0]["id"]')"
post "/engagements/$ENG_ID/approvals/$APPROVAL/approve" '{"note":"smoke test"}' \
  | grep -q '"status":"approved"' || fail "approval failed"
wait_for "$JOB" succeeded
[ "$(docker compose exec -T executor cat "/data/job_output/$JOB/output.log")" = "smoke" ] \
  || fail "job output missing"

DENIED="$(post "/engagements/$ENG_ID/jobs" \
  '{"tool":"run_command","params":{"argv":["curl","http://198.51.100.7/"]}}' | field '["id"]')"
wait_for "$DENIED" denied

# The tools run as the unprivileged user with a job's scrubbed environment (no PYTHONPATH).
[ "$(docker compose exec -T executor id -u)" = "10001" ] || fail "executor not running as 10001"
tool() { docker compose exec -T executor env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp "$@"; }
tool subfinder -version >/dev/null 2>&1 || fail "subfinder does not run"
tool dnsx -version >/dev/null 2>&1 || fail "dnsx does not run"
tool quiver-ct --help | grep -q 'quiver-ct' || fail "quiver-ct does not run"

# The executor is isolated: no secrets, no database, and job specs are read-only.
docker compose exec -T executor sh -c 'ls /run/secrets' >/dev/null 2>&1 \
  && fail "executor can see secrets"
docker compose exec -T executor sh -c 'touch /data/job_specs/forged.json' >/dev/null 2>&1 \
  && fail "executor can write job specs"
docker compose exec -T executor python -c \
  'import socket; socket.create_connection(("db", 5432), timeout=3)' >/dev/null 2>&1 \
  && fail "executor can reach the database"

cp "$JAR" "$OLD"
[ "$(status -b "$JAR" -X POST "$API/auth/logout")" = "204" ] || fail "logout failed"
[ "$(status -b "$OLD" "$API/auth/me")" = "401" ] || fail "session still valid after logout"

echo "Smoke test passed."
