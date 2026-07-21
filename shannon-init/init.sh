#!/bin/sh
# Bootstrap Shannon: authenticate, create a Claude token, assign it to the admin user.
# Idempotent — safe to run multiple times.

set -e

SHANNON_URL="${SHANNON_URL:-http://shannon-web:4000}"
ADMIN_EMAIL="${SHANNON_ADMIN_EMAIL:-admin@localhost}"
ADMIN_PASSWORD="${SHANNON_ADMIN_PASSWORD:-admin}"

# ── Pick which token to register ──────────────────────────────────────────────
if [ -n "$CLAUDE_CODE_OAUTH_TOKEN" ]; then
  TOKEN_VALUE="$CLAUDE_CODE_OAUTH_TOKEN"
  TOKEN_TYPE="oauth"
elif [ -n "$ANTHROPIC_API_KEY" ]; then
  TOKEN_VALUE="$ANTHROPIC_API_KEY"
  TOKEN_TYPE="api_key"
else
  echo "[shannon-init] No CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY set — Shannon workers will have no Claude token."
  echo "[shannon-init] Set one in your .env file to enable web app scanning."
  exit 0
fi

# ── Wait for Shannon web server ────────────────────────────────────────────────
echo "[shannon-init] Waiting for Shannon web server at $SHANNON_URL ..."
for i in $(seq 1 30); do
  if curl -sf "$SHANNON_URL/api/system/status" > /dev/null 2>&1; then
    echo "[shannon-init] Shannon is up."
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "[shannon-init] Shannon did not become ready in time. Exiting."
    exit 1
  fi
  sleep 3
done

# ── Authenticate ───────────────────────────────────────────────────────────────
echo "[shannon-init] Authenticating as $ADMIN_EMAIL ..."
LOGIN_RESP=$(curl -sf -X POST "$SHANNON_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")

JWT=$(echo "$LOGIN_RESP" | jq -r '.token // empty')
if [ -z "$JWT" ]; then
  echo "[shannon-init] Login failed: $LOGIN_RESP"
  exit 1
fi
echo "[shannon-init] Authenticated."

AUTH="-H \"Authorization: Bearer $JWT\""

# ── Get admin user ID ──────────────────────────────────────────────────────────
USERS=$(curl -sf "$SHANNON_URL/api/admin/users" \
  -H "Authorization: Bearer $JWT")
ADMIN_ID=$(echo "$USERS" | jq -r --arg email "$ADMIN_EMAIL" \
  '.[] | select(.email == $email) | .id // empty' | head -1)
ADMIN_TOKEN_ID=$(echo "$USERS" | jq -r --arg email "$ADMIN_EMAIL" \
  '.[] | select(.email == $email) | .token_id // empty' | head -1)

if [ -z "$ADMIN_ID" ]; then
  echo "[shannon-init] Could not find admin user in Shannon. Exiting."
  exit 1
fi
echo "[shannon-init] Admin user ID: $ADMIN_ID"

# ── Create or reuse token ──────────────────────────────────────────────────────
if [ -n "$ADMIN_TOKEN_ID" ] && [ "$ADMIN_TOKEN_ID" != "null" ]; then
  echo "[shannon-init] Admin already has token ID $ADMIN_TOKEN_ID assigned — skipping."
  exit 0
fi

echo "[shannon-init] Creating Claude token (type: $TOKEN_TYPE) ..."
TOKEN_RESP=$(curl -sf -X POST "$SHANNON_URL/api/admin/tokens" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"quiver-default\",\"value\":\"$TOKEN_VALUE\",\"token_type\":\"$TOKEN_TYPE\"}")
TOKEN_ID=$(echo "$TOKEN_RESP" | jq -r '.id // empty')

if [ -z "$TOKEN_ID" ]; then
  echo "[shannon-init] Failed to create token: $TOKEN_RESP"
  exit 1
fi
echo "[shannon-init] Token created with ID: $TOKEN_ID"

# ── Assign token to admin user ─────────────────────────────────────────────────
echo "[shannon-init] Assigning token to admin user ..."
ASSIGN_RESP=$(curl -sf -X PUT "$SHANNON_URL/api/admin/users/$ADMIN_ID/token" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d "{\"tokenId\":$TOKEN_ID}")
echo "[shannon-init] $ASSIGN_RESP"
echo "[shannon-init] Done. Shannon is ready for web app scanning."
