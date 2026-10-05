#!/usr/bin/env bash
# End-to-end check of the two example servers.
#
# Starts the in-repo test issuer and both examples, then sends each example
# the same requests and checks the status code and error body of every one:
# no token, a garbage token, a valid token, and a token with and without the
# scope the /admin routes require.
#
# Needs: go, node, curl, and `npm ci && npm run build` done in ts/ (the Express
# example depends on the package by path). `make examples` takes care of that.
set -euo pipefail
cd "$(dirname "$0")/.."

ISSUER=127.0.0.1:18089
GIN=127.0.0.1:18080
EXPRESS=127.0.0.1:18081

bin=$(mktemp -d)
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$bin"
}
trap cleanup EXIT

(cd conformance && go build -o "$bin/issuer" .)
(cd examples/gin-server && go build -o "$bin/gin-server" .)

export JWKIT_ISSUER="http://$ISSUER"
export JWKIT_AUDIENCE="https://api.jwkit.example"
export JWKIT_JWKS_URL="http://$ISSUER/.well-known/jwks.json"

(cd conformance && exec "$bin/issuer" -serve "$ISSUER") >"$bin/issuer.log" 2>&1 &
pids+=($!)
ADDR="$GIN" GIN_MODE=release "$bin/gin-server" >"$bin/gin.log" 2>&1 &
pids+=($!)
(cd examples/express-server && PORT="${EXPRESS##*:}" exec npx tsx server.ts) >"$bin/express.log" 2>&1 &
pids+=($!)

wait_for() {
  for _ in $(seq 1 100); do
    if curl -fsS -o /dev/null "$1" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "FAIL: $1 did not come up" >&2
  cat "$bin"/*.log >&2
  exit 1
}
wait_for "http://$ISSUER/.well-known/jwks.json"
wait_for "http://$GIN/healthz"
wait_for "http://$EXPRESS/healthz"

user_token=$(curl -fsS "http://$ISSUER/token")
admin_token=$(curl -fsS "http://$ISSUER/token?scope=admin")
es256_token=$(curl -fsS "http://$ISSUER/token?alg=ES256")

failures=0
# check <server> <path> <token or -> <expected status> <expected body substring>
check() {
  local server=$1 path=$2 token=$3 want_status=$4 want_body=$5
  local args=(-s -o "$bin/body" -w '%{http_code}')
  if [ "$token" != "-" ]; then args+=(-H "Authorization: Bearer $token"); fi
  local status
  status=$(curl "${args[@]}" "http://$server$path")
  if [ "$status" = "$want_status" ] && grep -qF -- "$want_body" "$bin/body"; then
    printf 'ok    %-22s %-13s -> %s %s\n' "$server" "$path" "$status" "$(cat "$bin/body")"
  else
    printf 'FAIL  %-22s %-13s -> %s %s (wanted %s containing %s)\n' "$server" "$path" "$status" "$(cat "$bin/body")" "$want_status" "$want_body"
    failures=$((failures + 1))
  fi
}

for server in "$GIN" "$EXPRESS"; do
  check "$server" /healthz     -              200 'ok'
  check "$server" /api/me      -              401 '{"error":"ErrMissingToken"}'
  check "$server" /api/me      not.a.token    401 '{"error":"ErrMalformed"}'
  check "$server" /api/me      "$user_token"  200 '"sub":"user-123"'
  check "$server" /api/me      "$user_token"  200 '"scopes":[]'
  check "$server" /api/me      "$admin_token" 200 '"scopes":["admin"]'
  check "$server" /api/me      "$es256_token" 200 '"sub":"user-123"'
  check "$server" /admin/stats "$user_token"  403 '{"error":"ErrInsufficientScope"}'
  check "$server" /admin/stats "$admin_token" 200 '"requests":42'
done

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "both examples behave identically on all checks"
