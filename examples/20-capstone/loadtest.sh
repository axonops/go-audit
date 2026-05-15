#!/usr/bin/env bash
# Copyright 2026 AxonOps Limited.
# Licensed under the Apache License, Version 2.0.
#
# loadtest.sh — Generates 300+ diverse audit events across all event
# types, categories, and severity levels. Run this after starting the
# application to populate Grafana dashboards with meaningful data.
#
# Prerequisites: curl, jq
# Usage: ./loadtest.sh [BASE_URL]

set -euo pipefail

BASE="${1:-http://localhost:8080}"

command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq is required"; exit 1; }

TOTAL=0
ERRORS=0

# Helper: make an API call and count it.
call() {
    local method="$1" path="$2" auth="$3"
    shift 3
    local body="${1:-}"
    local args=(-s -o /dev/null -w "%{http_code}" -X "$method")
    args+=(-H "Content-Type: application/json")

    if [[ "$auth" == api:* ]]; then
        args+=(-H "X-API-Key: ${auth#api:}")
    elif [[ "$auth" == bearer:* ]]; then
        args+=(-H "Authorization: Bearer ${auth#bearer:}")
    fi

    if [[ -n "$body" ]]; then
        args+=(-d "$body")
    fi

    local code
    code=$(curl "${args[@]}" "${BASE}${path}")
    TOTAL=$((TOTAL + 1))
    if [[ "$code" -ge 400 ]]; then
        ERRORS=$((ERRORS + 1))
    fi
}

# Helper: make a call and extract JSON field from response.
call_json() {
    local method="$1" path="$2" auth="$3" field="$4"
    shift 4
    local body="${1:-}"
    local args=(-s -X "$method")
    args+=(-H "Content-Type: application/json")

    if [[ "$auth" == api:* ]]; then
        args+=(-H "X-API-Key: ${auth#api:}")
    elif [[ "$auth" == bearer:* ]]; then
        args+=(-H "Authorization: Bearer ${auth#bearer:}")
    fi

    if [[ -n "$body" ]]; then
        args+=(-d "$body")
    fi

    local result
    result=$(curl "${args[@]}" "${BASE}${path}")
    TOTAL=$((TOTAL + 1))
    echo "$result" | jq -r ".$field // empty"
}

echo "=== audit Load Test ==="
echo "Target: $BASE"
echo ""

# --- Phase 1: Create users ---
echo "Phase 1: Creating users..."
for i in $(seq 1 5); do
    call POST "/users" "api:key-admin" \
        "{\"username\":\"user${i}\",\"email\":\"user${i}@example.com\",\"phone\":\"+1555000${i}\"}"
done
# Get user IDs for later.
USER1=$(call_json GET "/users" "api:key-alice" ".[0].id")
USER2=$(call_json GET "/users" "api:key-alice" ".[1].id" 2>/dev/null || echo "")
echo "  Created 5 users (first: ${USER1:-none})"

# --- Phase 2: Login/logout sessions ---
echo "Phase 2: Authentication events..."
# Successful logins.
TOKEN_ALICE=$(call_json POST "/login" "" "token" '{"username":"alice","password":"password"}')
TOKEN_BOB=$(call_json POST "/login" "" "token" '{"username":"bob","password":"password"}')
TOKEN_ADMIN=$(call_json POST "/login" "" "token" '{"username":"admin","password":"admin123"}')

# Failed logins (auth_failure events).
for i in $(seq 1 3); do
    call POST "/login" "" '{"username":"alice","password":"wrong"}'
    call POST "/login" "" '{"username":"nonexistent","password":"xxx"}'
done

# Logout and re-login.
call POST "/logout" "bearer:${TOKEN_BOB}"
TOKEN_BOB=$(call_json POST "/login" "" "token" '{"username":"bob","password":"password"}')
echo "  3 logins, 6 failures, 1 logout+relogin"

# --- Phase 3: Create items ---
echo "Phase 3: Creating items..."
ITEM_IDS=()
for i in $(seq 1 20); do
    id=$(call_json POST "/items" "bearer:${TOKEN_ALICE}" "id" \
        "{\"name\":\"Widget ${i}\",\"description\":\"A useful widget number ${i}\"}")
    if [[ -n "$id" ]]; then
        ITEM_IDS+=("$id")
    fi
done
echo "  Created ${#ITEM_IDS[@]} items"

# --- Phase 4: Read operations (high volume) ---
echo "Phase 4: Read operations..."
for i in $(seq 1 30); do
    call GET "/items" "bearer:${TOKEN_ALICE}"
    call GET "/users" "bearer:${TOKEN_BOB}"
    call GET "/orders" "bearer:${TOKEN_ALICE}"
done
# Read individual items.
for id in "${ITEM_IDS[@]:0:10}"; do
    call GET "/items/${id}" "bearer:${TOKEN_ALICE}"
    call GET "/items/${id}" "bearer:${TOKEN_BOB}"
done
echo "  90 list + 20 get operations"

# --- Phase 5: Create orders ---
echo "Phase 5: Creating orders..."
ORDER_IDS=()
if [[ -n "${USER1:-}" ]] && [[ ${#ITEM_IDS[@]} -gt 0 ]]; then
    for i in $(seq 1 10); do
        idx=$(( (i - 1) % ${#ITEM_IDS[@]} ))
        # Alternate between USER1 and USER2 for diversity.
        uid="${USER1}"
        if [[ -n "${USER2:-}" ]] && (( i % 2 == 0 )); then
            uid="${USER2}"
        fi
        id=$(call_json POST "/orders" "bearer:${TOKEN_ALICE}" "id" \
            "{\"user_id\":\"${uid}\",\"item_id\":\"${ITEM_IDS[$idx]}\",\"quantity\":${i}}")
        if [[ -n "$id" ]]; then
            ORDER_IDS+=("$id")
        fi
    done
fi
echo "  Created ${#ORDER_IDS[@]} orders"

# --- Phase 6: Update operations ---
echo "Phase 6: Update operations..."
for id in "${ITEM_IDS[@]:0:5}"; do
    call PUT "/items/${id}" "bearer:${TOKEN_ALICE}" \
        "{\"name\":\"Updated Widget\",\"description\":\"Improved version\"}"
done
for id in "${ORDER_IDS[@]:0:5}"; do
    call PUT "/orders/${id}" "bearer:${TOKEN_ALICE}" '{"status":"shipped"}'
done
for id in "${ORDER_IDS[@]:5:5}"; do
    call PUT "/orders/${id}" "bearer:${TOKEN_ALICE}" '{"status":"delivered"}'
done
echo "  5 item updates, 10 order updates"

# --- Phase 7: Auth failures with different users ---
echo "Phase 7: Authorization failures..."
# Non-admin tries admin endpoints (authorization_failure events).
for i in $(seq 1 5); do
    call GET "/admin/settings" "bearer:${TOKEN_ALICE}"
    call PUT "/admin/settings" "bearer:${TOKEN_BOB}" '{"key":"maintenance_mode","value":"true"}'
    call GET "/export/users" "bearer:${TOKEN_ALICE}"
    call DELETE "/admin/bulk-delete/items" "bearer:${TOKEN_BOB}"
done
echo "  20 authorization failures"

# --- Phase 8: Admin operations ---
echo "Phase 8: Admin operations..."
call PUT "/admin/settings" "bearer:${TOKEN_ADMIN}" \
    '{"key":"rate_limit_threshold","value":"10"}'
call PUT "/admin/settings" "bearer:${TOKEN_ADMIN}" \
    '{"key":"session_timeout_minutes","value":"60"}'
call PUT "/admin/settings" "bearer:${TOKEN_ADMIN}" \
    '{"key":"maintenance_mode","value":"true"}'
call PUT "/admin/settings" "bearer:${TOKEN_ADMIN}" \
    '{"key":"maintenance_mode","value":"false"}'
echo "  4 config changes"

# --- Phase 9: Compliance events ---
echo "Phase 9: Compliance events..."
call GET "/export/users" "bearer:${TOKEN_ADMIN}"
call GET "/export/users" "bearer:${TOKEN_ADMIN}"
call DELETE "/admin/bulk-delete/items" "bearer:${TOKEN_ADMIN}"
echo "  2 data exports, 1 bulk delete"

# --- Phase 10: Delete operations ---
echo "Phase 10: Delete operations..."
for id in "${ITEM_IDS[@]:10:5}"; do
    call DELETE "/items/${id}" "bearer:${TOKEN_ALICE}"
done
echo "  5 item deletes"

# --- Phase 11: Rate limiting ---
echo "Phase 11: Rate limiting (triggering 429)..."
for i in $(seq 1 8); do
    call POST "/login" "" '{"username":"alice","password":"wrong"}'
done
echo "  8 failed logins (should trigger rate_limit_exceeded)"

# --- Summary ---
echo ""
echo "=== Load Test Complete ==="
echo "  Total API calls: $TOTAL"
echo "  Expected errors:  $ERRORS (auth failures, rate limits, admin denials)"
echo ""
echo "Check your outputs:"
echo "  Grafana:       http://localhost:3000"
echo "  stdout:        docker compose logs app | tail -20"
echo "  audit.log:     head -5 audit.log"
echo "  security.log:  head -5 security.log"
