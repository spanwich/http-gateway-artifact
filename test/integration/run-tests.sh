#!/bin/bash
#
# run-tests-v2.sh — Phase 4 bearer token endpoint tests for seL4 HTTP Gateway
#
# Tests the 7-component XACML-aligned architecture with stateless bearer tokens.
#
# Usage:
#   ./run-tests-v2.sh                              # Use existing images
#   ./run-tests-v2.sh /path/to/build-http-gw-cp    # Copy images first
#
# Requires: docker, curl, jq (optional, for token extraction)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER_NAME="http-gw-autotest"
IMAGE_NAME="http-gateway-base"
BOOT_TIMEOUT=60
PORT=8443

# --- Cleanup ---
cleanup() {
    if docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
        echo "Stopping container..."
        docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# --- Copy images if build path provided ---
if [ $# -ge 1 ]; then
    BUILD_DIR="$1"
    echo "Copying images from $BUILD_DIR..."
    "$SCRIPT_DIR/update-images.sh" "$BUILD_DIR"
    echo ""
fi

# --- Verify images ---
for img in kernel-x86_64-pc99 capdl-loader-image-x86_64-pc99; do
    if [ ! -f "$SCRIPT_DIR/sel4-image/$img" ]; then
        echo "FATAL: Image not found: $SCRIPT_DIR/sel4-image/$img"
        exit 1
    fi
done

# --- Build Docker base image if needed ---
if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Building Docker base image..."
    docker build -f "$SCRIPT_DIR/Dockerfile.base" -t "$IMAGE_NAME" "$SCRIPT_DIR"
fi

# --- Stop any previous container ---
if docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "Stopping previous container..."
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    sleep 1
fi

# --- Check port availability ---
if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    echo "FATAL: Port $PORT is already in use"
    ss -tlnp | grep ":${PORT} "
    exit 1
fi

# --- Launch QEMU in Docker ---
echo "=== Launching QEMU in Docker (SLIRP) ==="
docker run --rm -d \
    --name "$CONTAINER_NAME" \
    -p "${PORT}:${PORT}" \
    -v "$SCRIPT_DIR/sel4-image:/sel4-image:ro" \
    "$IMAGE_NAME" \
    /usr/local/bin/start-gateway-slirp.sh >/dev/null

echo "Container: $CONTAINER_NAME"
echo "Waiting for boot (timeout: ${BOOT_TIMEOUT}s)..."

# --- Wait for boot ---
ELAPSED=0
READY=false
while [ $ELAPSED -lt $BOOT_TIMEOUT ]; do
    if docker logs "$CONTAINER_NAME" 2>/dev/null | grep -q "\[LwipProxy\] Ready:"; then
        READY=true
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

if ! $READY; then
    echo "FATAL: Boot timeout after ${BOOT_TIMEOUT}s"
    echo "--- Container logs (last 30 lines) ---"
    docker logs --tail 30 "$CONTAINER_NAME" 2>/dev/null || echo "(no logs)"
    exit 1
fi

echo "Boot complete in ${ELAPSED}s"
sleep 3  # Let lwIP + TLS listener finish setup
echo ""

# --- HTTP Endpoint Tests (Phase 4: Bearer Token Auth) ---
PASS=0
FAIL=0
TOTAL=7

run_test() {
    local test_num="$1"
    local description="$2"
    local expected_code="$3"
    shift 3

    local actual_code
    actual_code=$(curl -sk -o /dev/null -w "%{http_code}" \
        --connect-timeout 15 --max-time 30 "$@" 2>/dev/null) || actual_code="000"

    if [ "$actual_code" = "$expected_code" ]; then
        echo "  PASS [$test_num] $description (HTTP $actual_code)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL [$test_num] $description (expected $expected_code, got $actual_code)"
        FAIL=$((FAIL + 1))
    fi
}

# Helper: extract token from login response JSON
extract_token() {
    local response="$1"
    # Try jq first, fall back to grep/sed
    if command -v jq >/dev/null 2>&1; then
        echo "$response" | jq -r '.token // empty' 2>/dev/null
    else
        echo "$response" | grep -o '"token":"[^"]*"' | sed 's/"token":"//;s/"//'
    fi
}

echo "=== Running Phase 4 Bearer Token Tests ==="

# Test 1: GET /api/status without token -> 401 Unauthorized
run_test 1 "GET /api/status (no token)" "401" \
    "https://localhost:${PORT}/api/status"

# Test 2: POST /api/login (admin) -> 200 + token
LOGIN_RESPONSE=$(curl -sk --connect-timeout 15 --max-time 30 \
    -X POST -d '{"username":"admin","password":"admin456"}' \
    "https://localhost:${PORT}/api/login" 2>/dev/null) || LOGIN_RESPONSE=""
LOGIN_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 15 --max-time 30 \
    -X POST -d '{"username":"admin","password":"admin456"}' \
    "https://localhost:${PORT}/api/login" 2>/dev/null) || LOGIN_CODE="000"

if [ "$LOGIN_CODE" = "200" ]; then
    echo "  PASS [2] POST /api/login (admin) (HTTP $LOGIN_CODE)"
    PASS=$((PASS + 1))
else
    echo "  FAIL [2] POST /api/login (admin) (expected 200, got $LOGIN_CODE)"
    FAIL=$((FAIL + 1))
fi

# Extract token from login response
TOKEN=$(extract_token "$LOGIN_RESPONSE")
if [ -n "$TOKEN" ]; then
    echo "       Token obtained: ${TOKEN:0:20}..."
else
    echo "       WARNING: Could not extract token from response"
    echo "       Response: ${LOGIN_RESPONSE:0:100}"
fi

# Test 3: GET /api/status with valid token -> 200
if [ -n "$TOKEN" ]; then
    run_test 3 "GET /api/status (with bearer token)" "200" \
        -H "Authorization: Bearer $TOKEN" \
        "https://localhost:${PORT}/api/status"
else
    echo "  SKIP [3] GET /api/status (no token available)"
    FAIL=$((FAIL + 1))
fi

# Test 4: GET /api/status with bad token -> 403
run_test 4 "GET /api/status (bad token)" "403" \
    -H "Authorization: Bearer invalid_token_here" \
    "https://localhost:${PORT}/api/status"

# Test 5: POST /api/login (operator) -> 200
# Allow TLS session cleanup after 6 prior connections (test 2 makes 2 requests)
sleep 2
run_test 5 "POST /api/login (operator)" "200" \
    -X POST -d '{"username":"operator","password":"oper789"}' \
    "https://localhost:${PORT}/api/login"

# Test 6: Policy upload (admin login -> PUT /api/policy -> verify operator denied)
sleep 1
echo ""
echo "--- Test 6: Policy upload ---"
# Login as admin to get a fresh token
ADMIN_LOGIN=$(curl -sk --connect-timeout 15 --max-time 30 \
    -X POST -d '{"username":"admin","password":"admin456"}' \
    "https://localhost:${PORT}/api/login" 2>/dev/null) || ADMIN_LOGIN=""
ADMIN_TOKEN=$(extract_token "$ADMIN_LOGIN")

if [ -n "$ADMIN_TOKEN" ]; then
    # Build 65-byte binary policy: [num_rules:1][rule_0:8]...[rule_7:8]
    # Write to temp file to avoid bash null-byte stripping in $()
    POLICY_FILE=$(mktemp)
    python3 -c "
import struct, sys
rules = [
    (0x33333333, 1, 2, 0x0001),  # STATUS/GET/ADMIN/READ_SENSORS
    (0x22222222, 2, 1, 0x0000),  # LOGOUT/POST/OPER/none
    (0x44444444, 1, 2, 0x0004),  # POLICY/GET/ADMIN/CONFIGURE
] + [(0xDEADDEAD, 0, 0, 0)] * 5
data = bytes([3])  # num_rules
for ph, m, r, s in rules:
    data += struct.pack('<I', ph) + bytes([m, r]) + struct.pack('<H', s)
assert len(data) == 65, f'Expected 65 bytes, got {len(data)}'
with open('$POLICY_FILE', 'wb') as f:
    f.write(data)
" 2>/dev/null
    echo "       Policy file: $(wc -c < "$POLICY_FILE") bytes"

    # PUT /api/policy with admin token -> expect 200
    run_test 6 "PUT /api/policy (admin token)" "200" \
        -X PUT \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@${POLICY_FILE}" \
        "https://localhost:${PORT}/api/policy"
    rm -f "$POLICY_FILE" 2>/dev/null || true
else
    echo "  SKIP [6] PUT /api/policy (no admin token)"
    FAIL=$((FAIL + 1))
fi

# Test 7: Rate limit test
# Send many requests rapidly, expect 429 after rate limit
sleep 1
echo ""
echo "--- Test 7: Rate limit ---"
RATE_TOKEN=""
RATE_LOGIN=$(curl -sk --connect-timeout 15 --max-time 30 \
    -X POST -d '{"username":"admin","password":"admin456"}' \
    "https://localhost:${PORT}/api/login" 2>/dev/null) || RATE_LOGIN=""
RATE_TOKEN=$(extract_token "$RATE_LOGIN")

if [ -n "$RATE_TOKEN" ]; then
    # Send requests until 429 or 55 attempts exhausted.
    # RateLimiter counts ALL authenticated requests for subject "admin",
    # including test 3 (GET /status) and test 6 (PUT /policy) which ran
    # earlier with different admin tokens but the same subject_id.
    # Pre-loop count = 2 (test 3 + test 6), so 429 expected at loop
    # iteration #48 (2 + 48 = 50 = MAX_RATE).
    # Each request goes through full TLS handshake, so allow time for
    # single-core QEMU to process each one.
    GOT_429=false
    LAST_CODE=""
    for i in $(seq 1 55); do
        CODE=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 10 --max-time 15 \
            -H "Authorization: Bearer $RATE_TOKEN" \
            "https://localhost:${PORT}/api/status" 2>/dev/null) || CODE="000"
        LAST_CODE="$CODE"
        if [ "$CODE" = "429" ]; then
            GOT_429=true
            echo "       Got 429 on request #$i"
            break
        fi
        if [ "$CODE" = "000" ]; then
            echo "       Request #$i: connection failed, waiting 3s..."
            sleep 3
            continue
        fi
        # Progress indicator every 10 requests
        [ $((i % 10)) -eq 0 ] && echo "       Request #$i: HTTP $CODE"
        # Delay between requests — single-core QEMU needs time to
        # complete TLS shutdown and free memory between connections
        sleep 1
    done
    if $GOT_429; then
        echo "  PASS [7] Rate limit enforced (got 429 after rapid requests)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL [7] Rate limit not triggered after 55 requests (last code: $LAST_CODE)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  SKIP [7] Rate limit (no token available)"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "--- Container logs (last 40 lines) ---"
    docker logs --tail 40 "$CONTAINER_NAME" 2>/dev/null || echo "(no logs)"
    exit 1
fi

echo ""
echo "All tests passed."
exit 0
