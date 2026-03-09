#!/bin/bash
#
# run-tests.sh — 7 integration tests for seL4 HTTP Gateway (bearer token + rate limit)
#
# Runs inside the Docker container. QEMU must already be running.
#
# Note: curl returns exit code 56 (TLS recv error) on every request because
# the seL4 gateway resets the connection after sending the response. This is
# expected behavior. We use "; true" inside $() to capture the HTTP status
# code regardless of curl's exit code.
#
set +e

PORT=8443
BOOT_TIMEOUT=60
PASS=0
FAIL=0
TOTAL=7

# Helper: run curl and capture HTTP status code (ignore curl exit code)
do_curl() {
    curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 15 --max-time 30 "$@" 2>/dev/null; true
}

# Helper: run curl and capture response body (ignore curl exit code)
do_curl_body() {
    curl -sk --connect-timeout 15 --max-time 30 "$@" 2>/dev/null; true
}

# --- Wait for QEMU to boot ---
echo "Waiting for QEMU boot (timeout: ${BOOT_TIMEOUT}s)..."
ELAPSED=0
READY=false

while [ $ELAPSED -lt $BOOT_TIMEOUT ]; do
    if grep -q "\[LwipProxy\] Ready:" /tmp/gateway.log 2>/dev/null; then
        READY=true
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

if ! $READY; then
    echo "FATAL: QEMU did not boot within ${BOOT_TIMEOUT}s"
    echo "--- Last 20 lines of log ---"
    tail -20 /tmp/gateway.log 2>/dev/null || echo "(no log)"
    exit 1
fi

echo "QEMU booted in ${ELAPSED}s"

# Wait for TLS port to accept connections
echo "Waiting for TLS port ${PORT} to accept connections..."
CONN_TIMEOUT=60
CONN_ELAPSED=0
while [ $CONN_ELAPSED -lt $CONN_TIMEOUT ]; do
    HTTP_CODE=$(do_curl "https://localhost:${PORT}/api/status")
    if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "200" ]; then
        echo "Port ready after ${CONN_ELAPSED}s (got HTTP $HTTP_CODE)"
        break
    fi
    sleep 2
    CONN_ELAPSED=$((CONN_ELAPSED + 2))
done
if [ $CONN_ELAPSED -ge $CONN_TIMEOUT ]; then
    echo "WARNING: Port not ready after ${CONN_TIMEOUT}s, proceeding anyway"
fi
echo ""

# --- Test helpers ---
run_test() {
    local test_num="$1"
    local description="$2"
    local expected_code="$3"
    shift 3

    local actual_code
    actual_code=$(do_curl "$@")
    [ -z "$actual_code" ] && actual_code="000"

    if [ "$actual_code" = "$expected_code" ]; then
        echo "  PASS [$test_num] $description (HTTP $actual_code)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL [$test_num] $description (expected $expected_code, got $actual_code)"
        FAIL=$((FAIL + 1))
    fi
}

extract_token() {
    local response="$1"
    if command -v jq >/dev/null 2>&1; then
        echo "$response" | jq -r '.token // empty' 2>/dev/null
    else
        echo "$response" | grep -o '"token":"[^"]*"' | sed 's/"token":"//;s/"//'
    fi
}

echo "=== Running Integration Tests (7 tests) ==="

# Test 1: GET /api/status without token -> 401
run_test 1 "GET /api/status (no token)" "401" \
    "https://localhost:${PORT}/api/status"

# Test 2: POST /api/login (admin) -> 200 + token
LOGIN_RESPONSE=$(do_curl_body \
    -X POST -d '{"username":"admin","password":"admin456"}' \
    "https://localhost:${PORT}/api/login")
LOGIN_CODE=$(do_curl \
    -X POST -d '{"username":"admin","password":"admin456"}' \
    "https://localhost:${PORT}/api/login")

if [ "$LOGIN_CODE" = "200" ]; then
    echo "  PASS [2] POST /api/login (admin) (HTTP $LOGIN_CODE)"
    PASS=$((PASS + 1))
else
    echo "  FAIL [2] POST /api/login (admin) (expected 200, got $LOGIN_CODE)"
    FAIL=$((FAIL + 1))
fi

TOKEN=$(extract_token "$LOGIN_RESPONSE")
if [ -n "$TOKEN" ]; then
    echo "       Token obtained: ${TOKEN:0:20}..."
else
    echo "       WARNING: Could not extract token from response"
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
sleep 2
run_test 5 "POST /api/login (operator)" "200" \
    -X POST -d '{"username":"operator","password":"oper789"}' \
    "https://localhost:${PORT}/api/login"

# Test 6: Policy upload (admin login -> PUT /api/policy)
sleep 1
echo ""
echo "--- Test 6: Policy upload ---"
ADMIN_LOGIN=$(do_curl_body \
    -X POST -d '{"username":"admin","password":"admin456"}' \
    "https://localhost:${PORT}/api/login")
ADMIN_TOKEN=$(extract_token "$ADMIN_LOGIN")

if [ -n "$ADMIN_TOKEN" ]; then
    POLICY_FILE=$(mktemp)
    python3 -c "
import struct, sys
rules = [
    (0x33333333, 1, 2, 0x0001),
    (0x22222222, 2, 1, 0x0000),
    (0x44444444, 1, 2, 0x0004),
] + [(0xDEADDEAD, 0, 0, 0)] * 5
data = bytes([3])
for ph, m, r, s in rules:
    data += struct.pack('<I', ph) + bytes([m, r]) + struct.pack('<H', s)
assert len(data) == 65, f'Expected 65 bytes, got {len(data)}'
with open('$POLICY_FILE', 'wb') as f:
    f.write(data)
" 2>/dev/null
    echo "       Policy file: $(wc -c < "$POLICY_FILE") bytes"

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
sleep 1
echo ""
echo "--- Test 7: Rate limit ---"
RATE_LOGIN=$(do_curl_body \
    -X POST -d '{"username":"admin","password":"admin456"}' \
    "https://localhost:${PORT}/api/login")
RATE_TOKEN=$(extract_token "$RATE_LOGIN")

if [ -n "$RATE_TOKEN" ]; then
    GOT_429=false
    LAST_CODE=""
    for i in $(seq 1 55); do
        CODE=$(do_curl \
            -H "Authorization: Bearer $RATE_TOKEN" \
            "https://localhost:${PORT}/api/status")
        LAST_CODE="$CODE"
        if [ "$CODE" = "429" ]; then
            GOT_429=true
            echo "       Got 429 on request #$i"
            break
        fi
        if [ "$CODE" = "000" ] || [ -z "$CODE" ]; then
            echo "       Request #$i: connection failed, waiting 3s..."
            sleep 3
            continue
        fi
        [ $((i % 10)) -eq 0 ] && echo "       Request #$i: HTTP $CODE"
        sleep 1
    done
    if $GOT_429; then
        echo "  PASS [7] Rate limit enforced (got 429)"
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
    exit 1
fi

echo ""
echo "All tests passed."
exit 0
