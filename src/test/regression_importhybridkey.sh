#!/bin/bash
#
# Regression test: importhybridkey persistence / dumphybridkey round trip.
#
# Verifies that a hybrid private key exported from one wallet can be imported
# into a fresh wallet and then re-exported identically, both immediately and
# after a full daemon restart (the latter proves the ECDSA half survives as a
# real wallet "key" record rather than only living in memory).
#
# Checks:
#   1. importhybridkey returns the same hybrid address on the importer.
#   2. dumphybridkey on the importer matches the exporter exactly (WIF + DER).
#   3. The re-exported WIF is the one that was imported.
#   4. Hybrid signing still works after import.
#   5. After restarting the importer, (2)-(4) still hold.
#
# Usage: src/test/regression_importhybridkey.sh [path-to-phoenixcoind]

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
DATADIR_A="$(mktemp -d "/tmp/importhybridkey-A.XXXXXX")"
DATADIR_B="$(mktemp -d "/tmp/importhybridkey-B.XXXXXX")"
PORT_A=9661
PORT_B=9662
MSG="importhybridkey regression message"

PASS=0
FAIL=0

cleanup() {
    "$BIN" -datadir="$DATADIR_A" stop >/dev/null 2>&1
    "$BIN" -datadir="$DATADIR_B" stop >/dev/null 2>&1
    wait_down "$DATADIR_A"
    wait_down "$DATADIR_B"
    rm -rf "$DATADIR_A" "$DATADIR_B"
}
trap cleanup EXIT

check() {
    local name="$1" cond="$2"
    if [ "$cond" = "0" ]; then
        PASS=$((PASS+1)); echo "  PASS: $name"
    else
        FAIL=$((FAIL+1)); echo "  FAIL: $name"
    fi
}

rpc() {
    local dir="$1" port="$2" method="$3"; shift 3
    "$BIN" -datadir="$dir" -rpcuser=reguser -rpcpassword=regpass \
           -rpcport="$port" "$method" "$@"
}

wait_ready() {
    local dir="$1" port="$2" i
    for i in $(seq 1 60); do
        if rpc "$dir" "$port" getblockcount >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: daemon on $dir port $port did not become ready"
    return 1
}

wait_down() {
    local dir="$1" i
    for i in $(seq 1 60); do
        if ! pgrep -f "phoenixcoind -datadir=$dir" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: daemon on $dir did not shut down"
    return 1
}

start_node() {
    local dir="$1" port="$2"
    cat > "$dir/phoenixcoin.conf" <<EOF2
server=1
listen=0
maxconnections=0
rpcport=$port
rpcuser=reguser
rpcpassword=regpass
EOF2
    "$BIN" -datadir="$dir" -daemon >/dev/null 2>&1
    wait_ready "$dir" "$port"
}

echo "== step 1: start exporter A (fresh wallet) =="
start_node "$DATADIR_A" "$PORT_A" || { cleanup; echo "FAILED setup A"; exit 1; }
H=$(rpc "$DATADIR_A" "$PORT_A" gethybridaddress "regkey")
echo "   hybrid address: $H"
D_A=$(rpc "$DATADIR_A" "$PORT_A" dumphybridkey "$H")
WIF_A=$(echo "$D_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['secp_wif'])")
echo "   exporter WIF:   ${WIF_A:0:8}... (len ${#WIF_A})"

echo "== step 2: start importer B (fresh wallet) and import =="
start_node "$DATADIR_B" "$PORT_B" || { cleanup; echo "FAILED setup B"; exit 1; }
WIF=$(echo "$D_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['secp_wif'])")
DER=$(echo "$D_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['mldsa_priv_der_b64'])")
H_IMPORTED=$(rpc "$DATADIR_B" "$PORT_B" importhybridkey "$WIF" "$DER" "regkey")
check "importhybridkey returns the same address" "$([ "$H_IMPORTED" = "$H" ]; echo $?)"

echo "== step 3: immediate re-export on the importer =="
D_B=$(rpc "$DATADIR_B" "$PORT_B" dumphybridkey "$H")
check "dumphybridkey works immediately after import" "$([ -n "$D_B" ]; echo $?)"
check "immediate dump matches exporter (WIF + DER)" "$([ "$D_B" = "$D_A" ]; echo $?)"
WIF_B=$(echo "$D_B" | python3 -c "import sys,json;print(json.load(sys.stdin)['secp_wif'])")
check "re-exported WIF is the imported WIF" "$([ "$WIF_B" = "$WIF_A" ]; echo $?)"

echo "== step 4: hybrid signing still works on importer =="
SIG=$(rpc "$DATADIR_B" "$PORT_B" signmessage "$H" "$MSG")
check "signmessage on importer" "$([ -n "$SIG" ]; echo $?)"
check "verifymessage on importer" "$([ "$(rpc "$DATADIR_B" "$PORT_B" verifymessage "$H" "$SIG" "$MSG")" = "true" ]; echo $?)"
check "verifymessage on exporter (cross-node)" "$([ "$(rpc "$DATADIR_A" "$PORT_A" verifymessage "$H" "$SIG" "$MSG")" = "true" ]; echo $?)"

echo "== step 5: restart importer, re-export again =="
"$BIN" -datadir="$DATADIR_B" stop >/dev/null 2>&1
wait_down "$DATADIR_B" || { cleanup; echo "FAILED shutdown B"; exit 1; }
start_node "$DATADIR_B" "$PORT_B" || { cleanup; echo "FAILED restart B"; exit 1; }
D_B2=$(rpc "$DATADIR_B" "$PORT_B" dumphybridkey "$H")
check "dumphybridkey works after restart" "$([ -n "$D_B2" ]; echo $?)"
check "post-restart dump matches exporter (persistence)" "$([ "$D_B2" = "$D_A" ]; echo $?)"
WIF_B2=$(echo "$D_B2" | python3 -c "import sys,json;print(json.load(sys.stdin)['secp_wif'])")
check "post-restart WIF is the imported WIF" "$([ "$WIF_B2" = "$WIF_A" ]; echo $?)"

echo "== step 6: hybrid signing after restart =="
SIG2=$(rpc "$DATADIR_B" "$PORT_B" signmessage "$H" "$MSG")
check "signmessage after restart" "$([ -n "$SIG2" ]; echo $?)"
check "verifymessage after restart" "$([ "$(rpc "$DATADIR_B" "$PORT_B" verifymessage "$H" "$SIG2" "$MSG")" = "true" ]; echo $?)"
check "verifymessage after restart (exporter)" "$([ "$(rpc "$DATADIR_A" "$PORT_A" verifymessage "$H" "$SIG2" "$MSG")" = "true" ]; echo $?)"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]