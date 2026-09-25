#!/bin/bash
#
# Regression test: a backup/restore format must not silently drop malformed
# records. importhybridkeys must fail explicitly when a non-comment line is
# not a valid hybrid key record:
#   - too few fields (the grammar is <secp_wif> <mldsa_priv_der_b64> <created>
#     [label=|change=1|reserve=1] ...),
#   - an unparseable timestamp (must NOT be silently treated as epoch time 0),
#   - a timestamp token carrying trailing garbage,
#   - a zero timestamp ("1970-01-01T00:00:00Z"): the wallet never persists a
#     hybrid key with nCreateTime <= 0 (ValidateHybridKey rejects it), so a
#     dump line claiming epoch time is corrupt and must fail explicitly.
#
# Every import case runs on its own fresh node/datadir/port so no case can be
# contaminated by residue from an earlier one.
#
# Usage: src/test/regression_hybridkeys_malformed.sh [path-to-phoenixcoind]

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
# Resolve to an absolute path: a bare name like "phoenixcoind" would otherwise
# be looked up in $PATH (not the current directory) and fail to execute.
case "$BIN" in
    */*) BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")" ;;
    *)   BIN="$(pwd)/$BIN" ;;
esac
DATADIR_A="$(mktemp -d "/tmp/hymalformed-A.XXXXXX")"
RES_DIR="$(mktemp -d "/tmp/hymalformed-res.XXXXXX")"
PORT_A=9685

# One clean node per import case.
B1="$(mktemp -d "/tmp/hymalformed-B1.XXXXXX")";  PORT_B1=9691
B2="$(mktemp -d "/tmp/hymalformed-B2.XXXXXX")";  PORT_B2=9692
B3="$(mktemp -d "/tmp/hymalformed-B3.XXXXXX")";  PORT_B3=9693
B4="$(mktemp -d "/tmp/hymalformed-B4.XXXXXX")";  PORT_B4=9694
B5="$(mktemp -d "/tmp/hymalformed-B5.XXXXXX")";  PORT_B5=9695

PASS=0
FAIL=0

cleanup() {
    "$BIN" -datadir="$DATADIR_A" stop >/dev/null 2>&1
    local dir
    for dir in "$B1" "$B2" "$B3" "$B4" "$B5"; do
        "$BIN" -datadir="$dir" stop >/dev/null 2>&1
    done
    wait_down "$DATADIR_A"
    local dir
    for dir in "$B1" "$B2" "$B3" "$B4" "$B5"; do
        wait_down "$dir"
    done
    rm -rf "$DATADIR_A" "$RES_DIR" "$B1" "$B2" "$B3" "$B4" "$B5"
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
    local dir="$1" port="$2" i out
    for i in $(seq 1 60); do
        out=$(rpc "$dir" "$port" getblockcount 2>&1)
        if [ $? -eq 0 ]; then
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: daemon on $dir port $port did not become ready"
    echo "  last rpc output: $out"
    echo "  debug.log tail:"; tail -8 "$dir/debug.log" 2>/dev/null || true
    return 1
}

wait_down() {
    local dir="$1" i
    for i in $(seq 1 60); do
        if ! pgrep -f "phoenixcoind -datadir=$dir " >/dev/null 2>&1; then
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

echo "== step 1: exporter A creates a valid backup =="
start_node "$DATADIR_A" "$PORT_A" || { cleanup; echo "FAILED setup A"; exit 1; }
rpc "$DATADIR_A" "$PORT_A" gethybridaddress "alice" >/dev/null
rpc "$DATADIR_A" "$PORT_A" gethybridaddress "alice2" >/dev/null
rpc "$DATADIR_A" "$PORT_A" dumphybridkeys dump_base.txt >/dev/null
check "A export succeeds and has data lines" \
    "$([ "$(grep -vc '^#' "$DATADIR_A/dump_base.txt")" -ge 20 ]; echo $?)"

# Variants derived from A's valid backup:
#  * bad_tokens: a trailing non-comment line with too few fields.
#  * bad_time:   first data line's timestamp replaced by a non-time string.
#  * trail_junk: first data line's timestamp token has trailing garbage.
#  * epoch_zero: first data line's timestamp set to the true epoch (invalid:
#                wallets reject nCreateTime <= 0).
awk '!/^#/ && NF && !done { $3 = "not-a-time"; done=1 } { print }' \
    "$DATADIR_A/dump_base.txt" > "$RES_DIR/bad_time.txt"
awk '!/^#/ && NF && !done { $3 = "2020-01-01T00:00:00Zjunk"; done=1 } { print }' \
    "$DATADIR_A/dump_base.txt" > "$RES_DIR/trail_junk.txt"
awk '!/^#/ && NF && !done { $3 = "1970-01-01T00:00:00Z"; done=1 } { print }' \
    "$DATADIR_A/dump_base.txt" > "$RES_DIR/epoch_zero.txt"
cat "$DATADIR_A/dump_base.txt" > "$RES_DIR/bad_tokens.txt"
echo "not-a-record" >> "$RES_DIR/bad_tokens.txt"

echo "== step 2: valid backup still imports cleanly (baseline) =="
start_node "$B1" "$PORT_B1" || { cleanup; echo "FAILED setup B1"; exit 1; }
out=$(rpc "$B1" "$PORT_B1" importhybridkeys "$DATADIR_A/dump_base.txt" 2>&1)
check "baseline import succeeds" "$([ $? -eq 0 ]; echo $?)"

echo "== step 3: too-few-fields line fails the import explicitly =="
start_node "$B2" "$PORT_B2" || { cleanup; echo "FAILED setup B2"; exit 1; }
out=$(rpc "$B2" "$PORT_B2" importhybridkeys "$RES_DIR/bad_tokens.txt" 2>&1)
rc=$?
check "import with a short line errors out" "$([ "$rc" -ne 0 ]; echo $?)"
check "short-line import reports partial failure" \
    "$(echo "$out" | grep -q "Some hybrid keys could not be imported"; echo $?)"
check "short-line import is flagged in the debug log" \
    "$(grep -q "Malformed hybrid key line" "$B2/debug.log"; echo $?)"

echo "== step 4: unparseable timestamp fails instead of becoming epoch 0 =="
start_node "$B3" "$PORT_B3" || { cleanup; echo "FAILED setup B3"; exit 1; }
out=$(rpc "$B3" "$PORT_B3" importhybridkeys "$RES_DIR/bad_time.txt" 2>&1)
check "import with an invalid timestamp errors out" "$([ $? -ne 0 ]; echo $?)"
check "invalid-timestamp import reports partial failure" \
    "$(echo "$out" | grep -q "Some hybrid keys could not be imported"; echo $?)"
check "invalid-timestamp import is flagged in the debug log" \
    "$(grep -q "invalid timestamp" "$B3/debug.log"; echo $?)"

echo "== step 5: timestamp with trailing garbage is rejected =="
start_node "$B4" "$PORT_B4" || { cleanup; echo "FAILED setup B4"; exit 1; }
out=$(rpc "$B4" "$PORT_B4" importhybridkeys "$RES_DIR/trail_junk.txt" 2>&1)
check "import with trailing garbage errors out" "$([ $? -ne 0 ]; echo $?)"
check "trailing-garbage import reports partial failure" \
    "$(echo "$out" | grep -q "Some hybrid keys could not be imported"; echo $?)"
check "trailing-garbage import is flagged in the debug log" \
    "$(grep -q "invalid timestamp" "$B4/debug.log"; echo $?)"

echo "== step 6: a zero (epoch) timestamp is rejected, not treated as valid =="
start_node "$B5" "$PORT_B5" || { cleanup; echo "FAILED setup B5"; exit 1; }
out=$(rpc "$B5" "$PORT_B5" importhybridkeys "$RES_DIR/epoch_zero.txt" 2>&1)
check "import with an epoch timestamp errors out" "$([ $? -ne 0 ]; echo $?)"
check "epoch-timestamp import reports partial failure" \
    "$(echo "$out" | grep -q "Some hybrid keys could not be imported"; echo $?)"
check "epoch-timestamp import is flagged in the debug log" \
    "$(grep -q "invalid timestamp" "$B5/debug.log"; echo $?)"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]