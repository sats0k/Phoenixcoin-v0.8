#!/bin/bash
#
# Regression test: the LMDB wallet survives SIGKILL at every durable boundary.
#
# Kill during normal wallet operation: send, receive, label, keypool refill,
# hybrid import and encrypt must leave the wallet either exactly as it was
# before the operation or in the fully committed state after it, never in
# between.  The interrupted OP_CAST (wallet.rewrite) is also covered.
#
# The heavy lifting is done by a test-only crash hook (db.cpp:
# TestWalletCrashPoint).  PHOENIX_TEST_CRASH_FILE names a control file whose
# content is "<point> <skip>".  Each matching call decrements skip; the call
# that finds skip == 0 raises SIGKILL.  The file is absent during normal
# operation, so the hook is inert.  Crash points for standalone wallet writes
# include the record type ("wallet-write-after-commit:tx") so a case can pick
# the exact record class without counting unrelated writes.
#
# The script builds one LMDB wallet on a real mainnet chain fragment
# (blocks 1-6, as in regression_lmdb_wallet_e2e.sh), then gives every case its
# own copy of the reference datadir.  No case touches the user's real datadir.
#
# Usage: src/test/regression_lmdb_wallet_crash.sh [path-to-phoenixcoind]
#
# The RPC port is chosen from the ephemeral range and can be pinned with
# PXC_REGTEST_PORT for debugging or constrained environments.

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
WORK="$(mktemp -d "/tmp/lmdb-wallet-crash.XXXXXX")"
BASE_WALLET="$WORK/base-wallet"
REF_LMDB="$WORK/lmdb-reference"
CRASH_FILE="$WORK/crash.control"
NODE_PID=""
PASS=0
FAIL=0

find_free_port() {
    local i port
    for i in $(seq 1 50); do
        port=$(( RANDOM % 16384 + 49152 ))
        if ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            echo "$port"
            return 0
        fi
    done
    return 1
}

PORT="${PXC_REGTEST_PORT:-$(find_free_port)}"
case "$PORT" in
    ''|*[!0-9]*)
        echo "ERROR: could not allocate an RPC port (set PXC_REGTEST_PORT)" >&2
        exit 1
        ;;
esac

pass() { PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

check() {
    local name="$1" cond="$2"
    if [ "$cond" = "0" ]; then pass "$name"; else fail "$name"; fi
}

check_eq() {
    local name="$1" want="$2" got="$3"
    check "$name" "$([ "$want" = "$got" ]; echo $?)"
    if [ "$want" != "$got" ]; then
        echo "        want: $want"
        echo "        got:  $got"
    fi
}

check_contains() {
    local name="$1" needle="$2" haystack="$3"
    check "$name" "$(printf '%s\n' "$haystack" | grep -qF -- "$needle"; echo $?)"
}

check_not_contains() {
    local name="$1" needle="$2" haystack="$3"
    check "$name" "$(! printf '%s\n' "$haystack" | grep -qF -- "$needle"; echo $?)"
}

rpc_expect_fail() {
    local name="$1" dir="$2"; shift 2
    if rpc_dir "$dir" "$@" >/dev/null 2>&1; then
        fail "$name (unexpected success)"
    else
        pass "$name"
    fi
}

write_config() {
    local dir="$1"
    cat > "$dir/phoenixcoin.conf" <<EOF
server=1
listen=0
connect=0
maxconnections=0
dnsseed=0
rpcport=$PORT
rpcuser=reguser
rpcpassword=regpass
debug=1
EOF
}

rpc_dir() {
    local dir="$1" method="$2"; shift 2
    timeout 30 "$BIN" -datadir="$dir" -rpcuser=reguser -rpcpassword=regpass \
        -rpcport="$PORT" "$method" "$@"
}

rpc() { rpc_dir "$1" "$@"; }

# A background child that exits stays a zombie until wait() reaps it, which
# makes kill -0 useless as an exit test.  Look at the process state instead.
process_alive() {
    local stat
    stat="$(ps -o stat= -p "$1" 2>/dev/null)"
    [ -n "$stat" ] && [ "${stat#Z}" = "$stat" ]
}

wait_exit() {
    local pid="$1" i
    for i in $(seq 1 240); do
        if ! process_alive "$pid"; then
            wait "$pid"
            return $?
        fi
        sleep 0.25
    done
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    return 99
}

wait_ready_at() {
    local dir="$1" i
    for i in $(seq 1 90); do
        if timeout 5 "$BIN" -datadir="$dir" -rpcuser=reguser \
                -rpcpassword=regpass -rpcport="$PORT" getblockcount \
                >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: daemon in $dir did not become ready"
    return 1
}

arm() {
    local point="$1" skip="${2:-0}"
    printf '%s %s\n' "$point" "$skip" > "$CRASH_FILE"
}

disarm() {
    rm -f "$CRASH_FILE"
}

# Start the daemon in the foreground in the background, so its real exit
# status (137 for SIGKILL) is observable.  -daemon would fork and hide it.
start_bg() {
    local dir="$1"; shift
    write_config "$dir"
    PHOENIX_TEST_COINBASE_MATURITY=0 PHOENIX_TEST_CRASH_FILE="$CRASH_FILE" \
        "$BIN" -datadir="$dir" "$@" > "$dir/foreground.log" 2>&1 &
    NODE_PID=$!
}

start_ready() {
    local dir="$1"; shift
    start_bg "$dir" "$@"
    if wait_ready_at "$dir"; then
        return 0
    fi
    kill -9 "$NODE_PID" 2>/dev/null
    wait "$NODE_PID" 2>/dev/null
    NODE_PID=""
    return 1
}

stop_node() {
    local dir="$1"
    [ -n "${NODE_PID:-}" ] || return 0
    rpc_dir "$dir" stop >/dev/null 2>&1
    wait_exit "$NODE_PID" >/dev/null 2>&1
    NODE_PID=""
}

cleanup() {
    disarm
    if [ -n "${NODE_PID:-}" ] && process_alive "$NODE_PID"; then
        kill -9 "$NODE_PID" 2>/dev/null
        wait "$NODE_PID" 2>/dev/null
    fi
    if [ "${PXC_KEEP_WORK:-0}" = "1" ]; then
        echo "kept work directory: $WORK"
    else
        rm -rf "$WORK"
    fi
}

# PXC_ONLY filters cases by name while debugging; the setup still runs.
case_selected() {
    [ -z "${PXC_ONLY:-}" ] || [[ "$1" =~ $PXC_ONLY ]]
}
trap cleanup EXIT

# Copy a stopped datadir.  Logs, pid files and stale LMDB lock state belong to
# the source process, not to the case.
copy_dir() {
    local src="$1" dest="$2"
    rm -rf "$dest"
    mkdir -p "$dest"
    cp -a "$src/." "$dest/"
    rm -f "$dest/debug.log" "$dest/foreground.log" "$dest/phoenixcoind.pid" \
          "$dest/wallet.backend.tmp" "$dest/wallet/lock.mdb"
}

json_field() {
    python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1],""))' "$1"
}

txid_for_comment() {
    printf '%s' "$1" | python3 -c \
        'import json,sys
c = sys.argv[1]
print(next((t.get("txid", "") for t in json.load(sys.stdin)
            if t.get("comment") == c), ""))' "$2"
}

key_roundtrip() {
    local dir="$1" addr="$2" want_wif="$3" label="$4"
    check "$label: address is owned" \
        "$(rpc_dir "$dir" validateaddress "$addr" 2>/dev/null |
           grep -q '"ismine" : true'; echo $?)"
    check_eq "$label: private key unchanged" "$want_wif" \
        "$(rpc_dir "$dir" dumpprivkey "$addr" 2>/dev/null)"
}

unlock() {
    rpc_dir "$1" walletpassphrase "$WALLET_PASSPHRASE" 600 >/dev/null 2>&1
}

# The fixed mainnet blocks 1-4 come from the shared fragment; blocks 5 and 6
# were mined once with the same consensus rules and pay the WIFs below.
FRAGMENT="$(cd "$(dirname "$0")" && pwd)/regression_mainnet_fragment.sh"
if [ ! -f "$FRAGMENT" ]; then
    echo "ERROR: cannot find the mainnet fragment at $FRAGMENT" >&2
    exit 1
fi
. "$FRAGMENT"

BLOCK_HEX[5]="0200000091277ad30271f59836916dcc3edefcc59f9c30aacfeec3acdd6310b1a566072850cb9d591fbc58a76ab1c25d2fefaf3984da56f37302c554a31e0cf9848f86338af0e66af0ff0f1e3a0000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0b5502d804062f503253482fffffffff0100f2052a01000000232103bebdbbeeb9c1220d29d8bddc765c9935dd9b764cac9d83d64435a9a4074002c2ac00000000"
BLOCK_HEX[6]="0200000086d11e9d9484c72b534f27ba04fd1f6a6ed9f39f6d13869698df51dc80599aa710ee449d4c94aee22fea887407ac1c69862c52612199f4a3355c667cc2fc678df7f1e66af0ff0f1e540000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0b5602730c062f503253482fffffffff0100f2052a01000000232102d9833e4c4dec81e502308d05938d1d821a627983660f5b20d976b04562a8b780ac00000000"

EXTERNAL_ADDR="Puicad2AcZRj9DgF8WJtywBU7AbMxxLGAS"
COINBASE5_WIF="UEXuWq8hwusSVrhFtPowPv5H8xfvUT5vDx1y1CfNNj8vpBwjVYwR"
COINBASE6_WIF="UFEFb173uqVWSBeFnB6gstGyuvREZLMLNUXeMka4ETEAAvYouXBo"
COINBASE5_ADDR="PfzGAi9DoiSkPYSjDAEFLTiggCv6LKSFmf"
COINBASE6_ADDR="PeyhySKGqLTKn4mh91L8ePtQPEUsdXL9Yn"
WALLET_PASSPHRASE="crash test passphrase"

BASE_BALANCE="89.99000000"
SEND_BALANCE="88.98000000"

echo "== setup: build the reference LMDB wallet =="
mkdir -p "$BASE_WALLET"
if ! start_ready "$BASE_WALLET"; then
    echo "FAILED: could not start the daemon"
    exit 1
fi

for h in 1 2 3 4 5 6; do
    rpc_dir "$BASE_WALLET" submitblock "${BLOCK_HEX[$h]}" >/dev/null 2>&1
done
check_eq "chain fragment connected to height 6" "6" \
    "$(rpc_dir "$BASE_WALLET" getblockcount 2>/dev/null)"

rpc_dir "$BASE_WALLET" importprivkey "$COINBASE5_WIF" "coinbase-5" true \
    >/dev/null 2>&1
rpc_dir "$BASE_WALLET" importprivkey "$COINBASE6_WIF" "coinbase-6" true \
    >/dev/null 2>&1
check_eq "coinbase balance is 100 PXC" "100.00000000" \
    "$(rpc_dir "$BASE_WALLET" getbalance 2>/dev/null)"

TX_PRE=$(rpc_dir "$BASE_WALLET" sendtoaddress "$EXTERNAL_ADDR" 10 \
    "crash test seed send" "crash" 2>/dev/null)
check "created the seed send" "$([ -n "$TX_PRE" ]; echo $?)"

ALICE_ADDR=$(rpc_dir "$BASE_WALLET" getnewaddress alice 2>/dev/null)
ALICE_WIF=$(rpc_dir "$BASE_WALLET" dumpprivkey "$ALICE_ADDR" 2>/dev/null)
BOB_ADDR=$(rpc_dir "$BASE_WALLET" getnewaddress bob 2>/dev/null)
# Two addresses in "orig": the first is not the account's current key, so
# setaccount on it cannot trigger an unrelated key generation.
TARGET_ADDR=$(rpc_dir "$BASE_WALLET" getnewaddress orig 2>/dev/null)
rpc_dir "$BASE_WALLET" getnewaddress orig >/dev/null 2>&1
# Record the account's current key so setaccount on TARGET_ADDR (which is not
# that key) cannot generate an unrelated key and name record first.
rpc_dir "$BASE_WALLET" getaccountaddress orig >/dev/null 2>&1
TARGET_WIF=$(rpc_dir "$BASE_WALLET" dumpprivkey "$TARGET_ADDR" 2>/dev/null)
check_eq "the label target starts in account orig" "orig" \
    "$(rpc_dir "$BASE_WALLET" getaccount "$TARGET_ADDR" 2>/dev/null)"

rpc_dir "$BASE_WALLET" keypoolrefill 50 >/dev/null 2>&1

HYB_BASE_ADDR=$(rpc_dir "$BASE_WALLET" gethybridaddress "hybrid-base" 2>/dev/null)
HYB_BASE_JSON=$(rpc_dir "$BASE_WALLET" dumphybridkey "$HYB_BASE_ADDR" 2>/dev/null)
HYB_BASE_WIF=$(printf '%s' "$HYB_BASE_JSON" | json_field secp_wif)
HYB_BASE_DER=$(printf '%s' "$HYB_BASE_JSON" | json_field mldsa_priv_der_b64)
check "created the base hybrid key" \
    "$([ -n "$HYB_BASE_ADDR" ] && [ -n "$HYB_BASE_WIF" ] && [ -n "$HYB_BASE_DER" ]; echo $?)"
check_eq "base balance after the seed send" "$BASE_BALANCE" \
    "$(rpc_dir "$BASE_WALLET" getbalance 2>/dev/null)"

stop_node "$BASE_WALLET"

# Generate hybrid material and an independent private key in a brand new
# wallet, so the reference wallet does not already contain what the import
# cases add.  Copying the base datadir would reuse its keypool keys.
MATERIAL_SRC="$WORK/material-src"
mkdir -p "$MATERIAL_SRC"
if ! start_ready "$MATERIAL_SRC"; then
    echo "FAILED: could not start the material daemon"
    exit 1
fi
HYB_IMPORT_ADDR=$(rpc_dir "$MATERIAL_SRC" gethybridaddress "hybrid-import" 2>/dev/null)
HYB_IMPORT_JSON=$(rpc_dir "$MATERIAL_SRC" dumphybridkey "$HYB_IMPORT_ADDR" 2>/dev/null)
HYB_IMPORT_WIF=$(printf '%s' "$HYB_IMPORT_JSON" | json_field secp_wif)
HYB_IMPORT_DER=$(printf '%s' "$HYB_IMPORT_JSON" | json_field mldsa_priv_der_b64)
NEW_ADDR=$(rpc_dir "$MATERIAL_SRC" getnewaddress "receive-crash" 2>/dev/null)
NEW_WIF=$(rpc_dir "$MATERIAL_SRC" dumpprivkey "$NEW_ADDR" 2>/dev/null)
check "generated independent import material" \
    "$([ -n "$HYB_IMPORT_ADDR" ] && [ -n "$HYB_IMPORT_WIF" ] &&
       [ -n "$HYB_IMPORT_DER" ] && [ -n "$NEW_ADDR" ] && [ -n "$NEW_WIF" ]; echo $?)"
check "the material is not already in the reference wallet" \
    "$([ "$HYB_IMPORT_ADDR" != "$HYB_BASE_ADDR" ] && [ "$NEW_ADDR" != "$ALICE_ADDR" ]; echo $?)"
stop_node "$MATERIAL_SRC"
rm -rf "$MATERIAL_SRC"

echo "== setup: snapshot the reference LMDB wallet =="
copy_dir "$BASE_WALLET" "$REF_LMDB"
check "reference wallet has LMDB data and the lmdb marker" \
    "$([ -s "$REF_LMDB/wallet/data.mdb" ] && [ "$(cat "$REF_LMDB/wallet.backend" 2>/dev/null)" = lmdb ]; echo $?)"

# ---------------------------------------------------------------------------
# Shared verification.  Every recovered wallet must expose the same state the
# reference wallet does; a crash may only choose between "before" and "after".
# ---------------------------------------------------------------------------
verify_common() {
    local dir="$1" label="$2" balance="$3"
    check "$label: LMDB wallet has data and the lmdb marker" \
        "$([ -s "$dir/wallet/data.mdb" ] && [ "$(cat "$dir/wallet.backend" 2>/dev/null)" = lmdb ]; echo $?)"
    check_eq "$label: chain still at height 6" "6" \
        "$(rpc_dir "$dir" getblockcount 2>/dev/null)"
    check_eq "$label: balance" "$balance" \
        "$(rpc_dir "$dir" getbalance 2>/dev/null)"
    key_roundtrip "$dir" "$COINBASE5_ADDR" "$COINBASE5_WIF" "$label block 5 key"
    key_roundtrip "$dir" "$COINBASE6_ADDR" "$COINBASE6_WIF" "$label block 6 key"
    key_roundtrip "$dir" "$ALICE_ADDR" "$ALICE_WIF" "$label alice key"
    check_contains "$label: alice label survived" "$ALICE_ADDR" \
        "$(rpc_dir "$dir" getaddressesbyaccount alice 2>/dev/null)"
    check_contains "$label: bob label survived" "$BOB_ADDR" \
        "$(rpc_dir "$dir" getaddressesbyaccount bob 2>/dev/null)"
    check_contains "$label: seed send survived" "$TX_PRE" \
        "$(rpc_dir "$dir" listtransactions '*' 50 2>/dev/null)"
    check_contains "$label: seed amount survived" \
        '"amount" : -10.00000000' \
        "$(rpc_dir "$dir" gettransaction "$TX_PRE" 2>/dev/null)"
    check_eq "$label: hybrid key unchanged" "$HYB_BASE_WIF" \
        "$(rpc_dir "$dir" dumphybridkey "$HYB_BASE_ADDR" 2>/dev/null |
           json_field secp_wif)"
    check_eq "$label: hybrid ML-DSA key unchanged" "$HYB_BASE_DER" \
        "$(rpc_dir "$dir" dumphybridkey "$HYB_BASE_ADDR" 2>/dev/null |
           json_field mldsa_priv_der_b64)"
}

# ---------------------------------------------------------------------------
# Normal wallet operation.
# ---------------------------------------------------------------------------
prepare_lmdb_case() {
    local dir="$1"
    copy_dir "$REF_LMDB" "$dir"
}

# Crash a named point while running one RPC, then confirm SIGKILL.
crash_during_rpc() {
    local label="$1" dir="$2" point="$3" skip="$4"; shift 4
    local out rpc_rc
    arm "$point" "$skip"
    out="$(rpc_dir "$dir" "$@" 2>&1)"
    rpc_rc=$?
    wait_exit "$NODE_PID"
    local rc=$?
    NODE_PID=""
    disarm
    check_eq "$label: process was SIGKILLed at $point" "137" "$rc"
    if [ "$rc" != "137" ]; then
        echo "        rpc rc: $rpc_rc"
        echo "        rpc output: $out"
    fi
}

label_case() {
    local when="$1" point expected
    if [ "$when" = "before" ]; then
        point="wallet-write-before-commit:name"
        expected="orig"
    else
        point="wallet-write-after-commit:name"
        expected="crash-label"
    fi
    local dir="$WORK/case-label-$when"
    case_selected "label-$when" || return 0

    echo "== case label-$when: kill at $point =="
    prepare_lmdb_case "$dir"
    if ! start_ready "$dir"; then
        check "label-$when: daemon start" "1"; return
    fi
    crash_during_rpc "label-$when" "$dir" "$point" 0 \
        setaccount "$TARGET_ADDR" "crash-label"
    if ! start_ready "$dir"; then
        check "label-$when: restart after the crash" "1"; return
    fi
    check_eq "label-$when: account is $expected" "$expected" \
        "$(rpc_dir "$dir" getaccount "$TARGET_ADDR" 2>/dev/null)"
    verify_common "$dir" "label-$when" "$BASE_BALANCE"
    stop_node "$dir"
}

label_case before
label_case after

send_case() {
    local when="$1" point balance
    if [ "$when" = "before" ]; then
        point="wallet-write-before-commit:tx"
        balance="$BASE_BALANCE"
    else
        point="wallet-write-after-commit:tx"
        balance="$SEND_BALANCE"
    fi
    local dir="$WORK/case-send-$when"
    case_selected "send-$when" || return 0

    echo "== case send-$when: kill at $point =="
    prepare_lmdb_case "$dir"
    if ! start_ready "$dir"; then
        check "send-$when: daemon start" "1"; return
    fi
    crash_during_rpc "send-$when" "$dir" "$point" 0 \
        sendtoaddress "$EXTERNAL_ADDR" 1 "crash send $when" "crash"
    if ! start_ready "$dir"; then
        check "send-$when: restart after the crash" "1"; return
    fi

    local history tx_new detail
    history="$(rpc_dir "$dir" listtransactions '*' 50 2>/dev/null)"
    tx_new="$(txid_for_comment "$history" "crash send $when")"
    if [ "$when" = "before" ]; then
        check "send-before: the interrupted send is not in the wallet" \
            "$([ -z "$tx_new" ]; echo $?)"
    else
        check "send-after: the committed send is in the wallet" \
            "$([ -n "$tx_new" ]; echo $?)"
        detail="$(rpc_dir "$dir" gettransaction "$tx_new" 2>/dev/null)"
        check_contains "send-after: the committed send is recorded as a send" \
            '"category" : "send"' "$detail"
        check_contains "send-after: the committed send has its amount" \
            '"amount" : -1.00000000' "$detail"
    fi
    # For send-after the spent flags were written by no one: the repair in
    # ReacceptWalletTransactions must rebuild them or the balance stays high.
    check_eq "send-$when: balance reflects $([ "$when" = before ] && echo 'the pre-send' || echo 'the committed send') state" \
        "$balance" "$(rpc_dir "$dir" getbalance 2>/dev/null)"
    verify_common "$dir" "send-$when" "$balance"
    stop_node "$dir"
}

send_case before
send_case after

receive_case() {
    local when="$1" point
    if [ "$when" = "before" ]; then
        point="wallet-write-before-commit:key"
    else
        point="wallet-write-after-commit:key"
    fi
    local dir="$WORK/case-receive-$when"
    case_selected "receive-$when" || return 0

    echo "== case receive-$when: kill at $point =="
    prepare_lmdb_case "$dir"
    if ! start_ready "$dir"; then
        check "receive-$when: daemon start" "1"; return
    fi
    crash_during_rpc "receive-$when" "$dir" "$point" 0 \
        importprivkey "$NEW_WIF" "" false
    if ! start_ready "$dir"; then
        check "receive-$when: restart after the crash" "1"; return
    fi

    if [ "$when" = "before" ]; then
        check_contains "receive-before: the key was not imported" \
            '"ismine" : false' \
            "$(rpc_dir "$dir" validateaddress "$NEW_ADDR" 2>/dev/null)"
    else
        check_contains "receive-after: the key was imported" '"ismine" : true' \
            "$(rpc_dir "$dir" validateaddress "$NEW_ADDR" 2>/dev/null)"
        check_eq "receive-after: the imported key is intact" "$NEW_WIF" \
            "$(rpc_dir "$dir" dumpprivkey "$NEW_ADDR" 2>/dev/null)"
    fi
    verify_common "$dir" "receive-$when" "$BASE_BALANCE"
    stop_node "$dir"
}

receive_case before
receive_case after

keypool_case() {
    local when="$1" point
    if [ "$when" = "before" ]; then
        point="wallet-write-before-commit:pool"
    else
        point="wallet-write-after-commit:pool"
    fi
    local dir="$WORK/case-keypool-$when"
    case_selected "keypool-$when" || return 0

    echo "== case keypool-$when: kill at $point =="
    prepare_lmdb_case "$dir"
    if ! start_ready "$dir" -keypool=200; then
        check "keypool-$when: daemon start" "1"; return
    fi
    # No argument: TopUpKeyPool only appends, so every pool record it writes
    # has already had its key committed.  NewKeyPool would erase first.
    crash_during_rpc "keypool-$when" "$dir" "$point" 5 keypoolrefill
    if ! start_ready "$dir"; then
        check "keypool-$when: restart after the crash" "1"; return
    fi

    local addr wif
    addr="$(rpc_dir "$dir" getnewaddress keypool-crash 2>/dev/null)"
    wif="$(rpc_dir "$dir" dumpprivkey "$addr" 2>/dev/null)"
    check "keypool-$when: the recovered pool still yields a spendable key" \
        "$([ -n "$addr" ] && [ -n "$wif" ]; echo $?)"
    check "keypool-$when: the refill can be repeated" \
        "$(rpc_dir "$dir" keypoolrefill >/dev/null 2>&1; echo $?)"
    verify_common "$dir" "keypool-$when" "$BASE_BALANCE"
    stop_node "$dir"
}

keypool_case before
keypool_case after

hybrid_case() {
    local when="$1" point
    if [ "$when" = "before" ]; then
        point="wallet-txn-before-commit"
    else
        point="wallet-txn-after-commit"
    fi
    local dir="$WORK/case-hybrid-$when"
    case_selected "hybrid-$when" || return 0

    echo "== case hybrid-import-$when: kill at $point =="
    prepare_lmdb_case "$dir"
    if ! start_ready "$dir"; then
        check "hybrid-$when: daemon start" "1"; return
    fi
    # The optional rescan argument is a real bool, but this RPC does not
    # convert string parameters; leave it out and accept the default rescan.
    crash_during_rpc "hybrid-$when" "$dir" "$point" 0 \
        importhybridkey "$HYB_IMPORT_WIF" "$HYB_IMPORT_DER" "crash-hybrid"
    if ! start_ready "$dir"; then
        check "hybrid-$when: restart after the crash" "1"; return
    fi

    if [ "$when" = "before" ]; then
        check_contains "hybrid-before: no hybrid key was committed" \
            '"ismine" : false' \
            "$(rpc_dir "$dir" validateaddress "$HYB_IMPORT_ADDR" 2>/dev/null)"
        check_not_contains "hybrid-before: no hybrid label was committed" \
            '"crash-hybrid"' \
            "$(rpc_dir "$dir" listhybridaddresses 2>/dev/null)"
        local retry
        retry="$(rpc_dir "$dir" importhybridkey "$HYB_IMPORT_WIF" \
            "$HYB_IMPORT_DER" "crash-hybrid" 2>/dev/null)"
        check_eq "hybrid-before: retrying the import succeeds" "$HYB_IMPORT_ADDR" \
            "$retry"
    else
        check_contains "hybrid-after: the committed key is present" \
            '"ismine" : true' \
            "$(rpc_dir "$dir" validateaddress "$HYB_IMPORT_ADDR" 2>/dev/null)"
        check_contains "hybrid-after: the committed label is present" \
            '"crash-hybrid"' \
            "$(rpc_dir "$dir" listhybridaddresses 2>/dev/null)"
        local dumped
        dumped="$(rpc_dir "$dir" dumphybridkey "$HYB_IMPORT_ADDR" 2>/dev/null)"
        check_eq "hybrid-after: the ECDSA half is intact" "$HYB_IMPORT_WIF" \
            "$(printf '%s' "$dumped" | json_field secp_wif)"
        check_eq "hybrid-after: the ML-DSA half is intact" "$HYB_IMPORT_DER" \
            "$(printf '%s' "$dumped" | json_field mldsa_priv_der_b64)"
    fi
    verify_common "$dir" "hybrid-$when" "$BASE_BALANCE"
    stop_node "$dir"
}

hybrid_case before
hybrid_case after

verify_encrypted() {
    local dir="$1" label="$2"
    check "$label: LMDB wallet has data and the lmdb marker" \
        "$([ -s "$dir/wallet/data.mdb" ] && [ "$(cat "$dir/wallet.backend" 2>/dev/null)" = lmdb ]; echo $?)"
    check_eq "$label: chain still at height 6" "6" \
        "$(rpc_dir "$dir" getblockcount 2>/dev/null)"
    rpc_expect_fail "$label: wallet is locked after the crash" "$dir" \
        dumpprivkey "$ALICE_ADDR"
    unlock "$dir"
    key_roundtrip "$dir" "$COINBASE5_ADDR" "$COINBASE5_WIF" "$label block 5 key"
    key_roundtrip "$dir" "$ALICE_ADDR" "$ALICE_WIF" "$label alice key"
    check_eq "$label: hybrid key survived encryption" "$HYB_BASE_WIF" \
        "$(rpc_dir "$dir" dumphybridkey "$HYB_BASE_ADDR" 2>/dev/null |
           json_field secp_wif)"
    check_eq "$label: balance survived encryption" "$BASE_BALANCE" \
        "$(rpc_dir "$dir" getbalance 2>/dev/null)"
    check "$label: no wallet.rewrite staging directory is left" \
        "$([ ! -e "$dir/wallet.rewrite" ]; echo $?)"
    check "$label: no wallet.old plaintext copy is left" \
        "$([ ! -e "$dir/wallet.old" ]; echo $?)"
}

rewrite_case() {
    local name="$1" point="$2"
    local dir="$WORK/case-rewrite-$name"
    case_selected "rewrite-$name" || return 0

    echo "== case rewrite-$name: kill at $point =="
    prepare_lmdb_case "$dir"
    if ! start_ready "$dir"; then
        check "rewrite-$name: daemon start" "1"; return
    fi
    crash_during_rpc "rewrite-$name" "$dir" "$point" 0 \
        encryptwallet "$WALLET_PASSPHRASE"

    case "$name" in
    after-copy)
        check "after-copy: the active wallet is still in place" \
            "$([ -d "$dir/wallet" ]; echo $?)"
        check "after-copy: the compacted copy was staged" \
            "$([ -d "$dir/wallet.rewrite" ]; echo $?)"
        check "after-copy: the old wallet was not moved yet" \
            "$([ ! -e "$dir/wallet.old" ]; echo $?)"
        ;;
    after-old-rename)
        check "after-old-rename: the active wallet is missing" \
            "$([ ! -e "$dir/wallet" ]; echo $?)"
        check "after-old-rename: the compacted copy is staged" \
            "$([ -d "$dir/wallet.rewrite" ]; echo $?)"
        check "after-old-rename: the old wallet is parked" \
            "$([ -d "$dir/wallet.old" ]; echo $?)"
        ;;
    after-install)
        check "after-install: the compacted wallet is active" \
            "$([ -d "$dir/wallet" ]; echo $?)"
        check "after-install: the old wallet is still parked" \
            "$([ -d "$dir/wallet.old" ]; echo $?)"
        check "after-install: no staging copy remains" \
            "$([ ! -e "$dir/wallet.rewrite" ]; echo $?)"
        ;;
    esac

    if ! start_ready "$dir"; then
        check "rewrite-$name: restart after the crash" "1"; return
    fi
    if [ "$name" = "after-old-rename" ]; then
        check "after-old-rename: startup restored the staged wallet" \
            "$(grep -q 'Recovered interrupted LMDB wallet rewrite' \
                "$dir/debug.log"; echo $?)"
    fi
    verify_encrypted "$dir" "rewrite-$name"
    stop_node "$dir"
}

# At after-copy the old wallet is untouched and the compacted copy is staged.
rewrite_case after-copy       wallet-rewrite-after-copy
# Between the two renames wallet/ does not exist: startup installs the staged
# copy and removes the old (plaintext) environment.
rewrite_case after-old-rename wallet-rewrite-after-old-rename
# After the new wallet is installed only cleanup of wallet.old remains.
rewrite_case after-install    wallet-rewrite-after-install

echo
echo "== summary =="
echo "  passed: $PASS"
echo "  failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
