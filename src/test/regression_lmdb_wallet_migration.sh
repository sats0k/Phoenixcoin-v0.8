#!/bin/bash
#
# Regression test: migrate a real Berkeley DB wallet to LMDB and keep using it.
#
# This is the end-to-end counterpart to the wallet unit tests.  It drives real
# daemons through the complete handoff:
#
#   BDB wallet.dat
#       -> -walletbackend=lmdb startup
#       -> raw record copy into wallet/ in one transaction
#       -> wallet.backend=lmdb only after the copy commits
#       -> normal wallet use (signing keys, address book, hybrid keys)
#       -> restart (no second migration)
#       -> default BDB start refused while the LMDB marker is present
#       -> backupwallet / restore
#       -> failed migration leaves no marker and no wallet/ behind, then retry
#
# The BDB file is checked byte-for-byte before and after the switch: migration
# is a copy, not a destructive conversion.
#
# Usage: src/test/regression_lmdb_wallet_migration.sh [path-to-phoenixcoind]
#
# The RPC port is chosen from the ephemeral range and can be pinned with
# PXC_REGTEST_PORT for debugging or constrained environments.

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
DATADIR="$(mktemp -d "/tmp/lmdb-wallet.XXXXXX")"
FAIL_DIR="$(mktemp -d "/tmp/lmdb-wallet-fail.XXXXXX")"

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
FAIL_PORT="$(find_free_port)"
while [ "$FAIL_PORT" = "$PORT" ]; do
    FAIL_PORT="$(find_free_port)"
done
case "$FAIL_PORT" in
    ''|*[!0-9]*)
        echo "ERROR: could not allocate a failure-test RPC port" >&2
        exit 1
        ;;
esac

PASS=0
FAIL=0

check() {
    local name="$1" cond="$2"
    if [ "$cond" = "0" ]; then
        PASS=$((PASS+1)); echo "  PASS: $name"
    else
        FAIL=$((FAIL+1)); echo "  FAIL: $name"
    fi
}

write_config() {
    local dir="$1" port="$2"
    cat > "$dir/phoenixcoin.conf" <<EOF
server=1
listen=0
connect=0
maxconnections=0
dnsseed=0
rpcport=$port
rpcuser=reguser
rpcpassword=regpass
debug=1
EOF
}

rpc_dir() {
    local dir="$1" port="$2" method="$3"; shift 3
    timeout 20 "$BIN" -datadir="$dir" -rpcuser=reguser -rpcpassword=regpass \
        -rpcport="$port" "$method" "$@"
}

rpc() {
    rpc_dir "$DATADIR" "$PORT" "$@"
}

wait_ready_at() {
    local dir="$1" port="$2" i
    for i in $(seq 1 60); do
        if timeout 5 "$BIN" -datadir="$dir" -rpcuser=reguser \
                -rpcpassword=regpass -rpcport="$port" getblockcount \
                >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: daemon in $dir did not become ready"
    return 1
}

wait_down_at() {
    local dir="$1" i
    for i in $(seq 1 60); do
        if ! pgrep -f "phoenixcoind -datadir=$dir" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: daemon in $dir did not shut down"
    return 1
}

start_at() {
    local dir="$1" port="$2"; shift 2
    write_config "$dir" "$port"
    "$BIN" -datadir="$dir" "$@" -daemon >/dev/null 2>&1
    wait_ready_at "$dir" "$port"
}

start_node() {
    start_at "$DATADIR" "$PORT" "$@"
}

stop_at() {
    local dir="$1" port="$2"
    rpc_dir "$dir" "$port" stop >/dev/null 2>&1
    wait_down_at "$dir"
}

stop_node() {
    stop_at "$DATADIR" "$PORT"
}

cleanup() {
    local dir
    for dir in "$DATADIR" "$FAIL_DIR"; do
        # Only ask a live daemon to stop.  The RPC client blocks for minutes
        # when nothing is listening in this codebase.
        if pgrep -f "phoenixcoind -datadir=$dir" >/dev/null 2>&1; then
            local port="$PORT"
            [ "$dir" = "$FAIL_DIR" ] && port="$FAIL_PORT"
            rpc_dir "$dir" "$port" stop >/dev/null 2>&1
            wait_down_at "$dir" >/dev/null 2>&1
        fi
        rm -rf "$dir"
    done
}
trap cleanup EXIT

dump_keys() {
    # Print the number of key/value records in a database dump.  Both BDB's
    # db_dump and LMDB's mdb_dump print two lines per record.
    local file="$1" tool="$2" tag="$3" out dumpdir
    dumpdir="$(dirname "$file")"
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "  SKIP: $tool is not installed; raw $tag record check skipped" >&2
        return 1
    fi
    if [ "$tool" = "db_dump" ]; then
        out=$("$tool" -p "$file" 2>/dev/null) || {
            echo "  SKIP: $tool could not read $file" >&2
            return 1
        }
    else
        out=$("$tool" -p -s main "$file" 2>/dev/null) || {
            echo "  SKIP: $tool could not read $file" >&2
            return 1
        }
    fi
    printf '%s\n' "$out" > "$dumpdir/$tag.dump"
    awk '/^HEADER=END$/{inside=1; next}
         /^DATA=END$/{inside=0}
         inside { n++; if (n % 2 == 1) keys++ }
         END { print keys + 0 }' "$dumpdir/$tag.dump"
}

key_roundtrip_dir() {
    local dir="$1" port="$2" addr="$3" want_wif="$4" label="$5"
    check "$label: validateaddress reports the address as owned" \
        "$(rpc_dir "$dir" "$port" validateaddress "$addr" 2>/dev/null | grep -q '"ismine" : true'; echo $?)"
    check "$label: private key is unchanged" \
        "$([ "$(rpc_dir "$dir" "$port" dumpprivkey "$addr" 2>/dev/null)" = "$want_wif" ]; echo $?)"
}

key_roundtrip() {
    key_roundtrip_dir "$DATADIR" "$PORT" "$1" "$2" "$3"
}

echo "== step 1: populate a Berkeley DB wallet =="
start_node || { echo "FAILED: could not start the BDB daemon"; exit 1; }

ADDR=$(rpc getnewaddress alice 2>/dev/null)
WIF=$(rpc dumpprivkey "$ADDR" 2>/dev/null)
HYB=$(rpc gethybridaddress hybrid 2>/dev/null)
HYB_KEY=$(rpc dumphybridkey "$HYB" 2>/dev/null)
check "generated a legacy address" "$([ -n "$ADDR" ] && [ -n "$WIF" ]; echo $?)"
check "generated a hybrid address" "$([ -n "$HYB" ] && [ -n "$HYB_KEY" ]; echo $?)"
check "BDB layout before migration" \
    "$([ -f "$DATADIR/wallet.dat" ] && [ ! -e "$DATADIR/wallet" ] && [ ! -e "$DATADIR/wallet.backend" ]; echo $?)"

stop_node || { echo "FAILED: BDB daemon did not stop"; exit 1; }

BDB_SUM=$(sha256sum "$DATADIR/wallet.dat" | cut -d' ' -f1)
BDB_RECORDS=$(dump_keys "$DATADIR/wallet.dat" db_dump bdb) || BDB_RECORDS=""
[ -n "$BDB_RECORDS" ] && echo "  BDB wallet records: $BDB_RECORDS"

echo "== step 2: migrate wallet.dat to LMDB =="
start_node -walletbackend=lmdb || { echo "FAILED: migration startup failed"; exit 1; }

check "wallet.backend says lmdb" \
    "$([ "$(cat "$DATADIR/wallet.backend" 2>/dev/null)" = "lmdb" ]; echo $?)"
check "LMDB wallet exists" "$([ -s "$DATADIR/wallet/data.mdb" ]; echo $?)"
check "migration was logged" \
    "$(grep -q 'Migrating wallet from wallet.dat to LMDB' "$DATADIR/debug.log"; echo $?)"
check "migration completion was logged" \
    "$(grep -q 'Wallet migration complete' "$DATADIR/debug.log"; echo $?)"
key_roundtrip "$ADDR" "$WIF" "LMDB after migration"
check "hybrid key is unchanged after migration" \
    "$([ "$(rpc dumphybridkey "$HYB" 2>/dev/null)" = "$HYB_KEY" ]; echo $?)"
check "address book entry survived migration" \
    "$(rpc getaddressesbyaccount alice 2>/dev/null | grep -qF "$ADDR"; echo $?)"

stop_node || { echo "FAILED: LMDB daemon did not stop"; exit 1; }

check "wallet.dat is byte-for-byte unchanged" \
    "$([ "$(sha256sum "$DATADIR/wallet.dat" | cut -d' ' -f1)" = "$BDB_SUM" ]; echo $?)"

LMDB_RECORDS=$(dump_keys "$DATADIR/wallet" mdb_dump lmdb-before-restart) || LMDB_RECORDS=""
if [ -n "$BDB_RECORDS" ] && [ -n "$LMDB_RECORDS" ]; then
    echo "  LMDB wallet records: $LMDB_RECORDS"
    check "every BDB record was copied to LMDB" \
        "$([ "$LMDB_RECORDS" = "$BDB_RECORDS" ]; echo $?)"
fi

echo "== step 3: restart on LMDB and keep using the wallet =="
start_node -walletbackend=lmdb || { echo "FAILED: LMDB restart failed"; exit 1; }

check "restart did not run a second migration" \
    "$([ "$(grep -c 'Migrating wallet from wallet.dat to LMDB' "$DATADIR/debug.log")" -eq 1 ]; echo $?)"
key_roundtrip "$ADDR" "$WIF" "LMDB restart"

POST_ADDR=$(rpc getnewaddress postmigration 2>/dev/null)
POST_WIF=$(rpc dumpprivkey "$POST_ADDR" 2>/dev/null)
check "new address created after migration" \
    "$([ -n "$POST_ADDR" ] && [ -n "$POST_WIF" ]; echo $?)"

stop_node || { echo "FAILED: LMDB daemon did not stop"; exit 1; }

start_node -walletbackend=lmdb || { echo "FAILED: LMDB restart failed"; exit 1; }
key_roundtrip "$POST_ADDR" "$POST_WIF" "post-migration address after restart"
key_roundtrip "$ADDR" "$WIF" "migrated address after restart"
stop_node || { echo "FAILED: LMDB daemon did not stop"; exit 1; }

check "wallet.dat stayed untouched through LMDB writes" \
    "$([ "$(sha256sum "$DATADIR/wallet.dat" | cut -d' ' -f1)" = "$BDB_SUM" ]; echo $?)"

echo "== step 4: default BDB start is refused while the marker is lmdb =="
REFUSAL_LOG="$DATADIR/refusal.log"
timeout 30 "$BIN" -datadir="$DATADIR" >"$REFUSAL_LOG" 2>&1
check "BDB start fails during wallet initialization" \
    "$(grep -q 'Error initializing the wallet database' "$REFUSAL_LOG"; echo $?)"
check "BDB start names the LMDB wallet" \
    "$(grep -q 'This data directory uses the LMDB wallet' "$DATADIR/debug.log"; echo $?)"
check "BDB start explains how to use LMDB" \
    "$(grep -q -- '-walletbackend=lmdb' "$DATADIR/debug.log"; echo $?)"
check "BDB refusal left the marker alone" \
    "$([ "$(cat "$DATADIR/wallet.backend" 2>/dev/null)" = "lmdb" ]; echo $?)"
check "BDB refusal left wallet.dat byte-for-byte unchanged" \
    "$([ "$(sha256sum "$DATADIR/wallet.dat" | cut -d' ' -f1)" = "$BDB_SUM" ]; echo $?)"

echo "== step 5: backup and restore the LMDB wallet =="
start_node -walletbackend=lmdb || { echo "FAILED: LMDB daemon did not start"; exit 1; }
rpc backupwallet "$DATADIR/backup" >/dev/null 2>&1
check "backupwallet produced an LMDB environment" \
    "$([ -s "$DATADIR/backup/data.mdb" ]; echo $?)"
stop_node || { echo "FAILED: LMDB daemon did not stop"; exit 1; }

mv "$DATADIR/wallet" "$DATADIR/wallet.active" || exit 1
cp -a "$DATADIR/backup" "$DATADIR/wallet" || exit 1

start_node -walletbackend=lmdb || { echo "FAILED: restored wallet did not start"; exit 1; }
key_roundtrip "$ADDR" "$WIF" "restored backup"
key_roundtrip "$POST_ADDR" "$POST_WIF" "restored backup post-migration address"
stop_node || { echo "FAILED: restored daemon did not stop"; exit 1; }

rm -rf "$DATADIR/wallet"
mv "$DATADIR/wallet.active" "$DATADIR/wallet" || exit 1

start_node -walletbackend=lmdb || { echo "FAILED: original wallet did not restart"; exit 1; }
key_roundtrip "$ADDR" "$WIF" "original wallet after restore test"
stop_node || { echo "FAILED: LMDB daemon did not stop"; exit 1; }

echo "== step 6: failed migration leaves no marker and can be retried =="
start_at "$FAIL_DIR" "$FAIL_PORT" || {
    echo "FAILED: could not create the BDB failure-test wallet"; exit 1;
}
FAIL_ADDR=$(rpc_dir "$FAIL_DIR" "$FAIL_PORT" getnewaddress failtest 2>/dev/null)
FAIL_WIF=$(rpc_dir "$FAIL_DIR" "$FAIL_PORT" dumpprivkey "$FAIL_ADDR" 2>/dev/null)
check "created a BDB wallet for the failure test" \
    "$([ -n "$FAIL_ADDR" ] && [ -n "$FAIL_WIF" ]; echo $?)"
stop_at "$FAIL_DIR" "$FAIL_PORT" || {
    echo "FAILED: failure-test BDB daemon did not stop"; exit 1;
}

FAIL_LOG="$FAIL_DIR/failure.log"
mv "$FAIL_DIR/wallet.dat" "$FAIL_DIR/wallet.dat.real" || exit 1
mkdir "$FAIL_DIR/wallet.dat" || exit 1
timeout 30 "$BIN" -datadir="$FAIL_DIR" -walletbackend=lmdb \
    >"$FAIL_LOG" 2>&1
check "failed migration fails during wallet initialization" \
    "$(grep -q 'Error initializing the wallet database' "$FAIL_LOG"; echo $?)"
check "failed migration reports the unreadable wallet" \
    "$(grep -q 'cannot open wallet.dat' "$FAIL_DIR/debug.log"; echo $?)"
check "failed migration wrote no marker" \
    "$([ ! -e "$FAIL_DIR/wallet.backend" ]; echo $?)"
check "failed migration left no wallet/ behind" \
    "$([ ! -e "$FAIL_DIR/wallet" ]; echo $?)"
check "failed migration did not remove the original wallet" \
    "$([ -f "$FAIL_DIR/wallet.dat.real" ]; echo $?)"

rmdir "$FAIL_DIR/wallet.dat" || exit 1
mv "$FAIL_DIR/wallet.dat.real" "$FAIL_DIR/wallet.dat" || exit 1

# The untouched BDB wallet must still start normally after the failure.
start_at "$FAIL_DIR" "$FAIL_PORT" || {
    echo "FAILED: BDB wallet did not start after the failed migration"; exit 1;
}
key_roundtrip_dir "$FAIL_DIR" "$FAIL_PORT" "$FAIL_ADDR" "$FAIL_WIF" \
    "BDB fallback after failure"
stop_at "$FAIL_DIR" "$FAIL_PORT" || {
    echo "FAILED: fallback daemon did not stop"; exit 1;
}

# Deliberately under-size the map (1 MiB).  The migration must derive enough
# room from wallet.dat instead of failing with MDB_MAP_FULL.
start_at "$FAIL_DIR" "$FAIL_PORT" -walletbackend=lmdb -lmdbwalletsize=1 || {
    echo "FAILED: retry after failure did not start"; exit 1;
}
check "retry pre-sized the map for wallet.dat" \
    "$(grep -q 'LMDB wallet map size increased' "$FAIL_DIR/debug.log"; echo $?)"
check "retry wrote the LMDB marker" \
    "$([ "$(cat "$FAIL_DIR/wallet.backend" 2>/dev/null)" = "lmdb" ]; echo $?)"
key_roundtrip_dir "$FAIL_DIR" "$FAIL_PORT" "$FAIL_ADDR" "$FAIL_WIF" \
    "retry after failure"
stop_at "$FAIL_DIR" "$FAIL_PORT" || {
    echo "FAILED: retry daemon did not stop"; exit 1;
}

echo
echo "wallet migration regression: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
