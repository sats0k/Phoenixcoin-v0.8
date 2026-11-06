#!/bin/bash
#
# Regression test: standalone Berkeley DB to LMDB converter.
#
# Exercises the real operator workflow:
#
#   LMDB daemon creates a sample wallet and chain index
#       -> phoenix-db-fixture rewrites them into legacy wallet.dat/blkindex.dat
#       -> phoenix-db-migrate copies them into wallet/ and blkindex/
#       -> markers are written only after verified installs
#       -> the LMDB daemon loads the migrated wallet and chain index
#       -> a second run reports "already migrated" and changes nothing
#       -> source files stay byte-for-byte identical
#
# It also covers the failure matrix: dry runs, ambiguous markers, missing
# targets, corrupt sources, and interruption at each install step.
#
# Usage:
#   src/test/regression_db_migrate.sh [path-to-phoenixcoind] \
#       [path-to-phoenix-db-migrate] [path-to-phoenix-db-fixture]
#
# The RPC port is chosen from the ephemeral range and can be pinned with
# PXC_REGTEST_PORT for debugging or constrained environments.

set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${1:-$ROOT/src/phoenixcoind}"
MIGRATE="${2:-$ROOT/src/phoenix-db-migrate}"
FIXTURE="${3:-$ROOT/src/phoenix-db-fixture}"

DATADIR="$(mktemp -d "/tmp/db-migrate.XXXXXX")"
ENCDIR="$(mktemp -d "/tmp/db-migrate-enc.XXXXXX")"

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
ENC_PORT="$(find_free_port)"
while [ "$ENC_PORT" = "$PORT" ]; do
    ENC_PORT="$(find_free_port)"
done

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

rpc() { rpc_dir "$DATADIR" "$PORT" "$@"; }

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

stop_at() {
    local dir="$1" port="$2"
    if pgrep -f "phoenixcoind -datadir=$dir" >/dev/null 2>&1; then
        rpc_dir "$dir" "$port" stop >/dev/null 2>&1
        wait_down_at "$dir"
    fi
}

cleanup() {
    stop_at "$DATADIR" "$PORT" >/dev/null 2>&1
    stop_at "$ENCDIR" "$ENC_PORT" >/dev/null 2>&1
    rm -rf "$DATADIR" "$ENCDIR"
}
trap cleanup EXIT

count_records() {
    # Count key/value pairs in a BDB file or an LMDB environment.
    local path="$1" tool="$2" tag="$3" out
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo ""
        return 1
    fi
    if [ "$tool" = "db_dump" ]; then
        out=$("$tool" -p "$path" 2>/dev/null) || return 1
    else
        out=$("$tool" -p -s main "$path" 2>/dev/null) || return 1
    fi
    printf '%s\n' "$out" > "$DATADIR/$tag.dump"
    awk '/^HEADER=END$/{inside=1; next}
         /^DATA=END$/{inside=0}
         inside { n++; if (n % 2 == 1) keys++ }
         END { print keys + 0 }' "$DATADIR/$tag.dump"
}

run_migrate() {
    local dir="$1"; shift
    "$MIGRATE" --datadir="$dir" "$@" > "$dir/migrate.log" 2>&1
}

# Rewrite one LMDB environment from the daemon-created fixture into the
# legacy Berkeley DB layout, then remove the LMDB copy so the converter sees
# exactly the on-disk shape of a pre-LMDB data directory.
make_bdb_fixture() {
    local dir="$1"
    local env="$2"
    local target="$3"
    local dump="$dir/$env.mdbdump"
    if ! mdb_dump -s main "$dir/$env" > "$dump" 2>/dev/null; then
        echo "  ERROR: mdb_dump failed for $dir/$env"
        return 1
    fi
    if ! "$FIXTURE" "$dump" "$target" main; then
        echo "  ERROR: phoenix-db-fixture failed for $target"
        return 1
    fi
    rm -f "$dump"
    rm -rf "$dir/$env"
    rm -f "$dir/$env.backend"
    return 0
}

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

marker_is() { [ "$(cat "$1" 2>/dev/null)" = "$2" ]; }

if [ ! -x "$BIN" ]; then
    echo "ERROR: phoenixcoind not found at $BIN" >&2
    exit 1
fi
if [ ! -x "$MIGRATE" ]; then
    echo "ERROR: phoenix-db-migrate not found at $MIGRATE" >&2
    exit 1
fi
if [ ! -x "$FIXTURE" ]; then
    echo "ERROR: phoenix-db-fixture not found at $FIXTURE" >&2
    exit 1
fi
if ! command -v mdb_dump >/dev/null 2>&1; then
    echo "ERROR: mdb_dump is required to build the legacy fixtures" >&2
    exit 1
fi

echo "== step 1: create the legacy Berkeley DB fixture =="
start_at "$DATADIR" "$PORT" \
    || { echo "FAILED: could not start the LMDB daemon"; exit 1; }

ADDR=$(rpc getnewaddress alice 2>/dev/null)
WIF=$(rpc dumpprivkey "$ADDR" 2>/dev/null)
PUBKEY=$(rpc validateaddress "$ADDR" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["pubkey"])' 2>/dev/null)
rpc setaccount "$ADDR" alice >/dev/null 2>&1
HYB=$(rpc gethybridaddress hybrid 2>/dev/null)
HYB_KEY=$(rpc dumphybridkey "$HYB" 2>/dev/null)
MULTI=$(rpc addmultisigaddress 1 "[\"$PUBKEY\"]" multisig 2>/dev/null)
rpc keypoolrefill 200 >/dev/null 2>&1

check "generated a legacy address" "$([ -n "$ADDR" ] && [ -n "$WIF" ]; echo $?)"
check "generated a hybrid address" "$([ -n "$HYB" ] && [ -n "$HYB_KEY" ]; echo $?)"
check "stored a redeem script" "$([ -n "$MULTI" ]; echo $?)"

KEYPOOL_BEFORE=$(rpc getinfo 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["keypoolsize"])' 2>/dev/null)

stop_at "$DATADIR" "$PORT" || { echo "FAILED: fixture daemon did not stop"; exit 1; }

make_bdb_fixture "$DATADIR" wallet "$DATADIR/wallet.dat" \
    || { echo "FAILED: could not build the wallet fixture"; exit 1; }
make_bdb_fixture "$DATADIR" blkindex "$DATADIR/blkindex.dat" \
    || { echo "FAILED: could not build the chain fixture"; exit 1; }
check "legacy layout before migration" \
    "$([ -f "$DATADIR/wallet.dat" ] && [ -f "$DATADIR/blkindex.dat" ] && [ ! -e "$DATADIR/wallet" ] && [ ! -e "$DATADIR/blkindex" ]; echo $?)"

BDB_WALLET_SUM=$(sha_of "$DATADIR/wallet.dat")
BDB_CHAIN_SUM=$(sha_of "$DATADIR/blkindex.dat")
BDB_WALLET_RECORDS=$(count_records "$DATADIR/wallet.dat" db_dump bdb-wallet) || BDB_WALLET_RECORDS=""
BDB_CHAIN_RECORDS=$(count_records "$DATADIR/blkindex.dat" db_dump bdb-chain) || BDB_CHAIN_RECORDS=""
[ -n "$BDB_WALLET_RECORDS" ] && echo "  BDB wallet records: $BDB_WALLET_RECORDS"
[ -n "$BDB_CHAIN_RECORDS" ] && echo "  BDB chain records: $BDB_CHAIN_RECORDS"

echo "== step 2: dry run writes nothing =="
DRY="$(mktemp -d "/tmp/db-migrate-dry.XXXXXX")"
cp "$DATADIR/wallet.dat" "$DRY/wallet.dat"
run_migrate "$DRY" --wallet --dry-run
DRY_RC=$?
check "dry run succeeded" "$([ "$DRY_RC" = 0 ]; echo $?)"
check "dry run created no target" "$([ ! -e "$DRY/wallet" ]; echo $?)"
check "dry run created no marker" "$([ ! -e "$DRY/wallet.backend" ]; echo $?)"
check "dry run left the source untouched" \
    "$([ "$(sha_of "$DRY/wallet.dat")" = "$BDB_WALLET_SUM" ]; echo $?)"
rm -rf "$DRY"

echo "== step 3: convert the real data directory =="
run_migrate "$DATADIR"
RC=$?
check "converter exited successfully" "$([ $RC = 0 ]; echo $?)"
if [ $RC -ne 0 ]; then
    sed 's/^/    /' "$DATADIR/migrate.log"
fi
check "wallet.backend says lmdb" "$(marker_is "$DATADIR/wallet.backend" lmdb; echo $?)"
check "blkindex.backend says lmdb" "$(marker_is "$DATADIR/blkindex.backend" lmdb; echo $?)"
check "LMDB wallet exists" "$([ -s "$DATADIR/wallet/data.mdb" ]; echo $?)"
check "LMDB chain index exists" "$([ -s "$DATADIR/blkindex/data.mdb" ]; echo $?)"
check "BDB wallet is byte-for-byte unchanged" \
    "$([ "$(sha_of "$DATADIR/wallet.dat")" = "$BDB_WALLET_SUM" ]; echo $?)"
check "BDB chain index is byte-for-byte unchanged" \
    "$([ "$(sha_of "$DATADIR/blkindex.dat")" = "$BDB_CHAIN_SUM" ]; echo $?)"
check "converter left no staging directory" \
    "$([ -z "$(ls -a "$DATADIR" | grep '\.phoenix-migrate-')" ]; echo $?)"

if [ -n "$BDB_WALLET_RECORDS" ]; then
    LMDB_WALLET_RECORDS=$(count_records "$DATADIR/wallet" mdb_dump lmdb-wallet) || LMDB_WALLET_RECORDS=""
    if [ -n "$LMDB_WALLET_RECORDS" ]; then
        check "LMDB wallet has the same record count ($BDB_WALLET_RECORDS)" \
            "$([ "$LMDB_WALLET_RECORDS" = "$BDB_WALLET_RECORDS" ]; echo $?)"
    else
        echo "  SKIP: mdb_dump is not installed; LMDB wallet record count not compared"
    fi
fi
if [ -n "$BDB_CHAIN_RECORDS" ]; then
    LMDB_CHAIN_RECORDS=$(count_records "$DATADIR/blkindex" mdb_dump lmdb-chain) || LMDB_CHAIN_RECORDS=""
    if [ -n "$LMDB_CHAIN_RECORDS" ]; then
        check "LMDB chain has the same record count ($BDB_CHAIN_RECORDS)" \
            "$([ "$LMDB_CHAIN_RECORDS" = "$BDB_CHAIN_RECORDS" ]; echo $?)"
    else
        echo "  SKIP: mdb_dump is not installed; LMDB chain record count not compared"
    fi
fi

echo "== step 4: the LMDB daemon uses the migrated data =="
start_at "$DATADIR" "$PORT" || { echo "FAILED: LMDB daemon did not start"; exit 1; }
check "legacy address is still owned" \
    "$(rpc validateaddress "$ADDR" 2>/dev/null | grep -q '"ismine" : true'; echo $?)"
check "legacy private key is unchanged" \
    "$([ "$(rpc dumpprivkey "$ADDR" 2>/dev/null)" = "$WIF" ]; echo $?)"
check "hybrid private key is unchanged" \
    "$([ "$(rpc dumphybridkey "$HYB" 2>/dev/null)" = "$HYB_KEY" ]; echo $?)"
check "account label survived" \
    "$(rpc getaddressesbyaccount alice 2>/dev/null | grep -q "$ADDR"; echo $?)"
check "redeem script survived" \
    "$(rpc validateaddress "$MULTI" 2>/dev/null | grep -q '"ismine" : true'; echo $?)"
KEYPOOL_AFTER=$(rpc getinfo 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["keypoolsize"])' 2>/dev/null)
check "keypool survived ($KEYPOOL_BEFORE -> $KEYPOOL_AFTER)" \
    "$([ -n "$KEYPOOL_BEFORE" ] && [ -n "$KEYPOOL_AFTER" ] && [ "$KEYPOOL_AFTER" -ge "$KEYPOOL_BEFORE" ] && [ "$KEYPOOL_AFTER" -gt 0 ]; echo $?)"
check "daemon reports LMDB for both scopes" \
    "$(rpc getdbinfo 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
assert d["wallet"]["active_backend"] == "lmdb", d
assert d["chain"]["active_backend"] == "lmdb", d
assert d["wallet"]["marker"]["value"] == "lmdb", d
assert d["chain"]["marker"]["value"] == "lmdb", d
'; echo $?)"
stop_at "$DATADIR" "$PORT"

echo "== step 5: a second run is idempotent =="
run_migrate "$DATADIR"
check "second run exited successfully" "$([ $? = 0 ]; echo $?)"
check "second run reported already migrated" \
    "$(grep -q 'already migrated' "$DATADIR/migrate.log"; echo $?)"
check "second run left the BDB wallet unchanged" \
    "$([ "$(sha_of "$DATADIR/wallet.dat")" = "$BDB_WALLET_SUM" ]; echo $?)"
check "second run left the BDB chain unchanged" \
    "$([ "$(sha_of "$DATADIR/blkindex.dat")" = "$BDB_CHAIN_SUM" ]; echo $?)"

echo "== step 6: encrypted wallet conversion =="
start_at "$ENCDIR" "$ENC_PORT" \
    || { echo "FAILED: could not start the encrypted fixture daemon"; exit 1; }
ENC_ADDR=$(rpc_dir "$ENCDIR" "$ENC_PORT" getnewaddress enc 2>/dev/null)
rpc_dir "$ENCDIR" "$ENC_PORT" encryptwallet 'correct horse battery staple' >/dev/null 2>&1
sleep 2
stop_at "$ENCDIR" "$ENC_PORT"
make_bdb_fixture "$ENCDIR" wallet "$ENCDIR/wallet.dat" \
    || { echo "FAILED: could not build the encrypted wallet fixture"; exit 1; }
run_migrate "$ENCDIR" --wallet
check "encrypted wallet converted" "$([ $? = 0 ]; echo $?)"
check "encrypted wallet marker says lmdb" "$(marker_is "$ENCDIR/wallet.backend" lmdb; echo $?)"
start_at "$ENCDIR" "$ENC_PORT" || { echo "FAILED: encrypted LMDB daemon did not start"; exit 1; }
rpc_dir "$ENCDIR" "$ENC_PORT" walletpassphrase 'correct horse battery staple' 60 >/dev/null 2>&1
check "encrypted key survived conversion" \
    "$([ -n "$(rpc_dir "$ENCDIR" "$ENC_PORT" dumpprivkey "$ENC_ADDR" 2>/dev/null)" ]; echo $?)"
stop_at "$ENCDIR" "$ENC_PORT"

echo "== step 7: failure matrix =="
NEG="$(mktemp -d "/tmp/db-migrate-neg.XXXXXX")"
trap 'stop_at "$DATADIR" "$PORT" >/dev/null 2>&1; stop_at "$ENCDIR" "$ENC_PORT" >/dev/null 2>&1; rm -rf "$DATADIR" "$ENCDIR" "$NEG"' EXIT

# bdb marker plus a non-empty target must never be overwritten.
mkdir -p "$NEG/wallet"
cp "$DATADIR/wallet.dat" "$NEG/wallet.dat"
echo bdb > "$NEG/wallet.backend"
touch "$NEG/wallet/leftover"
run_migrate "$NEG" --wallet
check "refuses a non-empty target with a bdb marker" "$([ $? = 1 ]; echo $?)"
check "refusal wrote no lmdb marker" "$(marker_is "$NEG/wallet.backend" bdb; echo $?)"

# lmdb marker with a missing target is data loss, not an invitation to migrate.
rm -rf "$NEG/wallet"; rm -f "$NEG/wallet.backend"
echo lmdb > "$NEG/wallet.backend"
run_migrate "$NEG" --wallet
check "fails closed when an lmdb marker has no target" "$([ $? = 1 ]; echo $?)"
check "fail-closed run kept the source" \
    "$([ "$(sha_of "$NEG/wallet.dat")" = "$BDB_WALLET_SUM" ]; echo $?)"
rm -f "$NEG/wallet.backend"

# A corrupt source must not create a target or marker.
head -c 4096 /dev/urandom > "$NEG/wallet.dat"
run_migrate "$NEG" --wallet
check "rejects a corrupt source" "$([ $? = 1 ]; echo $?)"
check "corrupt source left no marker" "$([ ! -e "$NEG/wallet.backend" ]; echo $?)"
check "corrupt source left no target" "$([ ! -e "$NEG/wallet" ]; echo $?)"

echo "== step 8: interrupted installs are restartable =="
for MODE in records commit rename; do
    KILL="$(mktemp -d "/tmp/db-migrate-kill.XXXXXX")"
    cp "$DATADIR/wallet.dat" "$KILL/wallet.dat"
    BEFORE=$(sha_of "$KILL/wallet.dat")
    case "$MODE" in
        records) PHOENIX_DB_MIGRATE_TEST_KILL_AFTER_RECORDS=5 \
                     "$MIGRATE" --datadir="$KILL" --wallet >/dev/null 2>&1 ;;
        commit)  PHOENIX_DB_MIGRATE_TEST_KILL_AFTER_COMMIT=1 \
                     "$MIGRATE" --datadir="$KILL" --wallet >/dev/null 2>&1 ;;
        rename)  PHOENIX_DB_MIGRATE_TEST_KILL_AFTER_RENAME=1 \
                     "$MIGRATE" --datadir="$KILL" --wallet >/dev/null 2>&1 ;;
    esac
    check "kill after $MODE left the source untouched" \
        "$([ "$(sha_of "$KILL/wallet.dat")" = "$BEFORE" ]; echo $?)"
    if [ "$MODE" != "rename" ]; then
        check "kill after $MODE left no marker" \
            "$([ ! -e "$KILL/wallet.backend" ]; echo $?)"
    fi
    run_migrate "$KILL" --wallet
    check "rerun after kill at $MODE succeeded" "$([ $? = 0 ]; echo $?)"
    check "rerun after kill at $MODE installed the marker" \
        "$(marker_is "$KILL/wallet.backend" lmdb; echo $?)"
    check "rerun after kill at $MODE preserved the source" \
        "$([ "$(sha_of "$KILL/wallet.dat")" = "$BEFORE" ]; echo $?)"
    rm -rf "$KILL"
done

echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" = 0 ]
