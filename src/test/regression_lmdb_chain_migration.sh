#!/bin/bash
#
# Regression test: migrate a real Berkeley DB chain index to LMDB and keep
# using the chain afterwards.
#
# This is the end-to-end counterpart to the key/value conformance tests.  It
# drives real daemons through the complete handoff:
#
#   BDB chain index
#       -> -dbbackend=lmdb startup
#       -> MigrateToLMDB()
#       -> LMDB CTxDB
#       -> LoadBlockIndex()
#       -> normal chain operation (connect new blocks, read the tx index)
#       -> restart
#       -> same tip, height, block index and transaction records
#
# The test uses real mainnet blocks 1-4 instead of mining.  Block 1 is a
# hardened checkpoint, so a synthetic block cannot be connected without
# weakening consensus checks, and solving the 2^20-difficulty scrypt proof of
# work once per test run would make the test impractically slow.  The blocks
# are submitted through the normal submitblock -> ProcessBlock path, so they
# still exercise the real block validation and connection code.  Their raw
# bytes are fixed mainnet data and need no network access.
#
# Usage: src/test/regression_lmdb_chain_migration.sh [path-to-phoenixcoind]
#
# The RPC port is chosen from the ephemeral range and can be pinned with
# PXC_REGTEST_PORT for debugging or constrained environments.

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
DATADIR="$(mktemp -d "/tmp/lmdb-chain.XXXXXX")"

# Pick a free RPC port so concurrent runs do not collide.  The datadir is
# already unique; this covers the other shared resource.
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

GENESIS_HASH="be2f30f9e8db8f430056869c43503a992d232b28508e83eda101161a18cf7c73"

# Real Phoenixcoin mainnet blocks.  Each entry is the full network-serialised
# block exactly as returned by getblock <hash> 0.
BLOCK_HASH[1]="006e800301bbd850d7ba67ad9295c3a940f5fc8f5581e3484967bd33c4c8b965"
BLOCK_HASH[2]="bde2e3c86d87e869a4d795697462d6ddaccaea039e32aff1038bf2dc48be4e17"
BLOCK_HASH[3]="8064403fcdfa6553cc3c0654312e61cb29478c37cd62f83c91e493dd59474928"
BLOCK_HASH[4]="280766a5b11063ddacc3eecfaa309c9fc5fcde3ecc6d913698f57102d37a2791"

BLOCK_TXID[1]="c83fd7d4170e6f2f3a5cd7cb6c2d0cd228ee739dcc0545b3f3891da9a54bf528"
BLOCK_TXID[2]="c5caaaf73fd71248b7b0dd8fb3cc86f799d8ddcee9b5dc79eb6a85fb79bc4175"
BLOCK_TXID[3]="92f123f5146a4bd906b4b2f66d0d3c642dab5897acf457e35756b37c8e2bfdd3"
BLOCK_TXID[4]="7ca2e1f8e045a933a35d32509b68c56216e76717589db23cd1f39434302e3c5c"

BLOCK_HEX[1]="01000000737ccf181a1601a1ed838e50282b232d993a50439c865600438fdbe8f9302fbe28f54ba5a91d89f3b34505cc9d73ee28d20c2d6ccbd75c3a2f6f0e17d4d73fc842a38a51f0ff0f1ebf6800000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0420a38a510101062f503253482fffffffff0100f2052a01000000232102a3888b3ffdef44aaa27cef8bf6d7214c7f2bdcc9a622999c54f69268330a2d03ac00000000"
BLOCK_HEX[2]="0100000065b9c8c433bd674948e381558ffcf540a9c39592ad67bad750d8bb0103806e007541bc79fb856aeb79dcb5e9ceddd899f786ccb38fddb0b74812d73ff7aacac59ca38a51f0ff0f1eb51b01000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0443a38a510102062f503253482fffffffff0100f2052a01000000232103f9c886d2c62b55754c56dc9db4ee8112f975d2b0e0854ba7a1ab250d9a97f323ac00000000"
BLOCK_HEX[3]="01000000174ebe48dcf28b03f1af329e03eacaacddd662746995d7a469e8876dc8e3e2bdd3fd2b8e7cb35657e357f4ac9758ab2d643c0d6df6b2b406d94b6a14f523f192f9a38a51f0ff0f1ef2e300000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e049da38a510101062f503253482fffffffff0100f2052a010000002321020dd45d8976b2181699b5a42233619a20152efed704e3ed1750ed9ecb0e34a677ac00000000"
BLOCK_HEX[4]="0100000028494759dd93e4913cf862cd378c4729cb612e3154063ccc5365facd3f4064805c3c2e303494f3d13cb29d581767e71662c5689b50325da333a945e0f8e1a27c2da48a51f0ff0f1ef99200000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e04faa38a510104062f503253482fffffffff0100f2052a0100000023210376a74d10b3e60c717d322df2494e698be5615ebf31aec06e8beb9a73e6ce0548ac00000000"

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

rpc() {
    local method="$1"; shift
    local args=(-datadir="$DATADIR" -rpcuser=reguser -rpcpassword=regpass
                -rpcport="$PORT" "$method" "$@")
    if [ -n "${RPC_TIMEOUT:-}" ]; then
        # The RPC client blocks for a long time when nothing is listening,
        # which would turn a failed startup into a hung test run.
        timeout "$RPC_TIMEOUT" "$BIN" "${args[@]}"
    else
        "$BIN" "${args[@]}"
    fi
}

wait_ready() {
    local i
    for i in $(seq 1 60); do
        if RPC_TIMEOUT=5 rpc getblockcount >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: daemon did not become ready"
    return 1
}

wait_down() {
    local i
    for i in $(seq 1 60); do
        if ! pgrep -f "phoenixcoind -datadir=$DATADIR" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: daemon did not shut down"
    return 1
}

start_node() {
    cat > "$DATADIR/phoenixcoin.conf" <<EOF
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
    "$BIN" -datadir="$DATADIR" "$@" -daemon >/dev/null 2>&1
    wait_ready
}

stop_node() {
    RPC_TIMEOUT=15 rpc stop >/dev/null 2>&1
    wait_down
}

cleanup() {
    # Only ask a live daemon to stop.  Invoking the RPC client with no server
    # listening blocks for minutes in this codebase, so check first instead of
    # relying on the call to fail quickly.
    if pgrep -f "phoenixcoind -datadir=$DATADIR" >/dev/null 2>&1; then
        RPC_TIMEOUT=15 rpc stop >/dev/null 2>&1
        wait_down >/dev/null 2>&1
    fi
    rm -rf "$DATADIR"
}
trap cleanup EXIT

check_height_and_tip() {
    local want_height="$1" want_hash="$2" label="$3"
    local height hash
    height=$(rpc getblockcount 2>/dev/null)
    hash=$(rpc getblockhash "$want_height" 2>/dev/null)
    check "$label: height is $want_height" "$([ "$height" = "$want_height" ]; echo $?)"
    check "$label: block hash at height $want_height is preserved" \
        "$([ "$hash" = "$want_hash" ]; echo $?)"
}

check_block_records() {
    local last="$1" label="$2" h block_hex tx_hex
    for h in $(seq 1 "$last"); do
        block_hex="${BLOCK_HEX[$h]}"
        # These early blocks have a single coinbase transaction.  The tx hex
        # starts after the 80-byte header and the one-byte tx count: 162
        # hexadecimal characters.
        tx_hex="${block_hex:162}"
        check "$label: block $h round-trips through getblock" \
            "$([ "$(rpc getblock "${BLOCK_HASH[$h]}" 0 2>/dev/null)" = "$block_hex" ]; echo $?)"
        check "$label: tx index returns coinbase of block $h" \
            "$([ "$(rpc getrawtransaction "${BLOCK_TXID[$h]}" 0 2>/dev/null)" = "$tx_hex" ]; echo $?)"
    done
}

dump_keys() {
    # Print the number of key/value records in a database dump.  Both BDB's
    # db_dump and LMDB's mdb_dump use two lines per record (key, then value),
    # which makes the count unambiguous.
    local file="$1" tool="$2" tag="$3" out
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
    printf '%s\n' "$out" > "$DATADIR/$tag.dump"
    awk '/^HEADER=END$/{inside=1; next}
         /^DATA=END$/{inside=0}
         inside { n++; if (n % 2 == 1) keys++ }
         END { print keys + 0 }' "$DATADIR/$tag.dump"
}

check_dump_key_count() {
    local tag="$1" prefix="$2" want="$3" label="$4"
    [ -f "$DATADIR/$tag.dump" ] || return 0
    check "$label: $want $prefix keys" \
        "$([ "$(grep -cF " $prefix" "$DATADIR/$tag.dump")" -eq "$want" ]; echo $?)"
}

check_dump_key_present() {
    local tag="$1" key="$2" label="$3"
    [ -f "$DATADIR/$tag.dump" ] || return 0
    check "$label: $key record is present" \
        "$(grep -qF " $key" "$DATADIR/$tag.dump"; echo $?)"
}

echo "== step 1: populate a BDB chain index with real blocks =="
start_node || { echo "FAILED: could not start the BDB daemon"; exit 1; }

check "starts with the BDB backend" \
    "$([ -f "$DATADIR/blkindex.dat" ] && [ ! -e "$DATADIR/blkindex" ] && [ ! -e "$DATADIR/blkindex.backend" ]; echo $?)"
check_height_and_tip 0 "$GENESIS_HASH" "BDB"

for h in 1 2; do
    check "submitblock accepts mainnet block $h" \
        "$([ -z "$(rpc submitblock "${BLOCK_HEX[$h]}" 2>&1)" ]; echo $?)"
done
check_height_and_tip 2 "${BLOCK_HASH[2]}" "BDB after blocks 1-2"
check_block_records 2 "BDB"

stop_node || { echo "FAILED: BDB daemon did not shut down"; exit 1; }

BDB_RECORDS=$(dump_keys "$DATADIR/blkindex.dat" db_dump bdb)
if [ -n "$BDB_RECORDS" ]; then
    echo "  INFO: BDB chain index has $BDB_RECORDS records"
    check_dump_key_count bdb '\0ablockindex' 3 "BDB"
    # The genesis coinbase is not connected through ConnectBlock(), so only
    # blocks 1-2 have transaction-index records here.
    check_dump_key_count bdb '\02tx' 2 "BDB"
    check_dump_key_present bdb '\0dhashBestChain' "BDB"
    check_dump_key_present bdb '\12hashSyncCheckpoint' "BDB"
    check_dump_key_present bdb '\13strCheckpointPubKey' "BDB"
fi

echo "== step 2: migrate to LMDB on startup =="
start_node -dbbackend=lmdb || { echo "FAILED: could not start the LMDB daemon"; exit 1; }

check "blkindex.backend marker says lmdb" \
    "$([ "$(cat "$DATADIR/blkindex.backend" 2>/dev/null)" = "lmdb" ]; echo $?)"
check "LMDB chain index directory exists" \
    "$([ -d "$DATADIR/blkindex" ]; echo $?)"
check "Berkeley DB blkindex.dat is left in place as the migration source" \
    "$([ -f "$DATADIR/blkindex.dat" ]; echo $?)"
check "wallet storage stays on Berkeley DB" \
    "$([ -f "$DATADIR/wallet.dat" ] && [ ! -e "$DATADIR/wallet" ]; echo $?)"
check_height_and_tip 2 "${BLOCK_HASH[2]}" "LMDB after migration"
check_block_records 2 "LMDB after migration"

stop_node || { echo "FAILED: LMDB daemon did not shut down"; exit 1; }

LMDB_RECORDS=$(dump_keys "$DATADIR/blkindex" mdb_dump lmdb)
if [ -n "$LMDB_RECORDS" ]; then
    echo "  INFO: LMDB chain index has $LMDB_RECORDS records"
    if [ -n "$BDB_RECORDS" ]; then
        check "migration copied every BDB record ($BDB_RECORDS -> $LMDB_RECORDS)" \
            "$([ "$LMDB_RECORDS" = "$BDB_RECORDS" ]; echo $?)"
    fi
    check_dump_key_count lmdb '\0ablockindex' 3 "LMDB after migration"
    check_dump_key_count lmdb '\02tx' 2 "LMDB after migration"
    check_dump_key_present lmdb '\0dhashBestChain' "LMDB after migration"
    check_dump_key_present lmdb '\12hashSyncCheckpoint' "LMDB after migration"
    check_dump_key_present lmdb '\13strCheckpointPubKey' "LMDB after migration"
fi

echo "== step 3: restart on LMDB and connect more blocks =="
start_node -dbbackend=lmdb || { echo "FAILED: could not restart the LMDB daemon"; exit 1; }
check_height_and_tip 2 "${BLOCK_HASH[2]}" "LMDB restart"
check_block_records 2 "LMDB restart"

for h in 3 4; do
    check "submitblock accepts mainnet block $h on LMDB" \
        "$([ -z "$(rpc submitblock "${BLOCK_HEX[$h]}" 2>&1)" ]; echo $?)"
done
check_height_and_tip 4 "${BLOCK_HASH[4]}" "LMDB after connecting blocks 3-4"
check_block_records 4 "LMDB after connecting blocks 3-4"

stop_node || { echo "FAILED: LMDB daemon did not shut down"; exit 1; }

LMDB_RECORDS_AFTER=$(dump_keys "$DATADIR/blkindex" mdb_dump lmdb-after)
if [ -n "$LMDB_RECORDS_AFTER" ]; then
    echo "  INFO: LMDB chain index has $LMDB_RECORDS_AFTER records after blocks 3-4"
    if [ -n "$LMDB_RECORDS" ]; then
        check "connecting two blocks added four records ($LMDB_RECORDS -> $LMDB_RECORDS_AFTER)" \
            "$([ "$LMDB_RECORDS_AFTER" = "$((LMDB_RECORDS + 4))" ]; echo $?)"
    fi
    check_dump_key_count lmdb-after '\0ablockindex' 5 "LMDB after blocks 3-4"
    check_dump_key_count lmdb-after '\02tx' 4 "LMDB after blocks 3-4"
    check_dump_key_present lmdb-after '\0dhashBestChain' "LMDB after blocks 3-4"
fi

echo "== step 4: restart again and verify the new tip persists =="
start_node -dbbackend=lmdb || { echo "FAILED: could not restart the LMDB daemon"; exit 1; }
check_height_and_tip 4 "${BLOCK_HASH[4]}" "LMDB final restart"
check_block_records 4 "LMDB final restart"

stop_node || { echo "FAILED: LMDB daemon did not shut down"; exit 1; }

echo
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
