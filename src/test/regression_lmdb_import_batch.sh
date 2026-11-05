#!/bin/bash
#
# Regression test: batch the chain-index transaction while importing an
# external block file with -loadblock.
#
# The importer groups consecutive best-chain blocks below the checkpoint
# estimate into one LMDB transaction.  This test drives real mainnet blocks
# through that path and checks four things:
#
#   1. a clean bootstrap.dat imports all blocks in one batch and the tip,
#      block index and transaction index survive a restart, with wallet
#      notifications covering the pre-batch tip and every intermediate
#      coinbase;
#   2. importing the same file again skips known blocks instead of stopping
#      on the first duplicate;
#   3. a rejected block in the middle of a batch rolls the whole uncommitted
#      batch back without sending any notifications, so the node restarts at
#      genesis and a later clean import reaches the correct tip.
#
# Real blocks 1-4 are used because block 1 is a hardened checkpoint and their
# raw bytes need no mining or network access.  See
# regression_lmdb_chain_migration.sh for the same fixture.
#
# Usage: src/test/regression_lmdb_import_batch.sh [path-to-phoenixcoind]
#
# The RPC port is chosen from the ephemeral range and can be pinned with
# PXC_REGTEST_PORT for debugging or constrained environments.

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
DATADIR="$(mktemp -d "/tmp/lmdb-import-batch.XXXXXX")"
WORKDIR="$(mktemp -d "/tmp/lmdb-import-batch-files.XXXXXX")"

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
GENESIS_COINBASE="ff2aa75842fae1bfb100b656c57229ce37b03643434da2043ddab7a11cfe69a6"

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
    if pgrep -f "phoenixcoind -datadir=$DATADIR" >/dev/null 2>&1; then
        RPC_TIMEOUT=15 rpc stop >/dev/null 2>&1
        wait_down >/dev/null 2>&1
    fi
    rm -rf "$DATADIR"
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# Write a block file in the format LoadExternalBlockFile() scans:
# pchMessageStart, little-endian serialized size, then the block bytes.
make_block_file() {
    local out="$1"; shift
    python3 - "$out" "$@" <<'PY'
import struct
import sys

path = sys.argv[1]
with open(path, "wb") as f:
    for hex_block in sys.argv[2:]:
        data = bytes.fromhex(hex_block)
        f.write(bytes.fromhex("fed0d8c3"))
        f.write(struct.pack("<I", len(data)))
        f.write(data)
PY
}

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
        tx_hex="${block_hex:162}"
        check "$label: block $h round-trips through getblock" \
            "$([ "$(rpc getblock "${BLOCK_HASH[$h]}" 0 2>/dev/null)" = "$block_hex" ]; echo $?)"
        check "$label: tx index returns coinbase of block $h" \
            "$([ "$(rpc getrawtransaction "${BLOCK_TXID[$h]}" 0 2>/dev/null)" = "$tx_hex" ]; echo $?)"
    done
}

CLEAN_BLOCKS="$WORKDIR/clean.bootstrap.dat"
make_block_file "$CLEAN_BLOCKS" \
    "${BLOCK_HEX[1]}" "${BLOCK_HEX[2]}" "${BLOCK_HEX[3]}" "${BLOCK_HEX[4]}" || {
    echo "ERROR: could not create the clean block file" >&2
    exit 1
}

echo "== step 1: import four blocks in one batch =="
PHOENIX_TEST_NOTIFY_BATCH=1 start_node -dbbackend=lmdb -walletbackend=bdb "-loadblock=$CLEAN_BLOCKS" || {
    echo "FAILED: could not start the importing daemon"; exit 1;
}

check "the clean import committed one four-block batch" \
    "$(grep -q 'CChainImportBatch: committed 4 blocks' "$DATADIR/debug.log"; echo $?)"
# The batched commit must notify wallets about the pre-batch tip and every
# intermediate coinbase, exactly as the per-block path did.  The final block's
# coinbase is stored and announced only when the next best block arrives.
grep -o 'CChainImportBatch: notify coinbase [0-9a-f]*' "$DATADIR/debug.log" \
    | awk '{print $4}' > "$WORKDIR/notify.txt"
printf '%s\n%s\n%s\n%s\n' "$GENESIS_COINBASE" \
    "${BLOCK_TXID[1]}" "${BLOCK_TXID[2]}" "${BLOCK_TXID[3]}" \
    > "$WORKDIR/notify.expected"
check "the batch notified the previous tip and each intermediate coinbase" \
    "$(cmp -s "$WORKDIR/notify.txt" "$WORKDIR/notify.expected"; echo $?)"
check_height_and_tip 4 "${BLOCK_HASH[4]}" "clean import"
check_block_records 4 "clean import"

stop_node || { echo "FAILED: clean-import daemon did not shut down"; exit 1; }

echo "== step 2: re-import the same file without stopping at duplicates =="
: > "$DATADIR/debug.log"
start_node -dbbackend=lmdb -walletbackend=bdb "-loadblock=$CLEAN_BLOCKS" || {
    echo "FAILED: could not restart the daemon"; exit 1;
}
check_height_and_tip 4 "${BLOCK_HASH[4]}" "duplicate import"
check_block_records 4 "duplicate import"
check "duplicate import did not create another batch" \
    "$(! grep -q 'CChainImportBatch: committed' "$DATADIR/debug.log"; echo $?)"

stop_node || { echo "FAILED: duplicate-import daemon did not shut down"; exit 1; }

echo "== step 3: a rejected middle block rolls back the open batch =="
# Start from a fresh datadir so the wallet knows nothing about the earlier
# chain and only genesis is present.
rm -rf "$DATADIR"
DATADIR="$(mktemp -d "/tmp/lmdb-import-batch.XXXXXX")"
# Flip one nibble of block 3's merkle root.  The block still deserializes with
# the same size, but its proof of work / merkle check fails.
BAD_NIBBLE="${BLOCK_HEX[3]:72:1}"
if [ "$BAD_NIBBLE" = "1" ]; then BAD_NIBBLE=2; else BAD_NIBBLE=1; fi
BAD_BLOCK_3="${BLOCK_HEX[3]:0:72}${BAD_NIBBLE}${BLOCK_HEX[3]:73}"
BAD_BLOCKS="$WORKDIR/bad.bootstrap.dat"
make_block_file "$BAD_BLOCKS" \
    "${BLOCK_HEX[1]}" "${BLOCK_HEX[2]}" "$BAD_BLOCK_3" "${BLOCK_HEX[4]}" || {
    echo "ERROR: could not create the corrupted block file" >&2
    exit 1
}

PHOENIX_TEST_NOTIFY_BATCH=1 start_node -dbbackend=lmdb -walletbackend=bdb "-loadblock=$BAD_BLOCKS" || {
    echo "FAILED: could not start the rollback daemon"; exit 1;
}
check "the rejected block stopped the import" \
    "$(grep -q 'rejected, stopping' "$DATADIR/debug.log"; echo $?)"
check "the uncommitted two-block batch was rolled back" \
    "$(grep -q 'CChainImportBatch: rolled back 2 blocks' "$DATADIR/debug.log"; echo $?)"
check "the rolled-back batch sent no transaction notifications" \
    "$(! grep -q 'CChainImportBatch: notify coinbase' "$DATADIR/debug.log"; echo $?)"
check_height_and_tip 0 "$GENESIS_HASH" "after rollback"
check "block 1 is absent from the rolled-back index" \
    "$([ -z "$(rpc getblockhash 1 2>/dev/null)" ]; echo $?)"
check "block 2 is absent from the rolled-back index" \
    "$([ -z "$(rpc getblockhash 2 2>/dev/null)" ]; echo $?)"

stop_node || { echo "FAILED: rollback daemon did not shut down"; exit 1; }

echo "== step 4: a clean re-import reaches the correct tip =="
start_node -dbbackend=lmdb -walletbackend=bdb "-loadblock=$CLEAN_BLOCKS" || {
    echo "FAILED: could not start the recovery daemon"; exit 1;
}
check "the recovery import committed one four-block batch" \
    "$(grep -q 'CChainImportBatch: committed 4 blocks' "$DATADIR/debug.log"; echo $?)"
check_height_and_tip 4 "${BLOCK_HASH[4]}" "recovery import"
check_block_records 4 "recovery import"

stop_node || { echo "FAILED: recovery daemon did not shut down"; exit 1; }

echo
echo "lmdb import batch regression: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
