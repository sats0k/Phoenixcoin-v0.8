#!/bin/bash
#
# Regression test: full Berkeley DB wallet lifecycle, then migrate to LMDB and
# keep using the wallet normally.
#
# This is the end-to-end counterpart to wallet_migration_tests.  It drives two
# real daemons through the whole lifecycle:
#
#   BDB wallet.dat
#       -> real chain fragment (mainnet blocks 1-6)
#       -> imported keys, address book labels, watch-only and multisig scripts
#       -> real wallet transactions (coinbase credit + signed spend)
#       -> encryptwallet (daemon restart, locked wallet)
#       -> keypool refill and hybrid keys while unlocked
#       -> -walletbackend=lmdb startup (migration)
#       -> verify every wallet record class through RPC
#       -> restart LMDB and verify again
#       -> normal wallet use: new keys, labels, signatures, hybrid keys,
#          keypool refill and a brand new signed transaction
#       -> restart LMDB and verify the new state survived
#
# The BDB file is checked byte-for-byte before and after the switch: migration
# is a copy, not a destructive conversion.
#
# Why pre-mined blocks?
# ---------------------
# This codebase has no regtest mode.  A wallet transaction needs a real,
# spendable chain output, and a mainnet coinbase needs 101 confirmations.  The
# fixed blocks 1-4 only pay P2PK outputs whose private keys are unknown, and
# mining 101 blocks at the 2^20 proof-of-work limit would take hours on a CPU
# (about 8-10 kH/s here).  Blocks 5 and 6 below were mined once, at that same
# limit, to keys whose WIFs are embedded in this test.  They are submitted
# through the normal submitblock -> ProcessBlock path, so they still exercise
# real block validation and connection.  The test daemon is started with
# PHOENIX_TEST_COINBASE_MATURITY=0, a test-only override that makes those
# coinbases spendable immediately; it is inert unless the environment variable
# is set.  That lets the test build a genuinely valid signed transaction.
#
# Usage: src/test/regression_lmdb_wallet_e2e.sh [path-to-phoenixcoind]
#
# The RPC port is chosen from the ephemeral range and can be pinned with
# PXC_REGTEST_PORT for debugging or constrained environments.

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
DATADIR="$(mktemp -d "/tmp/lmdb-wallet-e2e.XXXXXX")"

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

check_eq() {
    local name="$1" want="$2" got="$3"
    check "$name" "$([ "$want" = "$got" ]; echo $?)"
}

check_contains() {
    local name="$1" needle="$2" haystack="$3"
    check "$name" "$(printf '%s\n' "$haystack" | grep -qF -- "$needle"; echo $?)"
}

check_rpc_fails() {
    local name="$1"; shift
    if rpc "$@" >/dev/null 2>&1; then
        FAIL=$((FAIL+1)); echo "  FAIL: $name (unexpected success)"
    else
        PASS=$((PASS+1)); echo "  PASS: $name"
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
    timeout 30 "$BIN" -datadir="$dir" -rpcuser=reguser -rpcpassword=regpass \
        -rpcport="$port" "$method" "$@"
}

rpc() {
    rpc_dir "$DATADIR" "$PORT" "$@"
}

wait_ready_at() {
    local dir="$1" port="$2" i
    for i in $(seq 1 90); do
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
    for i in $(seq 1 90); do
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
    # The maturity override is test-only and forgotten by the daemon on exit.
    PHOENIX_TEST_COINBASE_MATURITY=0 \
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
    if pgrep -f "phoenixcoind -datadir=$DATADIR" >/dev/null 2>&1; then
        rpc_dir "$DATADIR" "$PORT" stop >/dev/null 2>&1
        wait_down_at "$DATADIR" >/dev/null 2>&1
    fi
    rm -rf "$DATADIR"
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

key_roundtrip() {
    local addr="$1" want_wif="$2" label="$3"
    check "$label: validateaddress reports the address as owned" \
        "$(rpc validateaddress "$addr" 2>/dev/null | grep -q '"ismine" : true'; echo $?)"
    check "$label: private key is unchanged" \
        "$([ "$(rpc dumpprivkey "$addr" 2>/dev/null)" = "$want_wif" ]; echo $?)"
}

unlock() {
    rpc walletpassphrase "$WALLET_PASSPHRASE" 600 >/dev/null 2>&1
}

lock() {
    rpc walletlock >/dev/null 2>&1
}

wait_for_tx_in_mempool() {
    local txid="$1" i
    for i in $(seq 1 20); do
        if rpc getrawmempool 2>/dev/null | grep -qF "$txid"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# The fixed mainnet blocks 1-4 come from the chain-migration regression; blocks
# 5 and 6 were mined once with the same consensus rules and pay the WIFs below.
CHAIN_TEST="$(cd "$(dirname "$0")" && pwd)/regression_lmdb_chain_migration.sh"
if ! grep -q '^BLOCK_HEX\[' "$CHAIN_TEST" 2>/dev/null; then
    echo "ERROR: cannot find the fixed blocks in $CHAIN_TEST" >&2
    exit 1
fi
eval "$(grep '^BLOCK_HEX\[' "$CHAIN_TEST")"

BLOCK_HEX[5]="0200000091277ad30271f59836916dcc3edefcc59f9c30aacfeec3acdd6310b1a566072850cb9d591fbc58a76ab1c25d2fefaf3984da56f37302c554a31e0cf9848f86338af0e66af0ff0f1e3a0000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0b5502d804062f503253482fffffffff0100f2052a01000000232103bebdbbeeb9c1220d29d8bddc765c9935dd9b764cac9d83d64435a9a4074002c2ac00000000"
BLOCK_HEX[6]="0200000086d11e9d9484c72b534f27ba04fd1f6a6ed9f39f6d13869698df51dc80599aa710ee449d4c94aee22fea887407ac1c69862c52612199f4a3355c667cc2fc678df7f1e66af0ff0f1e540000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0b5602730c062f503253482fffffffff0100f2052a01000000232102d9833e4c4dec81e502308d05938d1d821a627983660f5b20d976b04562a8b780ac00000000"

BLOCK5_TXID="33868f84f90c1ea354c50273f356da8439afef2f5dc2b16aa758bc1f599dcb50"
BLOCK6_TXID="8d67fcc27c665c35a3f4992161522c86691cac077488ea2fe2ae944c9d44ee10"
COINBASE5_WIF="UEXuWq8hwusSVrhFtPowPv5H8xfvUT5vDx1y1CfNNj8vpBwjVYwR"
COINBASE6_WIF="UFEFb173uqVWSBeFnB6gstGyuvREZLMLNUXeMka4ETEAAvYouXBo"
COINBASE5_ADDR="PfzGAi9DoiSkPYSjDAEFLTiggCv6LKSFmf"
COINBASE6_ADDR="PeyhySKGqLTKn4mh91L8ePtQPEUsdXL9Yn"
EXTERNAL_ADDR="Puicad2AcZRj9DgF8WJtywBU7AbMxxLGAS"
# A valid mainnet address with no history in the fixed chain fragment, kept
# watch-only so its credit (if any) never disturbs the wallet balance checks.
WATCH_ADDR="Pajnrp35dtogiFeTqQxNurGDgsxfVVaUrz"
WALLET_PASSPHRASE="e2e passphrase with spaces"

echo "== step 1: populate a Berkeley DB wallet =="
start_node -walletbackend=bdb || { echo "FAILED: could not start the BDB daemon"; exit 1; }

for h in 1 2 3 4 5 6; do
    rpc submitblock "${BLOCK_HEX[$h]}" >/dev/null 2>&1
done
check_eq "chain fragment connected to height 6" "6" "$(rpc getblockcount 2>/dev/null)"
check_eq "first pre-mined block hash" \
    "a79a5980dc51df989686136d9ff3d96e6a1ffd04ba274f532bc784949d1ed186" \
    "$(rpc getblockhash 5 2>/dev/null)"

# Import the two coinbase keys with a rescan so the wallet sees the coinbases.
rpc importprivkey "$COINBASE5_WIF" "coinbase-5" true >/dev/null 2>&1
rpc importprivkey "$COINBASE6_WIF" "coinbase-6" true >/dev/null 2>&1
key_roundtrip "$COINBASE5_ADDR" "$COINBASE5_WIF" "block 5 coinbase key"
key_roundtrip "$COINBASE6_ADDR" "$COINBASE6_WIF" "block 6 coinbase key"
check_contains "block 5 coinbase is in the wallet history" "$BLOCK5_TXID" \
    "$(rpc listtransactions '*' 20 2>/dev/null)"
check_contains "block 6 coinbase is in the wallet history" "$BLOCK6_TXID" \
    "$(rpc listtransactions '*' 20 2>/dev/null)"
check_eq "coinbase balance is 100 PXC" "100.00000000" \
    "$(rpc getbalance 2>/dev/null)"

# Create a real signed transaction before encryption.  It spends block 5's
# coinbase and pays an address that is not in this wallet.
TX_PRE=$(rpc sendtoaddress "$EXTERNAL_ADDR" 10 "e2e pre-migration send" "e2e" 2>/dev/null)
check "created a pre-migration wallet transaction" \
    "$([ -n "$TX_PRE" ]; echo $?)"
check "pre-migration transaction reached the mempool" \
    "$(wait_for_tx_in_mempool "$TX_PRE"; echo $?)"
TX_PRE_JSON=$(rpc listtransactions '*' 20 2>/dev/null)
check_contains "pre-migration send is in the wallet history" "$TX_PRE" \
    "$TX_PRE_JSON"
TX_PRE_DETAIL=$(rpc gettransaction "$TX_PRE" 2>/dev/null)
check_contains "pre-migration send is recorded as a send" '"category" : "send"' \
    "$TX_PRE_DETAIL"
check_contains "pre-migration send paid the external address" "$EXTERNAL_ADDR" \
    "$TX_PRE_DETAIL"
check_contains "pre-migration send kept its amount" '"amount" : -10.00000000' \
    "$TX_PRE_DETAIL"
check "pre-migration transaction is a hybrid signature" \
    "$(printf '%s\n' "$TX_PRE_DETAIL" | grep -q 'Hybrid (ECDSA + ML-DSA-65)'; echo $?)"
BALANCE_AFTER_PRE=$(rpc getbalance 2>/dev/null)
check_eq "balance after the pre-migration send" "89.99000000" "$BALANCE_AFTER_PRE"

# Keys, labels, watch-only state and a multisig script.
ALICE_ADDR=$(rpc getnewaddress alice 2>/dev/null)
ALICE_WIF=$(rpc dumpprivkey "$ALICE_ADDR" 2>/dev/null)
BOB_ADDR=$(rpc getnewaddress bob 2>/dev/null)
BOB_WIF=$(rpc dumpprivkey "$BOB_ADDR" 2>/dev/null)
check "created labelled receiving addresses" \
    "$([ -n "$ALICE_ADDR" ] && [ -n "$BOB_ADDR" ] && [ "$ALICE_ADDR" != "$BOB_ADDR" ]; echo $?)"
check_contains "alice address is in the alice account" "$ALICE_ADDR" \
    "$(rpc getaddressesbyaccount alice 2>/dev/null)"
check_contains "bob address is in the bob account" "$BOB_ADDR" \
    "$(rpc getaddressesbyaccount bob 2>/dev/null)"

rpc importaddress "$WATCH_ADDR" "watched-external" false >/dev/null 2>&1
WATCH_JSON=$(rpc validateaddress "$WATCH_ADDR" 2>/dev/null)
check_contains "watch-only address is registered" '"watchonly" : true' "$WATCH_JSON"
check_contains "watch-only address has its label" '"account" : "watched-external"' \
    "$WATCH_JSON"

MULTISIG_ADDR=$(rpc addmultisigaddress 1 \
    '["02a3888b3ffdef44aaa27cef8bf6d7214c7f2bdcc9a622999c54f69268330a2d03","03f9c886d2c62b55754c56dc9db4ee8112f975d2b0e0854ba7a1ab250d9a97f323"]' \
    multisig 2>/dev/null)
check "created a multisig script address" \
    "$([ -n "$MULTISIG_ADDR" ]; echo $?)"
check_contains "multisig address is in the multisig account" "$MULTISIG_ADDR" \
    "$(rpc getaddressesbyaccount multisig 2>/dev/null)"

SIGN_ADDR="$ALICE_ADDR"
SIGNATURE=$(rpc signmessage "$SIGN_ADDR" "wallet migration end-to-end" 2>/dev/null)
check "signed a message before encryption" \
    "$(rpc verifymessage "$SIGN_ADDR" "$SIGNATURE" "wallet migration end-to-end" 2>/dev/null | grep -q true; echo $?)"
check "a tampered message does not verify" \
    "$(! rpc verifymessage "$SIGN_ADDR" "$SIGNATURE" "tampered" 2>/dev/null | grep -q true; echo $?)"

# Keypool state (this wallet format has no separate HD chain).
rpc keypoolrefill 50 >/dev/null 2>&1
KEYPOOL_ADDR=$(rpc getnewaddress keypool 2>/dev/null)
check "keypool produced a new address" "$([ -n "$KEYPOOL_ADDR" ]; echo $?)"

# Hybrid keys and labels.
HYB_BEFORE_ADDR=$(rpc gethybridaddress "hybrid-before" 2>/dev/null)
HYB_BEFORE_KEY=$(rpc dumphybridkey "$HYB_BEFORE_ADDR" 2>/dev/null)
check "created a labelled hybrid key before migration" \
    "$([ -n "$HYB_BEFORE_ADDR" ] && [ -n "$HYB_BEFORE_KEY" ]; echo $?)"
check_contains "hybrid address book entry survived" '"label" : "hybrid-before"' \
    "$(rpc listhybridaddresses 2>/dev/null)"
check_contains "hybrid key export carries the ML-DSA private key" \
    '"mldsa_priv_der_b64"' "$HYB_BEFORE_KEY"

stop_node || { echo "FAILED: BDB daemon did not stop"; exit 1; }

echo "== step 2: encrypt the BDB wallet =="
start_node -walletbackend=bdb || { echo "FAILED: could not restart the BDB daemon"; exit 1; }
ENCRYPT_RESULT=$(rpc encryptwallet "$WALLET_PASSPHRASE" 2>/dev/null)
check "encryptwallet returned the restart notice" \
    "$(printf '%s' "$ENCRYPT_RESULT" | grep -qi 'encrypt'; echo $?)"
wait_down_at "$DATADIR" || { echo "FAILED: encryptwallet did not stop the daemon"; exit 1; }

start_node -walletbackend=bdb || { echo "FAILED: encrypted BDB daemon did not restart"; exit 1; }
check_eq "chain is intact after encryption restart" "6" "$(rpc getblockcount 2>/dev/null)"
check_rpc_fails "encrypted wallet is locked: dumpprivkey is refused" \
    dumpprivkey "$ALICE_ADDR"
check_rpc_fails "wrong passphrase is rejected" \
    walletpassphrase "wrong passphrase" 60
unlock
check "correct passphrase unlocks the wallet" \
    "$([ "$(rpc dumpprivkey "$ALICE_ADDR" 2>/dev/null)" = "$ALICE_WIF" ]; echo $?)"
check_eq "encrypted wallet keeps the confirmed balance" "$BALANCE_AFTER_PRE" \
    "$(rpc getbalance 2>/dev/null)"

# Add keypool and hybrid state while the encrypted wallet is unlocked.
rpc keypoolrefill 80 >/dev/null 2>&1
check "keypool refill works on the encrypted wallet" \
    "$([ -n "$(rpc getnewaddress keypool-encrypted 2>/dev/null)" ]; echo $?)"
HYB_ENC_ADDR=$(rpc gethybridaddress "hybrid-encrypted" 2>/dev/null)
HYB_ENC_KEY=$(rpc dumphybridkey "$HYB_ENC_ADDR" 2>/dev/null)
check "created a hybrid key while the wallet was encrypted" \
    "$([ -n "$HYB_ENC_ADDR" ] && [ -n "$HYB_ENC_KEY" ]; echo $?)"
check_eq "the pre-encryption hybrid key is still exportable" \
    "$HYB_BEFORE_KEY" "$(rpc dumphybridkey "$HYB_BEFORE_ADDR" 2>/dev/null)"

lock
check_rpc_fails "wallet locks again: dumpprivkey is refused" \
    dumpprivkey "$ALICE_ADDR"
check_rpc_fails "wallet locks again: signmessage is refused" \
    signmessage "$ALICE_ADDR" "locked"

stop_node || { echo "FAILED: encrypted BDB daemon did not stop"; exit 1; }

BDB_SUM=$(sha256sum "$DATADIR/wallet.dat" | cut -d' ' -f1)
BDB_RECORDS=$(dump_keys "$DATADIR/wallet.dat" db_dump bdb) || BDB_RECORDS=""
[ -n "$BDB_RECORDS" ] && echo "  BDB wallet records: $BDB_RECORDS"

echo "== step 3: migrate wallet.dat to LMDB =="
start_node -walletbackend=lmdb || { echo "FAILED: migration startup failed"; exit 1; }

check_eq "wallet.backend says lmdb" "lmdb" \
    "$(cat "$DATADIR/wallet.backend" 2>/dev/null)"
check "LMDB wallet exists" "$([ -s "$DATADIR/wallet/data.mdb" ]; echo $?)"
check "migration was logged" \
    "$(grep -q 'Migrating wallet from wallet.dat to LMDB' "$DATADIR/debug.log"; echo $?)"
check "migration completion was logged" \
    "$(grep -q 'Wallet migration complete' "$DATADIR/debug.log"; echo $?)"
check_eq "chain is still at height 6 after migration" "6" \
    "$(rpc getblockcount 2>/dev/null)"
check_rpc_fails "LMDB wallet is still encrypted and locked: dumpprivkey is refused" \
    dumpprivkey "$ALICE_ADDR"

stop_node || { echo "FAILED: LMDB daemon did not stop"; exit 1; }

check "wallet.dat is byte-for-byte unchanged" \
    "$([ "$(sha256sum "$DATADIR/wallet.dat" | cut -d' ' -f1)" = "$BDB_SUM" ]; echo $?)"

# Dump the new wallet before unlocking it again: walletpassphrase starts an
# asynchronous keypool top-up, which legitimately adds records after this point.
LMDB_RECORDS=$(dump_keys "$DATADIR/wallet" mdb_dump lmdb-before-restart) || LMDB_RECORDS=""
if [ -n "$BDB_RECORDS" ] && [ -n "$LMDB_RECORDS" ]; then
    echo "  LMDB wallet records: $LMDB_RECORDS"
    check "every BDB record was copied to LMDB" \
        "$([ "$LMDB_RECORDS" = "$BDB_RECORDS" ]; echo $?)"
fi

echo "== step 4: restart on LMDB and verify the migrated state =="
start_node -walletbackend=lmdb || { echo "FAILED: LMDB restart failed"; exit 1; }
check "restart did not run a second migration" \
    "$([ "$(grep -c 'Migrating wallet from wallet.dat to LMDB' "$DATADIR/debug.log")" -eq 1 ]; echo $?)"
check_eq "LMDB restart keeps the chain at height 6" "6" \
    "$(rpc getblockcount 2>/dev/null)"

unlock
key_roundtrip "$ALICE_ADDR" "$ALICE_WIF" "migrated alice key"
key_roundtrip "$BOB_ADDR" "$BOB_WIF" "migrated bob key"
key_roundtrip "$COINBASE5_ADDR" "$COINBASE5_WIF" "migrated block 5 key"
key_roundtrip "$COINBASE6_ADDR" "$COINBASE6_WIF" "migrated block 6 key"
check_contains "alice label survived migration" "$ALICE_ADDR" \
    "$(rpc getaddressesbyaccount alice 2>/dev/null)"
check_contains "bob label survived migration" "$BOB_ADDR" \
    "$(rpc getaddressesbyaccount bob 2>/dev/null)"
check_contains "watch-only label survived migration" "$WATCH_ADDR" \
    "$(rpc getaddressesbyaccount watched-external 2>/dev/null)"
check_contains "watch-only flag survived migration" '"watchonly" : true' \
    "$(rpc validateaddress "$WATCH_ADDR" 2>/dev/null)"
check_contains "multisig label survived migration" "$MULTISIG_ADDR" \
    "$(rpc getaddressesbyaccount multisig 2>/dev/null)"

TX_AFTER=$(rpc listtransactions '*' 30 2>/dev/null)
check_contains "block 5 coinbase survived migration" "$BLOCK5_TXID" "$TX_AFTER"
check_contains "block 6 coinbase survived migration" "$BLOCK6_TXID" "$TX_AFTER"
check_contains "pre-migration transaction survived migration" "$TX_PRE" "$TX_AFTER"
TX_PRE_AFTER=$(rpc gettransaction "$TX_PRE" 2>/dev/null)
check_contains "pre-migration transaction kept its amount" \
    '"amount" : -10.00000000' "$TX_PRE_AFTER"
check_contains "pre-migration transaction is still recorded as a send" \
    '"category" : "send"' "$TX_PRE_AFTER"
check "pre-migration transaction is still hybrid signed" \
    "$(printf '%s\n' "$TX_PRE_AFTER" | grep -q 'Hybrid (ECDSA + ML-DSA-65)'; echo $?)"

check_eq "pre-encryption hybrid key unchanged after migration" \
    "$HYB_BEFORE_KEY" "$(rpc dumphybridkey "$HYB_BEFORE_ADDR" 2>/dev/null)"
check_eq "encrypted hybrid key unchanged after migration" \
    "$HYB_ENC_KEY" "$(rpc dumphybridkey "$HYB_ENC_ADDR" 2>/dev/null)"
check_contains "hybrid address book entry survived migration" \
    '"label" : "hybrid-before"' "$(rpc listhybridaddresses 2>/dev/null)"
check_contains "encrypted hybrid label survived migration" \
    '"label" : "hybrid-encrypted"' "$(rpc listhybridaddresses 2>/dev/null)"

check "message signature still verifies after migration" \
    "$(rpc verifymessage "$SIGN_ADDR" "$SIGNATURE" "wallet migration end-to-end" 2>/dev/null | grep -q true; echo $?)"
check_contains "LMDB restart keeps labels" "$ALICE_ADDR" \
    "$(rpc getaddressesbyaccount alice 2>/dev/null)"
check_eq "LMDB restart keeps the pre-encryption hybrid key" \
    "$HYB_BEFORE_KEY" "$(rpc dumphybridkey "$HYB_BEFORE_ADDR" 2>/dev/null)"
check "LMDB restart keeps message signatures valid" \
    "$(rpc verifymessage "$SIGN_ADDR" "$SIGNATURE" "wallet migration end-to-end" 2>/dev/null | grep -q true; echo $?)"
MIGRATED_KEYPOOL_ADDR=$(rpc getnewaddress keypool-migrated 2>/dev/null)
check "keypool still produces addresses after migration" \
    "$([ -n "$MIGRATED_KEYPOOL_ADDR" ]; echo $?)"

stop_node || { echo "FAILED: LMDB restart daemon did not stop"; exit 1; }

echo "== step 5: use the migrated wallet normally =="
start_node -walletbackend=lmdb || { echo "FAILED: LMDB daemon did not start"; exit 1; }
unlock

CAROL_ADDR=$(rpc getnewaddress carol 2>/dev/null)
CAROL_WIF=$(rpc dumpprivkey "$CAROL_ADDR" 2>/dev/null)
check "created a new address after migration" \
    "$([ -n "$CAROL_ADDR" ] && [ -n "$CAROL_WIF" ]; echo $?)"
check_contains "new address got its label" "$CAROL_ADDR" \
    "$(rpc getaddressesbyaccount carol 2>/dev/null)"

CAROL_SIG=$(rpc signmessage "$CAROL_ADDR" "post-migration wallet use" 2>/dev/null)
check "new address can sign a message" \
    "$(rpc verifymessage "$CAROL_ADDR" "$CAROL_SIG" "post-migration wallet use" 2>/dev/null | grep -q true; echo $?)"

HYB_AFTER_ADDR=$(rpc gethybridaddress "hybrid-after" 2>/dev/null)
HYB_AFTER_KEY=$(rpc dumphybridkey "$HYB_AFTER_ADDR" 2>/dev/null)
check "created a new hybrid key after migration" \
    "$([ -n "$HYB_AFTER_ADDR" ] && [ -n "$HYB_AFTER_KEY" ]; echo $?)"
check_contains "new hybrid key has its label" '"label" : "hybrid-after"' \
    "$(rpc listhybridaddresses 2>/dev/null)"

rpc keypoolrefill 60 >/dev/null 2>&1
check "keypool refills on the migrated wallet" \
    "$([ -n "$(rpc getnewaddress keypool-after 2>/dev/null)" ]; echo $?)"

# A brand new signed transaction, funded by the still-unspent block 6 coinbase.
TX_POST=$(rpc sendtoaddress "$EXTERNAL_ADDR" 7 "e2e post-migration send" "e2e" 2>/dev/null)
check "created a new transaction on the migrated wallet" \
    "$([ -n "$TX_POST" ]; echo $?)"
check "new transaction reached the mempool" \
    "$(wait_for_tx_in_mempool "$TX_POST"; echo $?)"
TX_POST_JSON=$(rpc listtransactions '*' 40 2>/dev/null)
check_contains "new transaction is in the wallet history" "$TX_POST" "$TX_POST_JSON"
TX_POST_DETAIL=$(rpc gettransaction "$TX_POST" 2>/dev/null)
check_contains "new transaction is recorded as a send" '"category" : "send"' \
    "$TX_POST_DETAIL"
check_contains "new transaction paid the external address" "$EXTERNAL_ADDR" \
    "$TX_POST_DETAIL"
check_contains "new transaction is a send of 7 PXC" '"amount" : -7.00000000' \
    "$TX_POST_DETAIL"
check "new transaction is hybrid signed" \
    "$(printf '%s\n' "$TX_POST_DETAIL" | grep -q 'Hybrid (ECDSA + ML-DSA-65)'; echo $?)"

lock
check_rpc_fails "migrated wallet locks: dumpprivkey is refused" \
    dumpprivkey "$CAROL_ADDR"
unlock
check "migrated wallet unlocks again" \
    "$([ "$(rpc dumpprivkey "$CAROL_ADDR" 2>/dev/null)" = "$CAROL_WIF" ]; echo $?)"

stop_node || { echo "FAILED: post-migration daemon did not stop"; exit 1; }

echo "== step 6: restart LMDB once more and verify the new state =="
start_node -walletbackend=lmdb || { echo "FAILED: final LMDB restart failed"; exit 1; }
check "no extra migration ran on the final restart" \
    "$([ "$(grep -c 'Migrating wallet from wallet.dat to LMDB' "$DATADIR/debug.log")" -eq 1 ]; echo $?)"
check_eq "final restart keeps the chain at height 6" "6" \
    "$(rpc getblockcount 2>/dev/null)"

unlock
key_roundtrip "$CAROL_ADDR" "$CAROL_WIF" "post-migration address after restart"
key_roundtrip "$ALICE_ADDR" "$ALICE_WIF" "migrated alice key after final restart"
check_contains "post-migration label survived the restart" "$CAROL_ADDR" \
    "$(rpc getaddressesbyaccount carol 2>/dev/null)"
check_contains "post-migration transaction survived the restart" "$TX_POST" \
    "$(rpc listtransactions '*' 40 2>/dev/null)"
check_contains "post-migration transaction kept its amount" \
    '"amount" : -7.00000000' "$(rpc gettransaction "$TX_POST" 2>/dev/null)"
check_eq "post-migration hybrid key survived the restart" \
    "$HYB_AFTER_KEY" "$(rpc dumphybridkey "$HYB_AFTER_ADDR" 2>/dev/null)"
check_contains "both pre- and post-migration transactions are present" "$TX_PRE" \
    "$(rpc listtransactions '*' 40 2>/dev/null)"

stop_node || { echo "FAILED: final LMDB daemon did not stop"; exit 1; }

check "wallet.dat stayed byte-for-byte unchanged through all LMDB use" \
    "$([ "$(sha256sum "$DATADIR/wallet.dat" | cut -d' ' -f1)" = "$BDB_SUM" ]; echo $?)"
check "LMDB wallet marker is still lmdb" \
    "$([ "$(cat "$DATADIR/wallet.backend" 2>/dev/null)" = "lmdb" ]; echo $?)"

echo
echo "== summary =="
echo "  passed: $PASS"
echo "  failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
