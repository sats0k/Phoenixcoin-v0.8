#!/bin/bash
#
# Regression test: online LMDB wallet backup, offline verification and restore.
#
# The workflow exercised here is the one an operator is expected to follow:
#
#   running node
#       -> backupwallet <new path>            (staged, verified, atomic)
#       -> -checklmdb <backup> [-checklmdbdeep]
#       -> checklmdb <backup> [full]          (while the node is running)
#       -> backupwallet <existing directory>  (copy goes to <dir>/wallet)
#       -> refusal of a non-empty destination
#       -> rejection of truncated/corrupt/empty environments
#       -> fail-closed startup on an incomplete live wallet
#       -> point-in-time restore from the backup
#       -> key and address-book round trips after restore
#
# The script also checks that offline verification does not modify the backup
# (no lock.mdb is created and data.mdb keeps its checksum).
#
# Usage: src/test/regression_lmdb_wallet_backup.sh [path-to-phoenixcoind]
#
# The RPC port is chosen from the ephemeral range and can be pinned with
# PXC_REGTEST_PORT for debugging or constrained environments.

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
DATADIR="$(mktemp -d "/tmp/lmdb-backup.XXXXXX")"

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

rpc() {
    timeout 20 "$BIN" -datadir="$DATADIR" -rpcuser=reguser -rpcpassword=regpass \
        -rpcport="$PORT" "$@"
}

wait_ready() {
    local i
    for i in $(seq 1 60); do
        if timeout 5 "$BIN" -datadir="$DATADIR" -rpcuser=reguser \
                -rpcpassword=regpass -rpcport="$PORT" getblockcount \
                >/dev/null 2>&1; then
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
    write_config "$DATADIR" "$PORT"
    "$BIN" -datadir="$DATADIR" "$@" -daemon >/dev/null 2>&1
    wait_ready
}

stop_node() {
    rpc stop >/dev/null 2>&1
    wait_down
}

cleanup() {
    # Only ask a live daemon to stop.  The RPC client blocks for minutes when
    # nothing is listening in this codebase.
    if pgrep -f "phoenixcoind -datadir=$DATADIR" >/dev/null 2>&1; then
        rpc stop >/dev/null 2>&1
        wait_down >/dev/null 2>&1
    fi
    rm -rf "$DATADIR"
}
trap cleanup EXIT

key_roundtrip() {
    local addr="$1" want_wif="$2" label="$3"
    check "$label: validateaddress reports the address as owned" \
        "$(rpc validateaddress "$addr" 2>/dev/null | grep -q '"ismine" : true'; echo $?)"
    check "$label: private key is unchanged" \
        "$([ "$(rpc dumpprivkey "$addr" 2>/dev/null)" = "$want_wif" ]; echo $?)"
}

# Run the standalone offline check.  The caller inspects the output file.
run_checklmdb() {
    local path="$1" deep="$2" out="$3"
    if [ "$deep" = "yes" ]; then
        timeout 60 "$BIN" -checklmdb="$path" -checklmdbdeep >"$out" 2>&1
    else
        timeout 60 "$BIN" -checklmdb="$path" >"$out" 2>&1
    fi
}

json_checklmdb_ok() {
    python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["ok"] is True, d
assert d["complete"] is True, d
assert d["main_database"] is True, d
assert d["records_readable"] is True, d
assert d["entries"] > 0, d
assert d["full_scan"] is True, d
assert d["page_size"] > 0, d
'
}

json_checklmdb_failed() {
    python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["ok"] is False, d
assert d["complete"] is False, d
assert d["error"] != "", d
'
}

json_live_refused() {
    python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["ok"] is False, d
assert "open" in d["error"], d
'
}

json_dbinfo_complete() {
    python3 -c '
import json, sys
d = json.load(sys.stdin)
w = d["wallet"]
assert w["active_backend"] == "lmdb", w
f = w["data_file"]
assert f["directory_exists"] is True, f
assert f["present"] is True, f
assert f["bytes"] > 0, f
assert f["complete"] is True, f
assert f["reason"] == "", f
assert w["opened_cleanly"] is True, w
'
}

echo "== step 1: create an LMDB wallet with a known address =="
start_node || {
    echo "FAILED: could not start the LMDB daemon"; exit 1;
}

check "no legacy backend marker is created" \
    "$([ ! -e "$DATADIR/wallet.backend" ]; echo $?)"
check "LMDB wallet exists" \
    "$([ -s "$DATADIR/wallet/data.mdb" ]; echo $?)"

ADDR=$(rpc getnewaddress alice 2>/dev/null)
WIF=$(rpc dumpprivkey "$ADDR" 2>/dev/null)
check "generated an address and private key" \
    "$([ -n "$ADDR" ] && [ -n "$WIF" ]; echo $?)"
key_roundtrip "$ADDR" "$WIF" "live wallet"

DBINFO=$(rpc getdbinfo 2>/dev/null)
check "getdbinfo reports a complete LMDB data file" \
    "$(printf '%s' "$DBINFO" | json_dbinfo_complete 2>/dev/null; echo $?)"

echo "== step 2: online backupwallet to a new path =="
BACKUP="$DATADIR/backup"
rpc backupwallet "$BACKUP" >/dev/null 2>&1
check "backupwallet succeeded" "$([ $? -eq 0 ]; echo $?)"
check "backup is an LMDB environment" \
    "$([ -s "$BACKUP/data.mdb" ]; echo $?)"
check "compacted backup has no lock.mdb" \
    "$([ ! -e "$BACKUP/lock.mdb" ]; echo $?)"

BACKUP_SUM_BEFORE=$(sha256sum "$BACKUP/data.mdb" | cut -d' ' -f1)
BACKUP_OUT="$DATADIR/check-backup.out"
run_checklmdb "$BACKUP" yes "$BACKUP_OUT"
check "-checklmdbdeep accepts the backup" \
    "$([ $? -eq 0 ]; echo $?)"
check "-checklmdbdeep reports OK" \
    "$(grep -q 'result: OK' "$BACKUP_OUT"; echo $?)"
check "-checklmdbdeep read every record" \
    "$(grep -q 'full scan: yes' "$BACKUP_OUT"; echo $?)"
check "-checklmdb did not create lock.mdb" \
    "$([ ! -e "$BACKUP/lock.mdb" ]; echo $?)"
check "-checklmdb did not modify data.mdb" \
    "$([ "$(sha256sum "$BACKUP/data.mdb" | cut -d' ' -f1)" = "$BACKUP_SUM_BEFORE" ]; echo $?)"

RPC_CHECK=$(rpc checklmdb "$BACKUP" true 2>/dev/null)
check "checklmdb RPC accepts the backup" \
    "$(printf '%s' "$RPC_CHECK" | json_checklmdb_ok 2>/dev/null; echo $?)"

RPC_LIVE=$(rpc checklmdb "$DATADIR" true 2>/dev/null)
check "checklmdb RPC refuses the live wallet" \
    "$(printf '%s' "$RPC_LIVE" | json_live_refused 2>/dev/null; echo $?)"

echo "== step 3: existing-directory backups and destination refusals =="
ROOT_BACKUP="$DATADIR/backup-root"
mkdir -p "$ROOT_BACKUP"
rpc backupwallet "$ROOT_BACKUP" >/dev/null 2>&1
check "an existing directory receives <dir>/wallet" \
    "$([ -s "$ROOT_BACKUP/wallet/data.mdb" ]; echo $?)"
ROOT_OUT="$DATADIR/check-root.out"
run_checklmdb "$ROOT_BACKUP" yes "$ROOT_OUT"
check "-checklmdb auto-descends into wallet/" \
    "$([ $? -eq 0 ] && grep -q "$ROOT_BACKUP/wallet" "$ROOT_OUT"; echo $?)"
RPC_ROOT=$(rpc checklmdb "$ROOT_BACKUP" true 2>/dev/null)
check "checklmdb RPC auto-descends into wallet/" \
    "$(printf '%s' "$RPC_ROOT" | json_checklmdb_ok 2>/dev/null; echo $?)"

REFUSE="$DATADIR/refuse"
mkdir -p "$REFUSE/wallet"
printf 'keep\n' > "$REFUSE/wallet/keep"
if rpc backupwallet "$REFUSE" >/dev/null 2>&1; then
    check "backupwallet refuses a non-empty wallet/ target" 1
else
    check "backupwallet refuses a non-empty wallet/ target" 0
fi
check "refused backup left the target untouched" \
    "$([ "$(cat "$REFUSE/wallet/keep")" = "keep" ]; echo $?)"
check "refused backup left no staging directory" \
    "$(find "$REFUSE" -maxdepth 1 -name 'wallet.tmp-*' | grep -q .; [ $? -ne 0 ]; echo $?)"

NOT_A_DIR="$DATADIR/not-a-backup"
printf 'keep\n' > "$NOT_A_DIR"
if rpc backupwallet "$NOT_A_DIR" >/dev/null 2>&1; then
    check "backupwallet refuses a regular file destination" 1
else
    check "backupwallet refuses a regular file destination" 0
fi
check "regular file destination is untouched" \
    "$([ "$(cat "$NOT_A_DIR")" = "keep" ]; echo $?)"

echo "== step 4: address created after the backup =="
POST_ADDR=$(rpc getnewaddress postbackup 2>/dev/null)
POST_WIF=$(rpc dumpprivkey "$POST_ADDR" 2>/dev/null)
check "created an address after the backup" \
    "$([ -n "$POST_ADDR" ] && [ -n "$POST_WIF" ]; echo $?)"
key_roundtrip "$POST_ADDR" "$POST_WIF" "post-backup address before restore"

echo "== step 5: reject truncated, corrupt and empty environments =="
TRUNC="$DATADIR/bad-trunc"
cp -a "$BACKUP" "$TRUNC"
PAGE_SIZE=$(getconf PAGESIZE 2>/dev/null || echo 4096)
truncate -s "$((PAGE_SIZE * 2))" "$TRUNC/data.mdb"
TRUNC_OUT="$DATADIR/check-trunc.out"
run_checklmdb "$TRUNC" yes "$TRUNC_OUT"
check "-checklmdb rejects a truncated data.mdb" \
    "$([ $? -ne 0 ]; echo $?)"
check "-checklmdb explains the truncation" \
    "$(grep -Eqi 'truncated|cannot open data.mdb' "$TRUNC_OUT"; echo $?)"
RPC_TRUNC=$(rpc checklmdb "$TRUNC" true 2>/dev/null)
check "checklmdb RPC rejects a truncated data.mdb" \
    "$(printf '%s' "$RPC_TRUNC" | json_checklmdb_failed 2>/dev/null; echo $?)"

CORRUPT="$DATADIR/bad-corrupt"
cp -a "$BACKUP" "$CORRUPT"
dd if=/dev/zero of="$CORRUPT/data.mdb" bs=4096 count=2 conv=notrunc status=none
CORRUPT_OUT="$DATADIR/check-corrupt.out"
run_checklmdb "$CORRUPT" no "$CORRUPT_OUT"
check "-checklmdb rejects zeroed meta pages" \
    "$([ $? -ne 0 ]; echo $?)"
RPC_CORRUPT=$(rpc checklmdb "$CORRUPT" true 2>/dev/null)
check "checklmdb RPC rejects zeroed meta pages" \
    "$(printf '%s' "$RPC_CORRUPT" | json_checklmdb_failed 2>/dev/null; echo $?)"

EMPTY="$DATADIR/bad-empty"
mkdir -p "$EMPTY"
EMPTY_OUT="$DATADIR/check-empty.out"
run_checklmdb "$EMPTY" no "$EMPTY_OUT"
check "-checklmdb rejects an empty directory" \
    "$([ $? -ne 0 ]; echo $?)"
check "-checklmdb names the missing data.mdb" \
    "$(grep -q 'data.mdb is missing' "$EMPTY_OUT"; echo $?)"
RPC_EMPTY=$(rpc checklmdb "$EMPTY" false 2>/dev/null)
check "checklmdb RPC rejects an empty directory" \
    "$(printf '%s' "$RPC_EMPTY" | json_checklmdb_failed 2>/dev/null; echo $?)"

echo "== step 6: startup fails closed on an incomplete live wallet =="
stop_node || { echo "FAILED: daemon did not stop"; exit 1; }

mv "$DATADIR/wallet" "$DATADIR/wallet.good"
cp -a "$DATADIR/wallet.good" "$DATADIR/wallet"
truncate -s 4096 "$DATADIR/wallet/data.mdb"
REFUSE_LOG="$DATADIR/incomplete-start.log"
timeout 30 "$BIN" -datadir="$DATADIR" \
    >"$REFUSE_LOG" 2>&1
check "startup with a truncated wallet fails" \
    "$([ $? -ne 0 ]; echo $?)"
check "startup error names the incomplete wallet" \
    "$(grep -q 'LMDB wallet.*is incomplete' "$REFUSE_LOG" "$DATADIR/debug.log" 2>/dev/null; echo $?)"
check "failed startup did not create a marker" \
    "$([ ! -e "$DATADIR/wallet.backend" ]; echo $?)"

rm -rf "$DATADIR/wallet"
mv "$DATADIR/wallet.good" "$DATADIR/wallet"
start_node || {
    echo "FAILED: the restored live wallet did not start"; exit 1;
}
key_roundtrip "$ADDR" "$WIF" "live wallet after failed start recovery"
key_roundtrip "$POST_ADDR" "$POST_WIF" "post-backup address before restore"
stop_node || { echo "FAILED: daemon did not stop"; exit 1; }

echo "== step 7: restore the point-in-time backup =="
mv "$DATADIR/wallet" "$DATADIR/wallet.live"
cp -a "$BACKUP" "$DATADIR/wallet"
start_node || {
    echo "FAILED: restored wallet did not start"; exit 1;
}

key_roundtrip "$ADDR" "$WIF" "restored snapshot"
check "address book survived the restore" \
    "$(rpc getaddressesbyaccount alice 2>/dev/null | grep -qF "$ADDR"; echo $?)"
# Keys are drawn from the pre-generated keypool, so a key created after the
# backup may legitimately exist in the snapshot.  The address-book entry is a
# committed wallet record and must not: this is the point-in-time check.
check "post-backup address book entry is gone after restore" \
    "$(if rpc getaddressesbyaccount postbackup 2>/dev/null | grep -qF "$POST_ADDR"; then echo 1; else echo 0; fi)"
check "post-backup account is gone after restore" \
    "$([ -z "$(rpc getaccount "$POST_ADDR" 2>/dev/null)" ]; echo $?)"

NEW_ADDR=$(rpc getnewaddress afterrestore 2>/dev/null)
NEW_WIF=$(rpc dumpprivkey "$NEW_ADDR" 2>/dev/null)
check "restored wallet accepts a new address" \
    "$([ -n "$NEW_ADDR" ] && [ -n "$NEW_WIF" ]; echo $?)"
stop_node || { echo "FAILED: restored daemon did not stop"; exit 1; }

start_node || {
    echo "FAILED: restored daemon did not restart"; exit 1;
}
key_roundtrip "$NEW_ADDR" "$NEW_WIF" "new address after restore restart"
key_roundtrip "$ADDR" "$WIF" "restored address after restart"
stop_node || { echo "FAILED: restored daemon did not stop"; exit 1; }

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
