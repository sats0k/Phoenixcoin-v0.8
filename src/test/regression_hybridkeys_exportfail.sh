#!/bin/bash
#
# Regression test: dumphybridkeys must NOT silently produce an incomplete
# backup. If any single hybrid key cannot be serialized, the whole export must
# fail: the RPC errors out, no (partial) backup file is left behind, and a
# retry succeeds once the transient problem is gone.
#
# The failure is provoked with the test-only environment variable
# PHOENIX_TEST_FAIL_HYBRID_EXPORT set to the hex id of one imported hybrid key;
# the first serialization attempt of that key then throws (test-only hook in
# EncodeHybridPrivKey, rpchybrid.cpp), which is exactly the per-key failure
# that DumpHybridKeys has to turn into an overall export failure.
#
# Steps:
#   1. Node A creates a hybrid pool + labels, exports a backup file.
#   2. Node B imports that file, so it owns keys it must later re-export.
#   3. B is restarted with the failure injection armed for ONE of the imported
#      keys; B's export of its own + imported keys must FAIL and leave no file.
#   4. B is restarted clean; the identical export now succeeds and contains
#      every key that A exported (plus B's own pool keys).
#   5. Re-exporting to an existing file is refused by the shared helper (the
#      RPC used to pre-check this itself; it now lives in DumpHybridKeys so the
#      Qt GUI gets the same guarantee) and the existing file stays untouched.
#
# Usage: src/test/regression_hybridkeys_exportfail.sh [path-to-phoenixcoind]

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
# Resolve to an absolute path: a bare name like "phoenixcoind" would otherwise
# be looked up in $PATH (not the current directory) and fail to execute.
case "$BIN" in
    */*) BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")" ;;
    *)   BIN="$(pwd)/$BIN" ;;
esac
DATADIR_A="$(mktemp -d "/tmp/hyexport-A.XXXXXX")"
DATADIR_B="$(mktemp -d "/tmp/hyexport-B.XXXXXX")"
PORT_A=9683
PORT_B=9684
ARMED_DIR="$(mktemp -d "/tmp/hyexport-armed.XXXXXX")"

PASS=0
FAIL=0

cleanup() {
    "$BIN" -datadir="$DATADIR_A" stop >/dev/null 2>&1
    "$BIN" -datadir="$DATADIR_B" stop >/dev/null 2>&1
    wait_down "$DATADIR_A"
    wait_down "$DATADIR_B"
    rm -rf "$DATADIR_A" "$DATADIR_B" "$ARMED_DIR"
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

# Run an RPC call and expect it to FAIL (reader: non-zero exit).
rpc_expect_fail() {
    local dir="$1" port="$2" method="$3"; shift 3
    local out
    out=$("$BIN" -datadir="$dir" -rpcuser=reguser -rpcpassword=regpass \
                -rpcport="$port" "$method" "$@" 2>&1)
    [ $? -ne 0 ]
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
    echo "  procs:"; pgrep -af "phoenixcoind" || true
    echo "  debug.log tail:"; tail -8 "$dir/debug.log" 2>/dev/null || true
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

# Starts the daemon; when env_extra is non-empty it is exported to the daemon
# process (used to arm the test-only hybrid export failure injection).
start_node() {
    local dir="$1" port="$2" env_extra="${3:-}"
    cat > "$dir/phoenixcoin.conf" <<EOF2
server=1
listen=0
maxconnections=0
rpcport=$port
rpcuser=reguser
rpcpassword=regpass
EOF2
    if [ -n "$env_extra" ]; then
        env "$env_extra" "$BIN" -datadir="$dir" -daemon >/dev/null 2>&1
    else
        "$BIN" -datadir="$dir" -daemon >/dev/null 2>&1
    fi
    wait_ready "$dir" "$port"
}

# Extract data-key lines from a hybrid dump file (''#'/header lines skipped).
data_lines() {
    grep -v '^#' "$1" | grep -v '^$'
}

# Every data line of file $1 must appear (verbatim) in file $2.
all_a_lines_present_in_b() {
    local f1="$1" f2="$2" n1 n2
    n1=$(data_lines "$f1" | wc -l)
    n2=$(data_lines "$f2" | wc -l)
    [ "$n2" -ge "$n1" ] && [ "$(comm -23 <(data_lines "$f1" | sort -u) \
         <(data_lines "$f2" | sort -u) | wc -l)" = "0" ]
}

# Extract the 20-byte hybrid key id (hex) from a base58check hybrid address.
# Payload = version(0x3A) || id(20) || checksum(4); leading zero bytes are
# encoded as initial '1' characters.
hybrid_id_hex() {
    python3 - "$1" <<'PY'
import sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + raw

raw = b58decode(sys.argv[1])
payload = raw[:len(raw) - 4]
print(payload[1:21][::-1].hex())
PY
}

echo "== step 1: exporter A creates hybrid keys and exports a backup =="
start_node "$DATADIR_A" "$PORT_A" || { cleanup; echo "FAILED setup A"; exit 1; }
H1=$(rpc "$DATADIR_A" "$PORT_A" gethybridaddress "alice")
H2=$(rpc "$DATADIR_A" "$PORT_A" gethybridaddress "alice2")
echo "   hybrid addresses: $H1 $H2"
rpc "$DATADIR_A" "$PORT_A" dumphybridkeys dump_a.txt >/dev/null
check "A export succeeds" "$([ -s "$DATADIR_A/dump_a.txt" ]; echo $?)"
N_A=$(data_lines "$DATADIR_A/dump_a.txt" | wc -l)
echo "   A exported $N_A hybrid keys"
check "A exported its whole key pool (>= 20 keys)" "$([ "$N_A" -ge 20 ]; echo $?)"

echo "== step 2: importer B imports A's backup =="
start_node "$DATADIR_B" "$PORT_B" || { cleanup; echo "FAILED setup B"; exit 1; }
rpc "$DATADIR_B" "$PORT_B" importhybridkeys "$DATADIR_A/dump_a.txt" >/dev/null
check "B imports A's backup" "$([ $? -eq 0 ]; echo $?)"
IDHEX=$(hybrid_id_hex "$H1")
echo "   injection target (key id of $H1): $IDHEX"

echo "== step 3: B with armed failure injection -- export MUST fail =="
"$BIN" -datadir="$DATADIR_B" stop >/dev/null 2>&1
wait_down "$DATADIR_B" || { cleanup; echo "FAILED shutdown B"; exit 1; }
cp -a "$DATADIR_B" "$ARMED_DIR/wallet-backup"
rm -rf "$DATADIR_B"
cp -a "$ARMED_DIR/wallet-backup" "$DATADIR_B"
start_node "$DATADIR_B" "$PORT_B" "PHOENIX_TEST_FAIL_HYBRID_EXPORT=$IDHEX" \
    || { cleanup; echo "FAILED armed start B"; exit 1; }

OUT=$(rpc "$DATADIR_B" "$PORT_B" dumphybridkeys dump_b.txt 2>&1)
OK_FAIL=$([ $? -ne 0 ]; echo $?)
check "armed export errors out (non-zero exit)" "$OK_FAIL"
check "armed export reports skipped/unserializable keys" \
    "$(echo "$OUT" | grep -q "could not be serialized"; echo $?)"
check "armed export leaves NO backup file behind" \
    "$([ ! -e "$DATADIR_B/dump_b.txt" ]; echo $?)"

echo "== step 4: clean restart of B -- identical export must succeed =="
"$BIN" -datadir="$DATADIR_B" stop >/dev/null 2>&1
wait_down "$DATADIR_B" || { cleanup; echo "FAILED shutdown B"; exit 1; }
start_node "$DATADIR_B" "$PORT_B" || { cleanup; echo "FAILED restart B"; exit 1; }

rpc "$DATADIR_B" "$PORT_B" dumphybridkeys dump_c.txt >/dev/null
check "clean export succeeds" "$([ -s "$DATADIR_B/dump_c.txt" ]; echo $?)"
N_B=$(data_lines "$DATADIR_B/dump_c.txt" | wc -l)
echo "   B exported $N_B hybrid keys (its pool + A's imported keys)"
check "clean export contains all of A's exported keys" \
    "$(all_a_lines_present_in_b "$DATADIR_A/dump_a.txt" "$DATADIR_B/dump_c.txt"; echo $?)"
GONE=$(comm -23 <(data_lines "$DATADIR_A/dump_a.txt" | sort -u) \
       <(data_lines "$DATADIR_B/dump_c.txt" | sort -u) | wc -l)
check "clean export is missing ZERO of A's keys" "$([ "$GONE" = "0" ]; echo $?)"

echo "== step 5: overwrite protection lives in the shared helper =="
OUT=$(rpc "$DATADIR_B" "$PORT_B" dumphybridkeys dump_c.txt 2>&1)
check "re-export to an existing file is refused" "$([ $? -ne 0 ]; echo $?)"
check "refusal reports the existing file" \
    "$(echo "$OUT" | grep -q "exists already"; echo $?)"
check "existing backup file is left untouched" \
    "$([ "$(data_lines "$DATADIR_B/dump_c.txt" | wc -l)" = "$N_B" ]; echo $?)"
check "no leftover temp file next to the export" \
    "$([ ! -e "$DATADIR_B/dump_c.txt.tmp" ]; echo $?)"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]