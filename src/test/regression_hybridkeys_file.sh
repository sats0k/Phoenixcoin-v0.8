#!/bin/bash
#
# Regression test: bulk hybrid key export/import via a dump file.
#
# Exercises the two new RPCs:
#   dumphybridkeys  <file>  -- exports EVERY hybrid private key to a file
#   importhybridkeys <file>  -- imports hybrid keys from such a file
#
# Checks:
#   1. dumphybridkeys refuses to overwrite an existing file.
#   2. The dump contains one key line per hybrid address (comments ignored).
#   3. importhybridkeys on a fresh wallet restores every key: the address,
#      the private material (dumphybridkey matches the exporter exactly),
#      the address-book labels, and hybrid message signing.
#   4. Re-export on the importer contains every one of the exporter's key
#      lines. The importer keeps its own freshly-generated keypool, so its
#      dump may legitimately contain extra key lines.
#   5. After a full daemon restart all of the above still holds (persistence
#      of the ECDSA half as a real wallet key plus the hybrid records).
#
# Usage: src/test/regression_hybridkeys_file.sh [path-to-phoenixcoind]

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
DATADIR_A="$(mktemp -d "/tmp/hybridkeys-A.XXXXXX")"
DATADIR_B="$(mktemp -d "/tmp/hybridkeys-B.XXXXXX")"
PORT_A=9691
PORT_B=9692
EXPORT_A="$DATADIR_A/hybridkeys.txt"
EXPORT_B="$DATADIR_B/hybridkeys.txt"
MSG="bulk hybrid keys regression message"

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

rpc_expect_fail() {
    local dir="$1" port="$2" method="$3"; shift 3
    local out
    out=$("$BIN" -datadir="$dir" -rpcuser=reguser -rpcpassword=regpass \
                -rpcport="$port" "$method" "$@" 2>&1)
    [ $? -ne 0 ]
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

# Private material + label of each key line of a dumphybridkeys file,
# sorted. The reserve=/change= marker is intentionally excluded: like the
# classic dumpwallet/importwallet pair, import does not re-assert keypool
# membership, so a restored key may re-export as change=1.
privlines() {
    awk '{ sec=$1; der=$2; tim=$3; lab="-";
           for (i=4; i<=NF; i++) { if ($i ~ /^label=/) { lab=$i; break } }
           print sec, der, tim, lab }' "$1" | sort
}

# Every line of export A must reappear in export B. B starts its own fresh
# hybrid keypool (EnsureHybridKeyPool on wallet load) and keeps it after
# import, so its dump can contain extra reserve keys.
all_a_lines_present_in_b() {
    [ -z "$(comm -23 <(privlines "$1") <(privlines "$2"))" ]
}

echo "== step 1: exporter A creates three labelled hybrid addresses =="
start_node "$DATADIR_A" "$PORT_A" || { cleanup; echo "FAILED setup A"; exit 1; }
H1=$(rpc "$DATADIR_A" "$PORT_A" gethybridaddress "one")
H2=$(rpc "$DATADIR_A" "$PORT_A" gethybridaddress "two")
H3=$(rpc "$DATADIR_A" "$PORT_A" gethybridaddress "three")
echo "   addresses: $H1"
echo "             $H2"
echo "             $H3"

echo "== step 2: dumphybridkeys writes the file =="
rpc "$DATADIR_A" "$PORT_A" dumphybridkeys "$EXPORT_A" >/dev/null
check "dump file exists" "$([ -s "$EXPORT_A" ]; echo $?)"
NLINES_A=$(grep -vcE '^[[:space:]]*$|^#' "$EXPORT_A")
check "every key got exported (>= 3 address keys, got $NLINES_A)" "$([ "$NLINES_A" -ge 3 ]; echo $?)"
check "dump file mentions the hybrid addresses" \
    "$(grep -qE "$H1|$H2|$H3" "$EXPORT_A"; echo $?)"

echo "== step 3: existing file is refused =="
check "dumphybridkeys refuses to overwrite" \
    "$(rpc_expect_fail "$DATADIR_A" "$PORT_A" dumphybridkeys "$EXPORT_A"; echo $?)"

echo "== step 4: fresh wallet B imports the whole file =="
start_node "$DATADIR_B" "$PORT_B" || { cleanup; echo "FAILED setup B"; exit 1; }
rpc "$DATADIR_B" "$PORT_B" importhybridkeys "$EXPORT_A" >/dev/null

for H in "$H1" "$H2" "$H3"; do
    check "B owns $H (ismine=true)" \
        "$([ "$(rpc "$DATADIR_B" "$PORT_B" validateaddress "$H" | python3 -c "import sys,json;print(json.load(sys.stdin)['ismine'])")" = "True" ]; echo $?)"
    D_A=$(rpc "$DATADIR_A" "$PORT_A" dumphybridkey "$H")
    D_B=$(rpc "$DATADIR_B" "$PORT_B" dumphybridkey "$H")
    check "B's private key for $H matches A (WIF + DER)" "$([ "$D_A" = "$D_B" ]; echo $?)"
done

for LAB in one two three; do
    check "B has label '$LAB' in the hybrid address book" \
        "$(rpc "$DATADIR_B" "$PORT_B" listhybridaddresses | grep -qE "\"label\"\s*:\s*\"$LAB\""; echo $?)"
done

echo "== step 5: hybrid signing on B (per imported key) =="
SIG=$(rpc "$DATADIR_B" "$PORT_B" signmessage "$H1" "$MSG")
check "signmessage on imported key" "$([ -n "$SIG" ]; echo $?)"
check "verifymessage on B" \
    "$([ "$(rpc "$DATADIR_B" "$PORT_B" verifymessage "$H1" "$SIG" "$MSG")" = "true" ]; echo $?)"
check "verifymessage on A (cross-node)" \
    "$([ "$(rpc "$DATADIR_A" "$PORT_A" verifymessage "$H1" "$SIG" "$MSG")" = "true" ]; echo $?)"

echo "== step 6: re-export from B contains every one of A's key lines =="
rpc "$DATADIR_B" "$PORT_B" dumphybridkeys "$EXPORT_B" >/dev/null
NLINES_B=$(grep -vcE '^[[:space:]]*$|^#' "$EXPORT_B")
check "B export contains each of A's $NLINES_A key lines (B has $NLINES_B)" \
    "$([ "$NLINES_B" -ge "$NLINES_A" ]; echo $?)"
check "B export has all of A's keys (WIF + DER + time + label)" \
    "$(all_a_lines_present_in_b "$EXPORT_A" "$EXPORT_B"; echo $?)"

echo "== step 7: restart B, everything must persist =="
"$BIN" -datadir="$DATADIR_B" stop >/dev/null 2>&1
wait_down "$DATADIR_B" || { cleanup; echo "FAILED shutdown B"; exit 1; }
start_node "$DATADIR_B" "$PORT_B" || { cleanup; echo "FAILED restart B"; exit 1; }

for H in "$H1" "$H2" "$H3"; do
    D_A=$(rpc "$DATADIR_A" "$PORT_A" dumphybridkey "$H")
    D_B=$(rpc "$DATADIR_B" "$PORT_B" dumphybridkey "$H")
    check "after restart: B private key for $H still matches A" "$([ "$D_A" = "$D_B" ]; echo $?)"
done
for LAB in one two three; do
    check "after restart: label '$LAB' still present" \
        "$(rpc "$DATADIR_B" "$PORT_B" listhybridaddresses | grep -qE "\"label\"\s*:\s*\"$LAB\""; echo $?)"
done
rm -f "$EXPORT_B"
rpc "$DATADIR_B" "$PORT_B" dumphybridkeys "$EXPORT_B" >/dev/null
check "after restart: re-export still contains all of A's keys" \
    "$(all_a_lines_present_in_b "$EXPORT_A" "$EXPORT_B"; echo $?)"
SIG2=$(rpc "$DATADIR_B" "$PORT_B" signmessage "$H1" "$MSG")
check "after restart: hybrid still signs" "$([ -n "$SIG2" ]; echo $?)"
check "after restart: signature verifies on A" \
    "$([ "$(rpc "$DATADIR_A" "$PORT_A" verifymessage "$H1" "$SIG2" "$MSG")" = "true" ]; echo $?)"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]