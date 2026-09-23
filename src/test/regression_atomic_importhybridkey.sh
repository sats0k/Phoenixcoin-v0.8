#!/bin/bash
#
# Regression test: importhybridkey is atomic in the presence of a mid-
# transaction database failure.
#
# importhybridkey persists three things in ONE CWalletDB transaction:
#   - the ECDSA half as a normal wallet key ("key"/"ckey" record),
#   - the combined hybrid key ("hyb" record),
#   - the address book label ("hybaddr" record).
# If any of those writes fails, the whole transaction must be aborted so a
# crash mid-import leaves no residue behind.
#
# To exercise that path, the daemon under test is started with the test-only
# environment variable PHOENIX_TEST_FAIL_HYBRID_WRITE set to the hex id of the
# key being imported; CWalletDB::WriteHybridKey then fails the FIRST matching
# write (one-shot, see walletdb_hybrid.cpp). The expected behaviour:
#   - the import RPC errors with "Error persisting hybrid key",
#   - no hybrid key, no ECDSA key and no label are registered in memory,
#   - nothing is left in the database (verified after a clean restart),
#   - retrying the identical import succeeds and persists.
#
# Note: the legacy P2PKH address is derived from the exported WIF with pure
# Python secp256k1 (Phoenixcoin P2PKH version 0x38, WIF 0xB8, compressed).
#
# Usage: src/test/regression_atomic_importhybridkey.sh [path-to-phoenixcoind]

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
DATADIR_A="$(mktemp -d "/tmp/atomic-import-A.XXXXXX")"
DATADIR_B="$(mktemp -d "/tmp/atomic-import-B.XXXXXX")"
PORT_A=9681
PORT_B=9682
MSG="atomic import live test"

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

# Run an RPC call and expect it to FAIL (reader: non-zero exit).
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

# Starts the daemon; when env_extra is non-empty it is exported to the daemon
# process (used to arm the test-only hybrid write failure injection).
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

# Derive the legacy P2PKH address from a WIF private key (pure Python
# secp256k1 + base58check). See regression_privkey_roundtrip.sh.
wif_to_legacy() {
    python3 - "$1" <<'PY'
import sys, hashlib

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

def keyhash(pub):
    return hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()

raw = b58decode(sys.argv[1])
payload = raw[:len(raw) - 4]
if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != raw[-4:]:
    sys.stderr.write("bad checksum\n"); sys.exit(1)
fCompressed = len(payload) == 34 and payload[-1] == 1
if not fCompressed:
    sys.stderr.write("uncompressed keys not expected\n"); sys.exit(1)
secret = payload[1:33]

p  = 2**256 - 2**32 - 977
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
d = int.from_bytes(secret, "big")

def inv(x): return pow(x, p - 2, p)
def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1) * inv(2 * y1) % p
    else:
        lam = (y2 - y1) * inv(x2 - x1) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

R, G = None, (Gx, Gy)
while d:
    if d & 1: R = add(R, G)
    G = add(G, G)
    d >>= 1
pub = (b"\x03" if R[1] & 1 else b"\x02") + R[0].to_bytes(32, "big")

h160 = keyhash(pub)
out = b"\x38" + h160
chk = hashlib.sha256(hashlib.sha256(out).digest()).digest()[:4]
num = int.from_bytes(out + chk, "big")
s = ""
while num:
    num, r = divmod(num, 58); s = B58[r] + s
pad = 0
for b in out + chk:
    if b == 0: pad += 1
    else: break
print("0" * pad + s)
PY
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

echo "== step 1: exporter A creates a hybrid address and exports both keys =="
start_node "$DATADIR_A" "$PORT_A" || { cleanup; echo "FAILED setup A"; exit 1; }
H=$(rpc "$DATADIR_A" "$PORT_A" gethybridaddress "atomic")
echo "   hybrid address: $H"
D_A=$(rpc "$DATADIR_A" "$PORT_A" dumphybridkey "$H")
WIF=$(echo "$D_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['secp_wif'])")
DER=$(echo "$D_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['mldsa_priv_der_b64'])")
L_A=$(wif_to_legacy "$WIF")
IDHEX=$(hybrid_id_hex "$H")
echo "   secp WIF:      ${WIF:0:8}...   hybrid id: $IDHEX"
echo "   legacy P2PKH:  $L_A"
check "exporter owns legacy P2PKH (ismine=true)" \
    "$([ "$(rpc "$DATADIR_A" "$PORT_A" validateaddress "$L_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['ismine'])")" = "True" ]; echo $?)"

echo "== step 2: importer B starts with hybrid write failure injection armed =="
start_node "$DATADIR_B" "$PORT_B" "PHOENIX_TEST_FAIL_HYBRID_WRITE=$IDHEX" \
    || { cleanup; echo "FAILED setup B"; exit 1; }

echo "== step 3: importhybridkey must FAIL on the deliberately broken write =="
OUT=$(rpc "$DATADIR_B" "$PORT_B" importhybridkey "$WIF" "$DER" "atomic" 2>&1)
OK_FAIL=$([ $? -ne 0 ]; echo $?)
check "importhybridkey errors (non-zero exit)" "$OK_FAIL"
check "importhybridkey reports the injected write failure" \
    "$(echo "$OUT" | grep -q "Error persisting hybrid key: failed to write hybrid key"; echo $?)"
check "import failure leaves NOTHING in memory (hybrid: no dumphybridkey)" \
    "$(rpc_expect_fail "$DATADIR_B" "$PORT_B" dumphybridkey "$H"; echo $?)"
check "import failure leaves NOTHING in memory (ECDSA: no dumpprivkey)" \
    "$(rpc_expect_fail "$DATADIR_B" "$PORT_B" dumpprivkey "$L_A"; echo $?)"
check "import failure leaves NO label for the failed hybrid import" \
    "$(! rpc "$DATADIR_B" "$PORT_B" listhybridaddresses | grep -qE "\"address\"\s*:\s*\"$H\""; echo $?)"
check "import failure leaves NO 'atomic' label in the address book" \
    "$(! rpc "$DATADIR_B" "$PORT_B" listhybridaddresses | grep -q 'atomic'; echo $?)"

echo "== step 4: clean restart of B (injection off) proves the DB has no residue =="
"$BIN" -datadir="$DATADIR_B" stop >/dev/null 2>&1
wait_down "$DATADIR_B" || { cleanup; echo "FAILED shutdown B"; exit 1; }
start_node "$DATADIR_B" "$PORT_B" || { cleanup; echo "FAILED restart B"; exit 1; }
check "DB residue-free: no hybrid key after restart" \
    "$(rpc_expect_fail "$DATADIR_B" "$PORT_B" dumphybridkey "$H"; echo $?)"
check "DB residue-free: no ECDSA key after restart" \
    "$(rpc_expect_fail "$DATADIR_B" "$PORT_B" dumpprivkey "$L_A"; echo $?)"
check "DB residue-free: no label for the failed import after restart" \
    "$(! rpc "$DATADIR_B" "$PORT_B" listhybridaddresses | grep -qE "\"address\"\s*:\s*\"$H\""; echo $?)"
check "DB residue-free: no 'atomic' label after restart" \
    "$(! rpc "$DATADIR_B" "$PORT_B" listhybridaddresses | grep -q 'atomic'; echo $?)"
check "DB residue-free: legacy address is not owned after restart (ismine=false)" \
    "$([ "$(rpc "$DATADIR_B" "$PORT_B" validateaddress "$L_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['ismine'])")" = "False" ]; echo $?)"
check "DB residue-free: hybrid address is not owned after restart (ismine=false)" \
    "$([ "$(rpc "$DATADIR_B" "$PORT_B" validateaddress "$H" | python3 -c "import sys,json;print(json.load(sys.stdin)['ismine'])")" = "False" ]; echo $?)"

echo "== step 5: retry of the identical import now succeeds and persists =="
H_IMPORTED=$(rpc "$DATADIR_B" "$PORT_B" importhybridkey "$WIF" "$DER" "atomic")
check "retry importhybridkey returns the same hybrid address" \
    "$([ "$H_IMPORTED" = "$H" ]; echo $?)"
D_B=$(rpc "$DATADIR_B" "$PORT_B" dumphybridkey "$H")
check "retry: dumphybridkey on B matches A exactly (WIF + DER)" \
    "$([ "$D_B" = "$D_A" ]; echo $?)"
check "retry: dumpprivkey on B returns the imported WIF" \
    "$([ "$(rpc "$DATADIR_B" "$PORT_B" dumpprivkey "$L_A")" = "$WIF" ]; echo $?)"

echo "== step 6: restart B again; everything still present =="
"$BIN" -datadir="$DATADIR_B" stop >/dev/null 2>&1
wait_down "$DATADIR_B" || { cleanup; echo "FAILED shutdown B"; exit 1; }
start_node "$DATADIR_B" "$PORT_B" || { cleanup; echo "FAILED restart B"; exit 1; }
check "post-retry restart: dumphybridkey still matches A" \
    "$([ "$(rpc "$DATADIR_B" "$PORT_B" dumphybridkey "$H")" = "$D_A" ]; echo $?)"
check "post-retry restart: label persisted in hybrid address book" \
    "$(rpc "$DATADIR_B" "$PORT_B" listhybridaddresses | grep -qE '"label"\s*:\s*"atomic"'; echo $?)"
check "post-retry restart: legacy key still spendable-owned (ismine=true)" \
    "$([ "$(rpc "$DATADIR_B" "$PORT_B" validateaddress "$L_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['ismine'])")" = "True" ]; echo $?)"
SIG=$(rpc "$DATADIR_B" "$PORT_B" signmessage "$H" "$MSG")
check "post-retry restart: hybrid still signs" "$([ -n "$SIG" ]; echo $?)"
check "post-retry restart: signature verifies cross-node on A" \
    "$([ "$(rpc "$DATADIR_A" "$PORT_A" verifymessage "$H" "$SIG" "$MSG")" = "true" ]; echo $?)"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
