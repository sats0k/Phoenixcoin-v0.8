#!/bin/bash
#
# Regression test: cross-node private-key export/import for BOTH halves of a
# hybrid key.
#
# A hybrid address carries two private keys:
#   1. hybrid  : dumped/imported via dumphybridkey / importhybridkey (the full
#                secp256k1 + ML-DSA pair, giving the "P"-style hybrid address).
#   2. legacy  : the secp256k1 half expressed as a normal P2PKH wallet key,
#                dumped/imported via dumpprivkey / importprivkey (giving the
#                legacy P2PKH address of the same key).
#
# The test starts an exporter wallet A, creates one hybrid address, derives the
# legacy P2PKH address from the exported WIF (pure-Python secp256k1), then:
#   - on A: validates BOTH addresses are wallet-owned and re-dumps identical
#           private keys;
#   - on B (fresh importer): imports the hybrid key AND the legacy WIF,
#           re-exports both identically, verifies both sign/verify and that
#           the legacy key is genuinely spendable-owned on B;
#   - restarts B and confirms all of the above still holds (persistence).
#
# Usage: src/test/regression_privkey_roundtrip.sh [path-to-phoenixcoind]

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
DATADIR_A="$(mktemp -d "/tmp/privkey-roundtrip-A.XXXXXX")"
DATADIR_B="$(mktemp -d "/tmp/privkey-roundtrip-B.XXXXXX")"
PORT_A=9671
PORT_B=9672
MSG="privkey roundtrip live test"

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

# Derive the legacy P2PKH address (and its compressed pubkey) from a WIF
# private key using pure Python secp256k1 + base58check. Phoenixcoin P2PKH
# addresses use version 0x38; WIF uses 0xB8 (0x38 + 128), compressed keys have
# a trailing 0x01 byte.
wif_to_legacy() {
    python3 - "$1" <<'PY'
import sys, hashlib, struct

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
secret = payload[1:]
fCompressed = len(payload) == 34 and payload[-1] == 1
if not fCompressed:
    sys.stderr.write("uncompressed keys not expected\n"); sys.exit(1)
secret = payload[1:33]

# secp256k1
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

echo "== step 1: start exporter A (fresh wallet) =="
start_node "$DATADIR_A" "$PORT_A" || { cleanup; echo "FAILED setup A"; exit 1; }
H=$(rpc "$DATADIR_A" "$PORT_A" gethybridaddress "roundtrip")
echo "   hybrid address: $H"
D_A=$(rpc "$DATADIR_A" "$PORT_A" dumphybridkey "$H")
WIF=$(echo "$D_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['secp_wif'])")
DER=$(echo "$D_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['mldsa_priv_der_b64'])")
echo "   secp WIF:      ${WIF:0:8}... (len ${#WIF}, compressed)"
L_A=$(wif_to_legacy "$WIF")
echo "   legacy P2PKH:  $L_A"

echo "== step 2: exporter A owns and re-dumps both keys =="
check "legacy address is wallet-owned on A (ismine=true)" \
    "$([ "$(rpc "$DATADIR_A" "$PORT_A" validateaddress "$L_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['ismine'])")" = "True" ]; echo $?)"
check "hybrid address is wallet-owned on A (ismine=true)" \
    "$([ "$(rpc "$DATADIR_A" "$PORT_A" validateaddress "$H" | python3 -c "import sys,json;print(json.load(sys.stdin)['ismine'])")" = "True" ]; echo $?)"
WIF_DUMP_A=$(rpc "$DATADIR_A" "$PORT_A" dumpprivkey "$L_A")
check "dumpprivkey on A matches exported WIF" "$([ "$WIF_DUMP_A" = "$WIF" ]; echo $?)"

echo "== step 3: start importer B (fresh wallet); import BOTH keys =="
start_node "$DATADIR_B" "$PORT_B" || { cleanup; echo "FAILED setup B"; exit 1; }
rpc "$DATADIR_B" "$PORT_B" importprivkey "$WIF" "roundtrip legacy" false >/dev/null
echo "   importprivkey on B returned OK (legacy WIF)"
H_IMPORTED=$(rpc "$DATADIR_B" "$PORT_B" importhybridkey "$WIF" "$DER" "roundtrip")
check "importhybridkey (after importprivkey) returns the same hybrid address" "$([ "$H_IMPORTED" = "$H" ]; echo $?)"

echo "== step 4: importer B re-exports both keys, identically =="
D_B=$(rpc "$DATADIR_B" "$PORT_B" dumphybridkey "$H")
check "dumphybridkey on B matches A exactly (WIF + DER)" "$([ "$D_B" = "$D_A" ]; echo $?)"
WIF_DUMP_B=$(rpc "$DATADIR_B" "$PORT_B" dumpprivkey "$L_A")
check "dumpprivkey on B returns the imported WIF" "$([ "$WIF_DUMP_B" = "$WIF" ]; echo $?)"
check "legacy address is wallet-owned on B (ismine=true)" \
    "$([ "$(rpc "$DATADIR_B" "$PORT_B" validateaddress "$L_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['ismine'])")" = "True" ]; echo $?)"

echo "== step 5: hybrid + legacy signing on B, verified on both nodes =="
SIG_H=$(rpc "$DATADIR_B" "$PORT_B" signmessage "$H" "$MSG")
check "hybrid signmessage on B" "$([ -n "$SIG_H" ]; echo $?)"
check "hybrid verifymessage on B" "$([ "$(rpc "$DATADIR_B" "$PORT_B" verifymessage "$H" "$SIG_H" "$MSG")" = "true" ]; echo $?)"
check "hybrid verifymessage on A (cross-node)" "$([ "$(rpc "$DATADIR_A" "$PORT_A" verifymessage "$H" "$SIG_H" "$MSG")" = "true" ]; echo $?)"
SIG_L=$(rpc "$DATADIR_B" "$PORT_B" signmessage "$L_A" "$MSG")
check "legacy signmessage on B" "$([ -n "$SIG_L" ]; echo $?)"
check "legacy verifymessage on B" "$([ "$(rpc "$DATADIR_B" "$PORT_B" verifymessage "$L_A" "$SIG_L" "$MSG")" = "true" ]; echo $?)"
check "legacy verifymessage on A (cross-node)" "$([ "$(rpc "$DATADIR_A" "$PORT_A" verifymessage "$L_A" "$SIG_L" "$MSG")" = "true" ]; echo $?)"

echo "== step 6: restart importer B, persist both keys =="
"$BIN" -datadir="$DATADIR_B" stop >/dev/null 2>&1
wait_down "$DATADIR_B" || { cleanup; echo "FAILED shutdown B"; exit 1; }
start_node "$DATADIR_B" "$PORT_B" || { cleanup; echo "FAILED restart B"; exit 1; }

echo "== step 7: post-restart re-export + signing on B =="
D_B2=$(rpc "$DATADIR_B" "$PORT_B" dumphybridkey "$H")
check "dumphybridkey after restart matches A (WIF + DER)" "$([ "$D_B2" = "$D_A" ]; echo $?)"
WIF_DUMP_B2=$(rpc "$DATADIR_B" "$PORT_B" dumpprivkey "$L_A")
check "dumpprivkey after restart returns the imported WIF" "$([ "$WIF_DUMP_B2" = "$WIF" ]; echo $?)"
check "legacy address is still wallet-owned after restart (ismine=true)" \
    "$([ "$(rpc "$DATADIR_B" "$PORT_B" validateaddress "$L_A" | python3 -c "import sys,json;print(json.load(sys.stdin)['ismine'])")" = "True" ]; echo $?)"
SIG_H2=$(rpc "$DATADIR_B" "$PORT_B" signmessage "$H" "$MSG")
check "hybrid signmessage after restart" "$([ -n "$SIG_H2" ]; echo $?)"
check "hybrid verifymessage after restart (A)" "$([ "$(rpc "$DATADIR_A" "$PORT_A" verifymessage "$H" "$SIG_H2" "$MSG")" = "true" ]; echo $?)"
SIG_L2=$(rpc "$DATADIR_B" "$PORT_B" signmessage "$L_A" "$MSG")
check "legacy signmessage after restart" "$([ -n "$SIG_L2" ]; echo $?)"
check "legacy verifymessage after restart (A)" "$([ "$(rpc "$DATADIR_A" "$PORT_A" verifymessage "$L_A" "$SIG_L2" "$MSG")" = "true" ]; echo $?)"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]