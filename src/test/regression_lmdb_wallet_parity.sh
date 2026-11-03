#!/bin/bash
#
# Regression test: a Berkeley DB wallet and an independently migrated LMDB
# wallet expose the same *logical* wallet state, before and after equivalent
# operations.
#
# Record-count checks prove that migration copies bytes.  This test proves that
# the two backends mean the same thing.  It builds one BDB wallet on a real
# chain fragment, stops it at a known state, copies the datadir twice, migrates
# exactly one copy to LMDB, then runs both wallets side by side as independent
# daemons.  At every checkpoint it compares a canonical form of the wallet:
#
#   * every private key (dumpwallet), including keypool membership and labels
#   * every hybrid secp256k1 + ML-DSA key (dumphybridkeys), including used/
#     unused pool state
#   * transaction history, amounts, fees, confirmations and comments
#   * accounts, account moves, received-by-account/address tallies
#   * address groupings, unspent outputs, hybrid address book
#   * balances and per-transaction details
#
# Only genuinely volatile or per-wallet-random data is discarded: timestamps,
# and in structural mode the identity and signature-size fields explained below.
# The two daemons are started on separate datadirs and RPC ports, so neither can
# mask a difference by talking to the other.
#
# Full vs structural comparison
# -----------------------------
# Up to encryption, both wallets contain exactly the same key material, so the
# comparison is `full`: WIFs, addresses, labels, txids and scripts must match.
# `encryptwallet` deliberately discards and regenerates the *legacy* keypool
# with fresh random keys (new keypool material is backend-independent and is
# not supposed to be identical across two wallets).  Every later checkpoint is
# therefore compared `structural`: key material and address identities are
# reduced to their shape (per-tag counts, labels, amounts), while everything
# that a backend could plausibly lose - transactions, account entries, hybrid
# keys, balances, unspent values - is still compared exactly.  Serialized size
# and fee-per-kB are also dropped there: an ECDSA DER signature varies by one
# byte depending on leading zeroes, so those two values differ between two
# independently created (but otherwise equivalent) transactions.
#
# The deterministic phase deliberately consumes no keypool keys, so the full
# comparison really does cover all 51 pool keys.  Random operations happen only
# after encryption, when random keypool material is expected.
#
# The test-only coinbase maturity override is inert unless the environment
# variable is set, and it is forgotten by the daemon on exit.  No test touches
# the user's real datadir.
#
# Usage: src/test/regression_lmdb_wallet_parity.sh [path-to-phoenixcoind]
#
# PXC_REGTEST_PORT can pin the base RPC port (the LMDB node uses base+1 when
# available; otherwise a second ephemeral port is chosen).  PXC_KEEP_WORK=1
# keeps the work directory and the snapshots for debugging.

set -u

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/src/phoenixcoind}"
case "$BIN" in
    /*) ;;
    *) BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")" ;;
esac

WORK="$(mktemp -d "/tmp/lmdb-wallet-parity.XXXXXX")"
BASE_BDB="$WORK/bdb-base"
BDB_DIR="$WORK/bdb"
LMDB_DIR="$WORK/lmdb"
MATERIAL="$WORK/material"
CANON="$WORK/canon.py"
PASS=0
FAIL=0

# The base daemon and one of the two final daemons can share a port because
# they never run at the same time.
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

BDB_PORT="${PXC_REGTEST_PORT:-$(find_free_port)}"
LMDB_PORT="$(find_free_port)"
while [ "$LMDB_PORT" = "$BDB_PORT" ]; do
    LMDB_PORT="$(find_free_port)"
done
case "$BDB_PORT:$LMDB_PORT" in
    *[!0-9:]*)
        echo "ERROR: could not allocate RPC ports (set PXC_REGTEST_PORT)" >&2
        exit 1
        ;;
esac

pass() { PASS=$((PASS+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

check() {
    local name="$1" cond="$2"
    if [ "$cond" = "0" ]; then pass "$name"; else fail "$name"; fi
}

check_eq() {
    local name="$1" want="$2" got="$3"
    check "$name" "$([ "$want" = "$got" ]; echo $?)"
    if [ "$want" != "$got" ]; then
        echo "        want: $want"
        echo "        got:  $got"
    fi
}

check_contains() {
    local name="$1" needle="$2" haystack="$3"
    check "$name" "$(printf '%s\n' "$haystack" | grep -qF -- "$needle"; echo $?)"
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
    timeout 60 "$BIN" -datadir="$dir" -rpcuser=reguser -rpcpassword=regpass \
        -rpcport="$port" "$method" "$@"
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

# Is a daemon for this datadir still running?  Prefer the pid file; the
# `-daemon` suffix distinguishes the server from the short-lived RPC client,
# which has the same -datadir argument but no -daemon.
daemon_alive() {
    local dir="$1" pid
    pid=$(cat "$dir/phoenixcoind.pid" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    pgrep -f "phoenixcoind -datadir=$dir.*-daemon" >/dev/null 2>&1
}

wait_down_at() {
    local dir="$1" i
    for i in $(seq 1 60); do
        daemon_alive "$dir" || return 0
        sleep 0.5
    done
    return 1
}

kill_at() {
    local dir="$1" pid i
    pid=$(cat "$dir/phoenixcoind.pid" 2>/dev/null)
    [ -n "$pid" ] ||
        pid=$(pgrep -f "phoenixcoind -datadir=$dir.*-daemon" | head -1)
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    for i in $(seq 1 20); do
        daemon_alive "$dir" || return 0
        sleep 0.25
    done
    return 1
}

# Wait for a daemon that is shutting itself down (encryptwallet).  Force it
# only if the self-shutdown path is stuck.
ensure_down_at() {
    local dir="$1"
    wait_down_at "$dir" && return 0
    echo "  NOTE: daemon in $dir did not stop itself; forcing shutdown"
    kill_at "$dir"
}

start_at() {
    local dir="$1" port="$2"; shift 2
    write_config "$dir" "$port"
    # The maturity override is test-only and forgotten by the daemon on exit.
    PHOENIX_TEST_COINBASE_MATURITY=0 \
        "$BIN" -datadir="$dir" "$@" -daemon >/dev/null 2>&1
    wait_ready_at "$dir" "$port"
}

stop_at() {
    local dir="$1" port="$2"
    rpc_dir "$dir" "$port" stop >/dev/null 2>&1
    wait_down_at "$dir" && return 0
    # A stop request issued while the wallet is still re-accepting transactions
    # at startup is occasionally lost.  Retry before falling back to SIGKILL.
    # Every caller stops between durable wallet operations, and the next start
    # re-opens the same files, so a forced stop cannot hide a wallet bug: the
    # following checkpoint would still see any torn state.
    rpc_dir "$dir" "$port" stop >/dev/null 2>&1
    wait_down_at "$dir" && return 0
    echo "  NOTE: daemon in $dir ignored stop; forcing shutdown"
    kill_at "$dir" || {
        echo "  ERROR: daemon in $dir survived SIGKILL"
        return 1
    }
}

cleanup() {
    local d p
    for d in "$BASE_BDB" "$BDB_DIR" "$LMDB_DIR" "$MATERIAL"; do
        [ -d "$d" ] || continue
        if pgrep -f "phoenixcoind -datadir=$d" >/dev/null 2>&1; then
            # A datadir only ever has one port associated with it.
            case "$d" in
                "$LMDB_DIR") p="$LMDB_PORT" ;;
                *) p="$BDB_PORT" ;;
            esac
            stop_at "$d" "$p" >/dev/null 2>&1 ||
                kill_at "$d" >/dev/null 2>&1
        fi
    done
    if [ "${PXC_KEEP_WORK:-0}" = "1" ]; then
        echo "kept work directory: $WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

# Copy a stopped datadir.  Logs, pid files and stale LMDB lock state belong to
# the source process, not to the copy.
copy_dir() {
    local src="$1" dest="$2"
    rm -rf "$dest"
    mkdir -p "$dest"
    cp -a "$src/." "$dest/"
    rm -f "$dest/debug.log" "$dest/foreground.log" "$dest/phoenixcoind.pid" \
          "$dest/wallet.backend.tmp" "$dest/wallet/lock.mdb"
}

json_field() {
    python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1],""))' "$1"
}

key_roundtrip() {
    local dir="$1" port="$2" addr="$3" want_wif="$4" label="$5"
    check "$label: address is owned" \
        "$(rpc_dir "$dir" "$port" validateaddress "$addr" 2>/dev/null |
           grep -q '"ismine" : true'; echo $?)"
    check_eq "$label: private key is unchanged" "$want_wif" \
        "$(rpc_dir "$dir" "$port" dumpprivkey "$addr" 2>/dev/null)"
}

hybrid_roundtrip() {
    local dir="$1" port="$2" addr="$3" want_wif="$4" want_der="$5" label="$6"
    local got
    got=$(rpc_dir "$dir" "$port" dumphybridkey "$addr" 2>/dev/null)
    check_eq "$label: hybrid ECDSA half is unchanged" "$want_wif" \
        "$(printf '%s' "$got" | json_field secp_wif)"
    check_eq "$label: hybrid ML-DSA half is unchanged" "$want_der" \
        "$(printf '%s' "$got" | json_field mldsa_priv_der_b64)"
}

unlock_dir() {
    local dir="$1" port="$2"
    # walletpassphrase starts an asynchronous keypool top-up.  A synchronous
    # keypoolrefill afterwards makes the resulting pool size deterministic;
    # both calls are idempotent once the pool is full.  This matters for the
    # structural comparison, which still checks keypool size.
    rpc_dir "$dir" "$port" walletpassphrase "$WALLET_PASSPHRASE" 3600 \
        >/dev/null 2>&1 || true
    if rpc_dir "$dir" "$port" keypoolrefill >/dev/null 2>&1; then
        return 0
    fi
    echo "  ERROR: could not unlock the wallet in $dir"
    return 1
}

# ---------------------------------------------------------------------------
# The canonical snapshot tool.  It talks to one daemon, collects every logical
# wallet view, canonicalizes it (dropping only volatility, and key/address
# identity in structural mode) and writes a sorted JSON document.
# ---------------------------------------------------------------------------
cat > "$CANON" <<'PY'
import json
import os
import re
import subprocess
import sys

# Fields that legitimately differ between two wallets even when the logical
# state is identical, or that depend on wall-clock time.
VOLATILE = {"time", "timereceived", "created", "unlocked_until"}
# In structural mode the same logical transaction may have a different txid and
# a different (freshly generated) change address, so identity fields go away.
# The serialized size is not logical state either: ECDSA DER signatures vary by
# a byte depending on leading zeroes, which also perturbs the fee-per-kB ratio.
STRUCT_DROP = {"txid", "address", "scriptPubKey", "pubkey_ecdsa", "hex", "vout",
               "size_bytes", "fee_per_kb"}

DUMP_KEY_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(?:label=(\S*)|(reserve=1)|(change=1))\s+#\s+addr=(\S+)\s*$")
DUMP_HYB_RE = re.compile(
    r"^(\S+)\s+(\S+)\s+(\S+)\s+(?:label=(\S*)|(reserve=1)|(change=1))"
    r"\s+#\s+addr=(\S+)\s+#\s+mldsa_alg=(\S+)\s*$")


def kn(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def rpc(binary, datadir, port, *args):
    cmd = [binary, "-datadir=" + datadir, "-rpcuser=reguser",
           "-rpcpassword=regpass", "-rpcport=" + str(port)]
    cmd.extend(args)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        sys.stderr.write("RPC timeout: %s\n" % " ".join(args))
        raise SystemExit(2)
    if proc.returncode != 0:
        sys.stderr.write("RPC failed (%s): %s\n" %
                         (" ".join(args), (proc.stderr or proc.stdout).strip()))
        raise SystemExit(2)
    return proc.stdout


def rpc_json(binary, datadir, port, *args):
    out = rpc(binary, datadir, port, *args)
    try:
        return json.loads(out)
    except ValueError:
        sys.stderr.write("Bad JSON from %s: %r\n" % (args, out))
        raise SystemExit(2)


def dump_text(binary, datadir, port, method, prefix, seq):
    name = "%s-%d-%d.txt" % (prefix, os.getpid(), seq)
    path = os.path.join(datadir, name)
    try:
        if os.path.exists(path):
            os.unlink(path)
        rpc(binary, datadir, port, method, name)
        if not os.path.exists(path):
            sys.stderr.write("%s did not create %s\n" % (method, path))
            raise SystemExit(2)
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def tag_of(label, reserve, change):
    if label is not None:
        return "label"
    if reserve is not None:
        return "reserve"
    return "change"


def parse_keys(text, mode):
    out = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue
        match = DUMP_KEY_RE.match(line)
        if not match:
            sys.stderr.write("Unparsed dumpwallet line: %r\n" % line)
            raise SystemExit(2)
        wif, _stamp, label, reserve, change, addr = match.groups()
        tag = tag_of(label, reserve, change)
        record = {"tag": tag}
        if tag == "label":
            record["label"] = label
        if mode == "full":
            record["wif"] = wif
            record["addr"] = addr
        out.append(record)
    return sorted(out, key=kn)


def parse_hybrid(text, mode):
    out = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue
        match = DUMP_HYB_RE.match(line)
        if not match:
            sys.stderr.write("Unparsed dumphybridkeys line: %r\n" % line)
            raise SystemExit(2)
        wif, der, _stamp, label, reserve, change, addr, alg = match.groups()
        tag = tag_of(label, reserve, change)
        record = {"tag": tag, "addr": addr, "alg": alg}
        if tag == "label":
            record["label"] = label
        if mode == "full":
            record["wif"] = wif
            record["der"] = der
        out.append(record)
    return sorted(out, key=kn)


def clean(value, mode):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in VOLATILE:
                continue
            if mode == "structural" and key in STRUCT_DROP:
                continue
            out[key] = clean(item, mode)
        return out
    if isinstance(value, list):
        return [clean(item, mode) for item in value]
    return value


def clean_groupings(groups, mode):
    out = []
    for group in groups:
        entries = []
        for entry in group:
            if mode == "full":
                entries.append(clean(entry, mode))
            else:
                # [address, amount, label?] -> [amount, label?]
                reduced = [entry[1]]
                if len(entry) > 2:
                    reduced.append(entry[2])
                entries.append(reduced)
        entries.sort(key=kn)
        out.append(entries)
    out.sort(key=kn)
    return out


def snapshot(mode, binary, datadir, port, outfile, extras):
    keys_text = dump_text(binary, datadir, port, "dumpwallet",
                          "parity-dump", 1)
    hybrid_text = dump_text(binary, datadir, port, "dumphybridkeys",
                            "parity-hybrid", 2)

    data = {}
    data["balance"] = rpc_json(binary, datadir, port, "getbalance")
    data["balance_star"] = rpc_json(binary, datadir, port,
                                    "getbalance", "*")
    data["accounts"] = clean(rpc_json(binary, datadir, port,
                                      "listaccounts", "0"), mode)
    data["transactions"] = sorted(clean(rpc_json(
        binary, datadir, port, "listtransactions", "*", "1000", "0"), mode),
        key=kn)
    data["received_by_account"] = sorted(clean(rpc_json(
        binary, datadir, port, "listreceivedbyaccount", "0", "true"), mode),
        key=kn)
    data["received_by_address"] = sorted(clean(rpc_json(
        binary, datadir, port, "listreceivedbyaddress", "0", "true"), mode),
        key=kn)
    data["unspent"] = sorted(clean(rpc_json(
        binary, datadir, port, "listunspent", "0", "9999999"), mode), key=kn)
    data["groupings"] = clean_groupings(rpc_json(
        binary, datadir, port, "listaddressgroupings"), mode)
    data["hybrid_addresses"] = sorted(clean(rpc_json(
        binary, datadir, port, "listhybridaddresses"), mode), key=kn)
    data["keys"] = parse_keys(keys_text, mode)
    data["hybrid_keys"] = parse_hybrid(hybrid_text, mode)

    txs = {}
    for extra in extras:
        if "=" not in extra:
            sys.stderr.write("bad transaction argument: %r\n" % extra)
            raise SystemExit(2)
        label, txid = extra.split("=", 1)
        txs[label] = clean(rpc_json(binary, datadir, port,
                                    "gettransaction", txid), mode)
    data["txs"] = txs

    with open(outfile, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: canon.py snapshot|compare ...\n")
        return 2

    command = argv[1]
    if command == "compare":
        with open(argv[2], "r", encoding="utf-8") as handle:
            left = json.load(handle)
        with open(argv[3], "r", encoding="utf-8") as handle:
            right = json.load(handle)
        differing = [key for key in sorted(set(left) | set(right))
                     if left.get(key) != right.get(key)]
        for key in differing:
            print(key)
        return 1 if differing else 0

    if command != "snapshot" or len(argv) < 7:
        sys.stderr.write(
            "usage: canon.py snapshot <mode> <bin> <datadir> <port> "
            "<outfile> [label=txid...]\n")
        return 2

    mode = argv[2]
    if mode not in ("full", "structural"):
        sys.stderr.write("bad mode: %r\n" % mode)
        return 2
    snapshot(mode, argv[3], argv[4], argv[5], argv[6], argv[7:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
PY

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
WATCH_ADDR="Pajnrp35dtogiFeTqQxNurGDgsxfVVaUrz"
WALLET_PASSPHRASE="parity passphrase with spaces"

# Keypool target used by every daemon.  TopUpKeyPool targets -keypool + 1, so an
# unlocked wallet settles at exactly 51 keys.  With the deterministic phase
# consuming none of them, a full snapshot really compares the whole pool.
#
# Note: the CLI does not convert `keypoolrefill`'s optional size argument (see
# RPCConvertValues), so `keypoolrefill 50` fails with "value is type str".  Only
# the no-argument form can be driven through the daemon's command line.  A
# larger pool is requested by restarting with a larger -keypool and then calling
# `keypoolrefill` without an argument.
KEYPOOL=50
KEYPOOL_BIG=80

# ---------------------------------------------------------------------------
# Snapshot / comparison helpers
# ---------------------------------------------------------------------------
snapshot_node() {
    local dir="$1" port="$2" mode="$3" out="$4" encsend="${5:-}"
    local extra=("block5=$BLOCK5_TXID" "block6=$BLOCK6_TXID" "pre=$TX_PRE")
    [ -n "$encsend" ] && extra+=("encsend=$encsend")
    python3 "$CANON" snapshot "$mode" "$BIN" "$dir" "$port" "$out" \
        "${extra[@]}"
}

# compare_parity <label> <mode> [bdb-encrypted-send-txid] [lmdb-...]
compare_parity() {
    local label="$1" mode="$2" eb="${3:-}" el="${4:-}"
    local bdb="$WORK/canon-bdb.json" lmdb="$WORK/canon-lmdb.json"

    if ! snapshot_node "$BDB_DIR" "$BDB_PORT" "$mode" "$bdb" "$eb"; then
        fail "$label: could not snapshot the BDB wallet"
        return
    fi
    if ! snapshot_node "$LMDB_DIR" "$LMDB_PORT" "$mode" "$lmdb" "$el"; then
        fail "$label: could not snapshot the LMDB wallet"
        return
    fi
    # Keep every checkpoint's snapshots: expect_tags() reads the current pair,
    # but a failed run is much easier to debug when earlier checkpoints and the
    # per-side difference are still on disk.
    cp "$bdb" "$WORK/canon-$label-bdb.json"
    cp "$lmdb" "$WORK/canon-$label-lmdb.json"
    diff -u "$bdb" "$lmdb" > "$WORK/diff-$label.txt" 2>&1 || true

    if python3 "$CANON" compare "$bdb" "$lmdb" > "$WORK/diff-sections.txt" 2>&1
    then
        pass "$label: logical wallet state matches ($mode)"
        return
    fi

    fail "$label: logical wallet state differs ($mode)"
    if [ -s "$WORK/diff-sections.txt" ]; then
        echo "        differing sections:"
        sed 's/^/          /' "$WORK/diff-sections.txt"
    fi
    echo "        first differences:"
    sed -n '1,80p' "$WORK/diff-$label.txt" | sed 's/^/          /'
}

# count of dumpwallet records carrying a tag (label/reserve/change)
tag_count() {
    local file="$1" tag="$2"
    python3 -c 'import json,sys
data = json.load(open(sys.argv[1]))
print(sum(1 for record in data["keys"] if record["tag"] == sys.argv[2]))' \
        "$file" "$tag"
}

expect_tags() {
    local label="$1" want_label="$2" want_reserve="$3" want_change="$4"
    local file side tag want got
    for side in bdb lmdb; do
        file="$WORK/canon-$side.json"
        for tag in label reserve change; do
            case "$tag" in
                label) want="$want_label" ;;
                reserve) want="$want_reserve" ;;
                change) want="$want_change" ;;
            esac
            got=$(tag_count "$file" "$tag")
            check_eq "$label: $side key records tagged $tag" "$want" "$got"
        done
    done
}

# ---------------------------------------------------------------------------
# Setup: build the reference BDB wallet
# ---------------------------------------------------------------------------
echo "== setup: build a Berkeley DB wallet at a known state =="
mkdir -p "$BASE_BDB"
if ! start_at "$BASE_BDB" "$BDB_PORT" -walletbackend=bdb -keypool="$KEYPOOL"; then
    echo "FAILED: could not start the base BDB daemon"
    exit 1
fi

for h in 1 2 3 4 5 6; do
    rpc_dir "$BASE_BDB" "$BDB_PORT" submitblock "${BLOCK_HEX[$h]}" \
        >/dev/null 2>&1
done
check_eq "chain fragment connected to height 6" "6" \
    "$(rpc_dir "$BASE_BDB" "$BDB_PORT" getblockcount 2>/dev/null)"

rpc_dir "$BASE_BDB" "$BDB_PORT" importprivkey "$COINBASE5_WIF" \
    "coinbase-5" true >/dev/null 2>&1
rpc_dir "$BASE_BDB" "$BDB_PORT" importprivkey "$COINBASE6_WIF" \
    "coinbase-6" true >/dev/null 2>&1
check_eq "coinbase balance is 100 PXC" "100.00000000" \
    "$(rpc_dir "$BASE_BDB" "$BDB_PORT" getbalance 2>/dev/null)"

TX_PRE=$(rpc_dir "$BASE_BDB" "$BDB_PORT" sendtoaddress "$EXTERNAL_ADDR" 10 \
    "parity pre-migration send" "parity" 2>/dev/null)
check "created the pre-migration send" "$([ -n "$TX_PRE" ]; echo $?)"
check_eq "balance after the pre-migration send" "89.99000000" \
    "$(rpc_dir "$BASE_BDB" "$BDB_PORT" getbalance 2>/dev/null)"

ALICE_ADDR=$(rpc_dir "$BASE_BDB" "$BDB_PORT" getnewaddress alice 2>/dev/null)
ALICE_WIF=$(rpc_dir "$BASE_BDB" "$BDB_PORT" dumpprivkey "$ALICE_ADDR" 2>/dev/null)
BOB_ADDR=$(rpc_dir "$BASE_BDB" "$BDB_PORT" getnewaddress bob 2>/dev/null)
BOB_WIF=$(rpc_dir "$BASE_BDB" "$BDB_PORT" dumpprivkey "$BOB_ADDR" 2>/dev/null)

# Three addresses in "orig": the setaccount target must not be the account's
# current key, otherwise setaccount would silently generate a pool key.
ORIG_TARGET=$(rpc_dir "$BASE_BDB" "$BDB_PORT" getnewaddress orig 2>/dev/null)
rpc_dir "$BASE_BDB" "$BDB_PORT" getnewaddress orig >/dev/null 2>&1
ORIG_CURRENT=$(rpc_dir "$BASE_BDB" "$BDB_PORT" getaccountaddress orig 2>/dev/null)
check_eq "the setaccount target starts in account orig" "orig" \
    "$(rpc_dir "$BASE_BDB" "$BDB_PORT" getaccount "$ORIG_TARGET" 2>/dev/null)"
check "the setaccount target is not the account's current key" \
    "$([ -n "$ORIG_TARGET" ] && [ "$ORIG_TARGET" != "$ORIG_CURRENT" ]; echo $?)"

rpc_dir "$BASE_BDB" "$BDB_PORT" importaddress "$WATCH_ADDR" \
    "watched-external" false >/dev/null 2>&1
MULTISIG_ADDR=$(rpc_dir "$BASE_BDB" "$BDB_PORT" addmultisigaddress 1 \
    '["02a3888b3ffdef44aaa27cef8bf6d7214c7f2bdcc9a622999c54f69268330a2d03","03f9c886d2c62b55754c56dc9db4ee8112f975d2b0e0854ba7a1ab250d9a97f323"]' \
    multisig 2>/dev/null)
check "created a multisig script address" \
    "$([ -n "$MULTISIG_ADDR" ]; echo $?)"

HYB_BASE_ADDR=$(rpc_dir "$BASE_BDB" "$BDB_PORT" gethybridaddress \
    "hybrid-base" 2>/dev/null)
HYB_BASE_JSON=$(rpc_dir "$BASE_BDB" "$BDB_PORT" dumphybridkey \
    "$HYB_BASE_ADDR" 2>/dev/null)
HYB_BASE_WIF=$(printf '%s' "$HYB_BASE_JSON" | json_field secp_wif)
HYB_BASE_DER=$(printf '%s' "$HYB_BASE_JSON" | json_field mldsa_priv_der_b64)
check "created the labelled base hybrid key" \
    "$([ -n "$HYB_BASE_ADDR" ] && [ -n "$HYB_BASE_WIF" ] &&
       [ -n "$HYB_BASE_DER" ]; echo $?)"

# Settle the legacy keypool last so the stopped state has exactly 51 pool keys.
# (Only the no-argument form reaches the RPC; see KEYPOOL above.)
check "keypoolrefill succeeded" \
    "$(rpc_dir "$BASE_BDB" "$BDB_PORT" keypoolrefill >/dev/null 2>&1; echo $?)"

stop_at "$BASE_BDB" "$BDB_PORT" || {
    echo "FAILED: base daemon did not stop"; exit 1;
}
check "the base wallet is a Berkeley DB wallet" \
    "$([ -f "$BASE_BDB/wallet.dat" ] && [ ! -f "$BASE_BDB/wallet.backend" ]; echo $?)"

# ---------------------------------------------------------------------------
# Fresh material: generated in a brand-new wallet so neither copy already has
# it.  Copying the base datadir would reuse its pre-generated keypool keys.
# ---------------------------------------------------------------------------
echo "== setup: generate independent import material =="
mkdir -p "$MATERIAL"
if ! start_at "$MATERIAL" "$BDB_PORT" -walletbackend=bdb -keypool=1; then
    echo "FAILED: could not start the material daemon"
    exit 1
fi
FRESH_HYB_ADDR=$(rpc_dir "$MATERIAL" "$BDB_PORT" gethybridaddress \
    "fresh-hybrid" 2>/dev/null)
FRESH_HYB_JSON=$(rpc_dir "$MATERIAL" "$BDB_PORT" dumphybridkey \
    "$FRESH_HYB_ADDR" 2>/dev/null)
FRESH_HYB_WIF=$(printf '%s' "$FRESH_HYB_JSON" | json_field secp_wif)
FRESH_HYB_DER=$(printf '%s' "$FRESH_HYB_JSON" | json_field mldsa_priv_der_b64)
FRESH_ADDR=$(rpc_dir "$MATERIAL" "$BDB_PORT" getnewaddress "fresh-key" 2>/dev/null)
FRESH_WIF=$(rpc_dir "$MATERIAL" "$BDB_PORT" dumpprivkey "$FRESH_ADDR" 2>/dev/null)
check "generated independent key and hybrid-key material" \
    "$([ -n "$FRESH_HYB_ADDR" ] && [ -n "$FRESH_HYB_WIF" ] &&
       [ -n "$FRESH_HYB_DER" ] && [ -n "$FRESH_ADDR" ] &&
       [ -n "$FRESH_WIF" ]; echo $?)"
stop_at "$MATERIAL" "$BDB_PORT"
rm -rf "$MATERIAL"

# ---------------------------------------------------------------------------
# Branch the known state: one BDB wallet, one independently migrated LMDB copy
# ---------------------------------------------------------------------------
echo "== setup: migrate one copy to LMDB =="
copy_dir "$BASE_BDB" "$BDB_DIR"
copy_dir "$BASE_BDB" "$LMDB_DIR"

if ! start_at "$LMDB_DIR" "$LMDB_PORT" -walletbackend=lmdb \
        -keypool="$KEYPOOL"; then
    echo "FAILED: cannot start the reference LMDB migration"
    exit 1
fi
check_eq "migration wrote the LMDB backend marker" "lmdb" \
    "$(cat "$LMDB_DIR/wallet.backend" 2>/dev/null)"
check "migration completed" \
    "$(grep -q 'Wallet migration complete' "$LMDB_DIR/debug.log"; echo $?)"
stop_at "$LMDB_DIR" "$LMDB_PORT" || {
    echo "FAILED: the migration daemon did not stop"; exit 1;
}

check "the BDB branch still has a Berkeley DB wallet" \
    "$([ -f "$BDB_DIR/wallet.dat" ] && [ ! -f "$BDB_DIR/wallet.backend" ]; echo $?)"
check "the LMDB branch has an LMDB wallet environment" \
    "$([ -f "$LMDB_DIR/wallet/data.mdb" ]; echo $?)"

echo "== start both wallets independently =="
if ! start_at "$BDB_DIR" "$BDB_PORT" -walletbackend=bdb -keypool="$KEYPOOL"; then
    echo "FAILED: could not start the BDB branch"
    exit 1
fi
if ! start_at "$LMDB_DIR" "$LMDB_PORT" -walletbackend=lmdb \
        -keypool="$KEYPOOL"; then
    echo "FAILED: could not start the LMDB branch"
    exit 1
fi
check_eq "both branches report the same chain height" \
    "$(rpc_dir "$BDB_DIR" "$BDB_PORT" getblockcount 2>/dev/null)" \
    "$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" getblockcount 2>/dev/null)"

# ---------------------------------------------------------------------------
# Checkpoint 1: migration itself preserved the logical state
# ---------------------------------------------------------------------------
echo "== checkpoint 1: post-migration state =="
compare_parity "post-migration" full
expect_tags "post-migration" 8 51 21

# ---------------------------------------------------------------------------
# Checkpoint 2: equivalent deterministic operations on both branches
# ---------------------------------------------------------------------------
echo "== checkpoint 2: equivalent deterministic operations =="
rpc_dir "$BDB_DIR" "$BDB_PORT" importprivkey "$FRESH_WIF" "det-import" false \
    >/dev/null 2>&1
rpc_dir "$LMDB_DIR" "$LMDB_PORT" importprivkey "$FRESH_WIF" "det-import" false \
    >/dev/null 2>&1
check_eq "imported key is owned by both branches" "true:true" \
    "$(rpc_dir "$BDB_DIR" "$BDB_PORT" validateaddress "$FRESH_ADDR" 2>/dev/null |
        grep -q '"ismine" : true' && echo true):$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" validateaddress "$FRESH_ADDR" 2>/dev/null | grep -q '"ismine" : true' && echo true)"

IMPORTED_HYB_BDB=$(rpc_dir "$BDB_DIR" "$BDB_PORT" importhybridkey \
    "$FRESH_HYB_WIF" "$FRESH_HYB_DER" "det-hybrid-import" 2>/dev/null)
IMPORTED_HYB_LMDB=$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" importhybridkey \
    "$FRESH_HYB_WIF" "$FRESH_HYB_DER" "det-hybrid-import" 2>/dev/null)
check_eq "importhybridkey returned the same address on both branches" \
    "$FRESH_HYB_ADDR" "$IMPORTED_HYB_BDB"
check_eq "importhybridkey address on LMDB" "$IMPORTED_HYB_BDB" "$IMPORTED_HYB_LMDB"

rpc_dir "$BDB_DIR" "$BDB_PORT" setaccount "$ORIG_TARGET" "det-account" \
    >/dev/null 2>&1
rpc_dir "$LMDB_DIR" "$LMDB_PORT" setaccount "$ORIG_TARGET" "det-account" \
    >/dev/null 2>&1
check_eq "setaccount applied on BDB" "det-account" \
    "$(rpc_dir "$BDB_DIR" "$BDB_PORT" getaccount "$ORIG_TARGET" 2>/dev/null)"
check_eq "setaccount applied on LMDB" "det-account" \
    "$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" getaccount "$ORIG_TARGET" 2>/dev/null)"

check_eq "move applied on BDB" "true" \
    "$(rpc_dir "$BDB_DIR" "$BDB_PORT" move "" "det-move-account" 1.5 2>/dev/null)"
check_eq "move applied on LMDB" "true" \
    "$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" move "" "det-move-account" 1.5 2>/dev/null)"

# The hybrid pool is shared, so allocation itself must be identical.
DET_HYB_BDB=$(rpc_dir "$BDB_DIR" "$BDB_PORT" gethybridaddress "det-hybrid" 2>/dev/null)
DET_HYB_LMDB=$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" gethybridaddress "det-hybrid" 2>/dev/null)
check "deterministic gethybridaddress returned a key" \
    "$([ -n "$DET_HYB_BDB" ]; echo $?)"
check_eq "hybrid keypool allocation matches on both branches" \
    "$DET_HYB_BDB" "$DET_HYB_LMDB"

# Sign on one backend, verify on the other: this proves the private keys are
# byte-identical, not merely present under the same address.
SIG_BDB=$(rpc_dir "$BDB_DIR" "$BDB_PORT" signmessage "$ALICE_ADDR" \
    "parity deterministic message" 2>/dev/null)
SIG_LMDB=$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" signmessage "$ALICE_ADDR" \
    "parity deterministic message" 2>/dev/null)
check "BDB signature verifies on LMDB" \
    "$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" verifymessage "$ALICE_ADDR" \
       "$SIG_BDB" "parity deterministic message" 2>/dev/null |
       grep -q true; echo $?)"
check "LMDB signature verifies on BDB" \
    "$(rpc_dir "$BDB_DIR" "$BDB_PORT" verifymessage "$ALICE_ADDR" \
       "$SIG_LMDB" "parity deterministic message" 2>/dev/null |
       grep -q true; echo $?)"

compare_parity "deterministic-operations" full
expect_tags "deterministic-operations" 9 51 22

# ---------------------------------------------------------------------------
# Checkpoint 3: encryption and a real post-encryption spend
# ---------------------------------------------------------------------------
echo "== checkpoint 3: encrypt both wallets and spend after unlock =="
rpc_dir "$BDB_DIR" "$BDB_PORT" encryptwallet "$WALLET_PASSPHRASE" \
    >/dev/null 2>&1
rpc_dir "$LMDB_DIR" "$LMDB_PORT" encryptwallet "$WALLET_PASSPHRASE" \
    >/dev/null 2>&1
ensure_down_at "$BDB_DIR" || { echo "FAILED: BDB encryptwallet did not stop"; exit 1; }
ensure_down_at "$LMDB_DIR" || { echo "FAILED: LMDB encryptwallet did not stop"; exit 1; }

if ! start_at "$BDB_DIR" "$BDB_PORT" -walletbackend=bdb -keypool="$KEYPOOL"; then
    echo "FAILED: could not restart the encrypted BDB branch"; exit 1
fi
if ! start_at "$LMDB_DIR" "$LMDB_PORT" -walletbackend=lmdb \
        -keypool="$KEYPOOL"; then
    echo "FAILED: could not restart the encrypted LMDB branch"; exit 1
fi

# A locked encrypted wallet must refuse to export keys on both backends.
check "BDB encrypted wallet is locked at startup" \
    "$(! rpc_dir "$BDB_DIR" "$BDB_PORT" dumpwallet locked.txt \
        >/dev/null 2>&1; echo $?)"
check "LMDB encrypted wallet is locked at startup" \
    "$(! rpc_dir "$LMDB_DIR" "$LMDB_PORT" dumpwallet locked.txt \
        >/dev/null 2>&1; echo $?)"
rm -f "$BDB_DIR/locked.txt" "$LMDB_DIR/locked.txt"

unlock_dir "$BDB_DIR" "$BDB_PORT" || { echo "FAILED: BDB unlock"; exit 1; }
unlock_dir "$LMDB_DIR" "$LMDB_PORT" || { echo "FAILED: LMDB unlock"; exit 1; }

# Block 6's coinbase is the only output large enough for this amount, so coin
# selection is deterministic even though the change key and output position are
# not.  The resulting transactions are compared structurally.
SEND_BDB=$(rpc_dir "$BDB_DIR" "$BDB_PORT" sendtoaddress "$EXTERNAL_ADDR" 40 \
    "parity encrypted send" "parity" 2>/dev/null)
SEND_LMDB=$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" sendtoaddress "$EXTERNAL_ADDR" 40 \
    "parity encrypted send" "parity" 2>/dev/null)
check "created the encrypted send on BDB" "$([ -n "$SEND_BDB" ]; echo $?)"
check "created the encrypted send on LMDB" "$([ -n "$SEND_LMDB" ]; echo $?)"
check_eq "both branches have the same balance after the encrypted send" \
    "49.98000000" "$(rpc_dir "$BDB_DIR" "$BDB_PORT" getbalance 2>/dev/null)"
check_eq "LMDB balance after the encrypted send" \
    "49.98000000" "$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" getbalance 2>/dev/null)"

compare_parity "post-encryption-send" structural "$SEND_BDB" "$SEND_LMDB"
expect_tags "post-encryption-send" 9 50 74

# ---------------------------------------------------------------------------
# Checkpoint 4: grow the keypool and allocate random addresses after encryption
# ---------------------------------------------------------------------------
echo "== checkpoint 4: keypool growth and random address allocation =="
# `keypoolrefill` cannot receive its size argument through the CLI, so ask for a
# bigger pool by restarting with a bigger -keypool and then letting the
# no-argument `keypoolrefill` (inside unlock_dir) fill it.  Both branches leave
# encryption with 50 pool keys and must grow to exactly KEYPOOL_BIG + 1.
stop_at "$BDB_DIR" "$BDB_PORT" || { echo "FAILED: BDB did not stop"; exit 1; }
stop_at "$LMDB_DIR" "$LMDB_PORT" || { echo "FAILED: LMDB did not stop"; exit 1; }
if ! start_at "$BDB_DIR" "$BDB_PORT" -walletbackend=bdb -keypool="$KEYPOOL_BIG"; then
    echo "FAILED: could not restart the BDB branch"; exit 1
fi
if ! start_at "$LMDB_DIR" "$LMDB_PORT" -walletbackend=lmdb \
        -keypool="$KEYPOOL_BIG"; then
    echo "FAILED: could not restart the LMDB branch"; exit 1
fi
unlock_dir "$BDB_DIR" "$BDB_PORT" || { echo "FAILED: BDB unlock"; exit 1; }
unlock_dir "$LMDB_DIR" "$LMDB_PORT" || { echo "FAILED: LMDB unlock"; exit 1; }

RAND_BDB=$(rpc_dir "$BDB_DIR" "$BDB_PORT" getnewaddress "random" 2>/dev/null)
RAND_LMDB=$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" getnewaddress "random" 2>/dev/null)
check "keypool produced an address on BDB" "$([ -n "$RAND_BDB" ]; echo $?)"
check "keypool produced an address on LMDB" "$([ -n "$RAND_LMDB" ]; echo $?)"
check "fresh keypool addresses are independently random" \
    "$([ "$RAND_BDB" != "$RAND_LMDB" ]; echo $?)"

RAND_HYB_BDB=$(rpc_dir "$BDB_DIR" "$BDB_PORT" gethybridaddress \
    "random-hybrid" 2>/dev/null)
RAND_HYB_LMDB=$(rpc_dir "$LMDB_DIR" "$LMDB_PORT" gethybridaddress \
    "random-hybrid" 2>/dev/null)
check_eq "shared hybrid pool still allocates identically" \
    "$RAND_HYB_BDB" "$RAND_HYB_LMDB"

# Settle the pool again after consuming one key for the random address.
rpc_dir "$BDB_DIR" "$BDB_PORT" keypoolrefill >/dev/null 2>&1
rpc_dir "$LMDB_DIR" "$LMDB_PORT" keypoolrefill >/dev/null 2>&1

compare_parity "after-random-ops" structural "$SEND_BDB" "$SEND_LMDB"
expect_tags "after-random-ops" 10 81 74

# ---------------------------------------------------------------------------
# Checkpoint 5: restart both and verify the final state survived
# ---------------------------------------------------------------------------
echo "== checkpoint 5: restart both wallets and compare again =="
stop_at "$BDB_DIR" "$BDB_PORT" || { echo "FAILED: BDB did not stop"; exit 1; }
stop_at "$LMDB_DIR" "$LMDB_PORT" || { echo "FAILED: LMDB did not stop"; exit 1; }

if ! start_at "$BDB_DIR" "$BDB_PORT" -walletbackend=bdb -keypool="$KEYPOOL_BIG"; then
    echo "FAILED: could not restart the BDB branch"; exit 1
fi
if ! start_at "$LMDB_DIR" "$LMDB_PORT" -walletbackend=lmdb \
        -keypool="$KEYPOOL_BIG"; then
    echo "FAILED: could not restart the LMDB branch"; exit 1
fi

check "BDB branch is still BDB after restart" \
    "$([ -f "$BDB_DIR/wallet.dat" ] && [ ! -f "$BDB_DIR/wallet.backend" ]; echo $?)"
check_eq "LMDB branch is still LMDB after restart" "lmdb" \
    "$(cat "$LMDB_DIR/wallet.backend" 2>/dev/null)"
check "restarted BDB wallet is locked" \
    "$(! rpc_dir "$BDB_DIR" "$BDB_PORT" dumpwallet locked.txt \
        >/dev/null 2>&1; echo $?)"
check "restarted LMDB wallet is locked" \
    "$(! rpc_dir "$LMDB_DIR" "$LMDB_PORT" dumpwallet locked.txt \
        >/dev/null 2>&1; echo $?)"
rm -f "$BDB_DIR/locked.txt" "$LMDB_DIR/locked.txt"

unlock_dir "$BDB_DIR" "$BDB_PORT" || { echo "FAILED: BDB unlock"; exit 1; }
unlock_dir "$LMDB_DIR" "$LMDB_PORT" || { echo "FAILED: LMDB unlock"; exit 1; }

compare_parity "after-restart" structural "$SEND_BDB" "$SEND_LMDB"
expect_tags "after-restart" 10 81 74

# Targeted identity checks: the exact keys that existed before encryption must
# survive verbatim on both backends.
echo "== final: known-key and address-book invariants on both branches =="
key_roundtrip "$BDB_DIR" "$BDB_PORT" "$COINBASE5_ADDR" "$COINBASE5_WIF" \
    "BDB block 5 coinbase key"
key_roundtrip "$LMDB_DIR" "$LMDB_PORT" "$COINBASE5_ADDR" "$COINBASE5_WIF" \
    "LMDB block 5 coinbase key"
key_roundtrip "$BDB_DIR" "$BDB_PORT" "$COINBASE6_ADDR" "$COINBASE6_WIF" \
    "BDB block 6 coinbase key"
key_roundtrip "$LMDB_DIR" "$LMDB_PORT" "$COINBASE6_ADDR" "$COINBASE6_WIF" \
    "LMDB block 6 coinbase key"
key_roundtrip "$BDB_DIR" "$BDB_PORT" "$ALICE_ADDR" "$ALICE_WIF" \
    "BDB alice key"
key_roundtrip "$LMDB_DIR" "$LMDB_PORT" "$ALICE_ADDR" "$ALICE_WIF" \
    "LMDB alice key"
key_roundtrip "$BDB_DIR" "$BDB_PORT" "$FRESH_ADDR" "$FRESH_WIF" \
    "BDB imported key"
key_roundtrip "$LMDB_DIR" "$LMDB_PORT" "$FRESH_ADDR" "$FRESH_WIF" \
    "LMDB imported key"

hybrid_roundtrip "$BDB_DIR" "$BDB_PORT" "$HYB_BASE_ADDR" \
    "$HYB_BASE_WIF" "$HYB_BASE_DER" "BDB base hybrid key"
hybrid_roundtrip "$LMDB_DIR" "$LMDB_PORT" "$HYB_BASE_ADDR" \
    "$HYB_BASE_WIF" "$HYB_BASE_DER" "LMDB base hybrid key"
hybrid_roundtrip "$BDB_DIR" "$BDB_PORT" "$FRESH_HYB_ADDR" \
    "$FRESH_HYB_WIF" "$FRESH_HYB_DER" "BDB imported hybrid key"
hybrid_roundtrip "$LMDB_DIR" "$LMDB_PORT" "$FRESH_HYB_ADDR" \
    "$FRESH_HYB_WIF" "$FRESH_HYB_DER" "LMDB imported hybrid key"

for side in BDB LMDB; do
    if [ "$side" = BDB ]; then dir="$BDB_DIR"; port="$BDB_PORT";
    else dir="$LMDB_DIR"; port="$LMDB_PORT"; fi
    check_contains "$side: watch-only address survived" '"watchonly" : true' \
        "$(rpc_dir "$dir" "$port" validateaddress "$WATCH_ADDR" 2>/dev/null)"
    check_contains "$side: watch-only label survived" \
        '"account" : "watched-external"' \
        "$(rpc_dir "$dir" "$port" validateaddress "$WATCH_ADDR" 2>/dev/null)"
    check_contains "$side: multisig script survived" "$MULTISIG_ADDR" \
        "$(rpc_dir "$dir" "$port" getaddressesbyaccount multisig 2>/dev/null)"
    check_contains "$side: alice label survived" "$ALICE_ADDR" \
        "$(rpc_dir "$dir" "$port" getaddressesbyaccount alice 2>/dev/null)"
    check_contains "$side: bob label survived" "$BOB_ADDR" \
        "$(rpc_dir "$dir" "$port" getaddressesbyaccount bob 2>/dev/null)"
    check_contains "$side: setaccount label survived" "$ORIG_TARGET" \
        "$(rpc_dir "$dir" "$port" getaddressesbyaccount det-account 2>/dev/null)"
    check_contains "$side: hybrid base label survived" "$HYB_BASE_ADDR" \
        "$(rpc_dir "$dir" "$port" listhybridaddresses 2>/dev/null)"
    check_contains "$side: deterministic hybrid label survived" "$DET_HYB_BDB" \
        "$(rpc_dir "$dir" "$port" listhybridaddresses 2>/dev/null)"
    check_eq "$side: final balance" "49.98000000" \
        "$(rpc_dir "$dir" "$port" getbalance 2>/dev/null)"
done

echo
echo "RESULT: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
