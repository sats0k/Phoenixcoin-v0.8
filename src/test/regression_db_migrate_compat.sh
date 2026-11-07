#!/bin/bash
#
# Regression test: converter compatibility with older Berkeley DB versions.
#
# Phoenixcoin users have data directories written by different Berkeley DB
# releases.  The converter must read them without assuming a single library
# version.  This test builds a database with an older libdb_cxx (for example
# 5.3), then converts it with the normal converter, which is normally linked
# against the current Berkeley DB (for example 6.2).
#
# The test is optional: when no older libdb_cxx is installed it reports SKIP
# and exits successfully.  Release builds must run it on at least one machine
# with the oldest supported Berkeley DB.
#
# Usage:
#   src/test/regression_db_migrate_compat.sh [phoenix-db-migrate] [old-libdb]
#
# The older library can also be selected with PXC_OLD_BDB_LIB.

set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIGRATE="${1:-$ROOT/src/phoenix-db-migrate}"
OLD_LIB="${2:-${PXC_OLD_BDB_LIB:-}}"

if [ ! -x "$MIGRATE" ]; then
    echo "ERROR: phoenix-db-migrate not found at $MIGRATE" >&2
    exit 1
fi

if [ -z "$OLD_LIB" ]; then
    for candidate in \
        /usr/lib/libdb_cxx-5.3.so \
        /usr/lib64/libdb_cxx-5.3.so \
        /usr/lib/x86_64-linux-gnu/libdb_cxx-5.3.so \
        /usr/local/lib/libdb_cxx-5.3.so \
        /usr/lib/libdb_cxx-5.1.so \
        /usr/lib/x86_64-linux-gnu/libdb_cxx-5.1.so \
        /usr/lib/libdb_cxx-4.8.so \
        /usr/lib/x86_64-linux-gnu/libdb_cxx-4.8.so; do
        if [ -e "$candidate" ]; then
            OLD_LIB="$candidate"
            break
        fi
    done
fi

if [ -z "$OLD_LIB" ] || [ ! -e "$OLD_LIB" ]; then
    echo "SKIP: no older libdb_cxx found (set PXC_OLD_BDB_LIB to run this test)"
    exit 0
fi

WORK="$(mktemp -d "/tmp/db-migrate-compat.XXXXXX")"
cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT

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

cat > "$WORK/make_old_bdb.cpp" <<'CPP'
#include <db_cxx.h>

#include <cstdio>

int main(int argc, char** argv)
{
    if (argc != 3)
        return 2;

    DbEnv env(static_cast<u_int32_t>(DB_CXX_NO_EXCEPTIONS));
    int rc = env.open(argv[1], DB_CREATE | DB_INIT_MPOOL | DB_PRIVATE, 0);
    if (rc != 0)
    {
        std::fprintf(stderr, "env.open: %s\n", db_strerror(rc));
        return 1;
    }

    Db db(&env, DB_CXX_NO_EXCEPTIONS);
    rc = db.open(nullptr, argv[2], "main", DB_BTREE, DB_CREATE, 0);
    if (rc != 0)
    {
        std::fprintf(stderr, "db.open: %s\n", db_strerror(rc));
        return 1;
    }

    // CDB serializes a record type as a compact-size-prefixed string.  The
    // converter only requires a parseable "version" record for a wallet.
    unsigned char key[] = {7, 'v', 'e', 'r', 's', 'i', 'o', 'n'};
    unsigned char value[] = {0, 0, 0, 0};
    Dbt dbKey(key, sizeof(key));
    Dbt dbValue(value, sizeof(value));
    rc = db.put(nullptr, &dbKey, &dbValue, 0);
    if (rc != 0)
    {
        std::fprintf(stderr, "put: %s\n", db_strerror(rc));
        return 1;
    }

    db.close(0);
    env.close(0);
    std::printf("old Berkeley DB fixture: %s\n", argv[2]);
    return 0;
}
CPP

CXX_BIN="${CXX:-g++}"
if ! "$CXX_BIN" -O2 -std=c++17 -o "$WORK/make_old_bdb" \
        "$WORK/make_old_bdb.cpp" "$OLD_LIB" -lpthread -lrt; then
    echo "ERROR: could not build the old Berkeley DB fixture helper" >&2
    exit 1
fi

if ! "$WORK/make_old_bdb" "$WORK" "$WORK/wallet.dat"; then
    echo "ERROR: could not create the old Berkeley DB fixture" >&2
    exit 1
fi

SOURCE_SUM="$(sha256sum "$WORK/wallet.dat" | cut -d' ' -f1)"

echo "== converter version =="
"$MIGRATE" --version
check "--version reports the converter version" \
    "$("$MIGRATE" --version 2>/dev/null | grep -q 'phoenix-db-migrate'; echo $?)"
check "--version reports the Berkeley DB library" \
    "$("$MIGRATE" --version 2>/dev/null | grep -q 'Berkeley DB library'; echo $?)"

echo "== convert a database written by $OLD_LIB =="
if ! "$MIGRATE" --datadir="$WORK" --wallet > "$WORK/migrate.log" 2>&1; then
    echo "  ERROR: migration failed:"
    sed 's/^/    /' "$WORK/migrate.log"
    FAIL=$((FAIL+1))
else
    PASS=$((PASS+1)); echo "  PASS: converter accepted the older Berkeley DB file"
fi

check "wallet marker says lmdb" \
    "$([ "$(cat "$WORK/wallet.backend" 2>/dev/null)" = lmdb ]; echo $?)"
check "LMDB environment was installed" \
    "$([ -s "$WORK/wallet/data.mdb" ]; echo $?)"
check "original Berkeley DB file is unchanged" \
    "$([ "$(sha256sum "$WORK/wallet.dat" | cut -d' ' -f1)" = "$SOURCE_SUM" ]; echo $?)"

if command -v mdb_dump >/dev/null 2>&1; then
    mdb_dump -s main "$WORK/wallet" > "$WORK/lmdb.dump" 2>/dev/null
    check "converted record survives with its original key" \
        "$(grep -q '0776657273696f6e' "$WORK/lmdb.dump"; echo $?)"
    check "converted record survives with its original value" \
        "$(grep -q '00000000' "$WORK/lmdb.dump"; echo $?)"
else
    echo "  SKIP: mdb_dump not available, record contents not checked"
fi

echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" = 0 ]
