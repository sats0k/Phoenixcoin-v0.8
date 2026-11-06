// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

// Test helper: build a legacy-layout Berkeley DB file from an `mdb_dump -s
// main` dump.  The converter regression suite uses it to turn a wallet or
// chain index produced by an LMDB-only daemon into the exact on-disk shape
// that a pre-LMDB Phoenixcoin installation used, without needing an old
// daemon binary.
//
// This program is test tooling only.  It links db_cxx; phoenixcoind,
// test_phoenixcoin and the GUI must not.
//
// Usage:
//   phoenix-db-fixture <mdb-dump-file> <bdb-file> <logical-db-name>

#include <db_cxx.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

int HexDigit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool ParseHex(const std::string& strLine, std::vector<unsigned char>& out)
{
    out.clear();
    if (strLine.size() % 2 != 0)
        return false;
    out.reserve(strLine.size() / 2);
    for (size_t i = 0; i < strLine.size(); i += 2)
    {
        const int hi = HexDigit(strLine[i]);
        const int lo = HexDigit(strLine[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

bool Store(Db& db, const std::vector<unsigned char>& key,
           const std::vector<unsigned char>& value)
{
    Dbt dbKey(const_cast<unsigned char*>(key.data()), key.size());
    Dbt dbValue(const_cast<unsigned char*>(value.data()), value.size());
    const int rc = db.put(nullptr, &dbKey, &dbValue, 0);
    if (rc != 0)
    {
        std::fprintf(stderr, "bdb_fixture: put failed: %s\n",
                     db_strerror(rc));
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 4)
    {
        std::fprintf(stderr, "usage: %s <mdb-dump> <bdb-file> <db-name>\n",
                     argc > 0 ? argv[0] : "phoenix-db-fixture");
        return 2;
    }

    std::ifstream in(argv[1]);
    if (!in)
    {
        std::fprintf(stderr, "bdb_fixture: cannot open %s\n", argv[1]);
        return 1;
    }

    Db db(nullptr, DB_CXX_NO_EXCEPTIONS);
    int rc = db.open(nullptr, argv[2], argv[3], DB_BTREE,
                     DB_CREATE | DB_TRUNCATE, 0);
    if (rc != 0)
    {
        std::fprintf(stderr, "bdb_fixture: cannot create %s: %s\n",
                     argv[2], db_strerror(rc));
        return 1;
    }

    bool fInData = false;
    bool fHaveKey = false;
    std::vector<unsigned char> key;
    std::vector<unsigned char> value;
    std::string line;
    size_t nRecords = 0;

    while (std::getline(in, line))
    {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        if (!fInData)
        {
            if (line == "HEADER=END")
                fInData = true;
            continue;
        }
        if (line == "DATA=END")
            break;

        // mdb_dump writes one space before every key and value line.  An
        // empty value is a line containing only that space.
        if (!line.empty() && line.front() == ' ')
            line.erase(line.begin());

        if (!ParseHex(line, fHaveKey ? value : key))
        {
            std::fprintf(stderr, "bdb_fixture: invalid hex in %s\n", argv[1]);
            db.close(0);
            return 1;
        }

        if (!fHaveKey)
        {
            fHaveKey = true;
            continue;
        }

        if (!Store(db, key, value))
        {
            db.close(0);
            return 1;
        }
        ++nRecords;
        fHaveKey = false;
    }

    if (fHaveKey)
    {
        std::fprintf(stderr, "bdb_fixture: truncated key/value pair in %s\n",
                     argv[1]);
        db.close(0);
        return 1;
    }

    rc = db.close(0);
    if (rc != 0)
    {
        std::fprintf(stderr, "bdb_fixture: close failed: %s\n",
                     db_strerror(rc));
        return 1;
    }

    std::printf("Berkeley DB fixture: %zu records in %s\n", nRecords, argv[2]);
    return 0;
}
