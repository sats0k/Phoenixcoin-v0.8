// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <atomic>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

#include "bdb_kv.h"
#include "lmdb_kv.h"
#include "util.h"

BOOST_AUTO_TEST_SUITE(kvdb_tests)

namespace {

static CDBKey Key(const std::string &value)
{
    return CDBKey(value.begin(), value.end());
}

static CDBValue Value(const std::string &value)
{
    return CDBValue(value.begin(), value.end());
}

static std::filesystem::path MakeTempDir(const std::string &tag)
{
    static std::atomic<unsigned int> counter(0);
    std::filesystem::path dir = std::filesystem::temp_directory_path() /
        ("phoenixcoin_kvdb_" + tag + "_" + std::to_string(GetTimeMillis()) +
         "_" + std::to_string(counter.fetch_add(1)));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    BOOST_REQUIRE_MESSAGE(!ec, "could not create temp directory " << dir << ": " << ec.message());
    return dir;
}

template <typename DBType>
struct DBGuard
{
    std::filesystem::path dir;
    DBType db;

    explicit DBGuard(const std::string &tag)
        : dir(MakeTempDir(tag))
    {
        BOOST_REQUIRE_MESSAGE(db.Open(dir.string()),
                              "could not open " << tag << " database in " << dir);
    }

    ~DBGuard()
    {
        db.Close();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

static std::unique_ptr<CDBTransaction> BeginRead(CKeyValueDB &db)
{
    std::unique_ptr<CDBTransaction> txn = db.BeginTransaction(true);
    BOOST_REQUIRE_MESSAGE(txn.get() != nullptr, "could not begin read transaction");
    return txn;
}

static std::unique_ptr<CDBTransaction> BeginWrite(CKeyValueDB &db)
{
    std::unique_ptr<CDBTransaction> txn = db.BeginTransaction(false);
    BOOST_REQUIRE_MESSAGE(txn.get() != nullptr, "could not begin write transaction");
    return txn;
}

static bool ReadValue(CKeyValueDB &db, const CDBKey &key, CDBValue &value)
{
    std::unique_ptr<CDBTransaction> txn = BeginRead(db);
    const bool found = txn->Read(key, value);
    BOOST_REQUIRE_MESSAGE(txn->Commit(), "read transaction commit failed");
    return found;
}

static void WriteValue(CKeyValueDB &db, const CDBKey &key, const CDBValue &value,
                       bool fOverwrite = true)
{
    std::unique_ptr<CDBTransaction> txn = BeginWrite(db);
    BOOST_REQUIRE_MESSAGE(txn->Write(key, value, fOverwrite), "write failed");
    BOOST_REQUIRE_MESSAGE(txn->Commit(), "write transaction commit failed");
}

template <typename DBType>
void RunBasicCrud(const std::string &tag)
{
    DBGuard<DBType> guard(tag);
    CKeyValueDB &db = guard.db;
    CDBValue value;

    BOOST_CHECK(!ReadValue(db, Key("missing"), value));

    WriteValue(db, Key("alpha"), Value("one"));
    BOOST_REQUIRE(ReadValue(db, Key("alpha"), value));
    BOOST_CHECK(value == Value("one"));

    WriteValue(db, Key("alpha"), Value("two"));
    BOOST_REQUIRE(ReadValue(db, Key("alpha"), value));
    BOOST_CHECK(value == Value("two"));

    {
        std::unique_ptr<CDBTransaction> txn = BeginWrite(db);
        BOOST_CHECK(!txn->Write(Key("alpha"), Value("three"), false));
        BOOST_REQUIRE_MESSAGE(txn->Commit(), "write transaction commit failed");
    }
    BOOST_REQUIRE(ReadValue(db, Key("alpha"), value));
    BOOST_CHECK(value == Value("two"));

    WriteValue(db, Key("empty"), CDBValue());
    value = Value("sentinel");
    BOOST_REQUIRE(ReadValue(db, Key("empty"), value));
    BOOST_CHECK(value.empty());

    const CDBKey binaryKey{0x00, 0x01, 0x7f, 0xff};
    const CDBValue binaryValue{0xff, 0x00, 0x42};
    WriteValue(db, binaryKey, binaryValue);
    value.clear();
    BOOST_REQUIRE(ReadValue(db, binaryKey, value));
    BOOST_CHECK(value == binaryValue);

    {
        std::unique_ptr<CDBTransaction> txn = BeginWrite(db);
        BOOST_CHECK(txn->Erase(Key("alpha")));
        BOOST_REQUIRE_MESSAGE(txn->Commit(), "write transaction commit failed");
    }
    BOOST_CHECK(!ReadValue(db, Key("alpha"), value));

    {
        std::unique_ptr<CDBTransaction> txn = BeginWrite(db);
        BOOST_CHECK(txn->Erase(Key("missing")));
        BOOST_REQUIRE_MESSAGE(txn->Commit(), "write transaction commit failed");
    }
}

template <typename DBType>
void RunTransactions(const std::string &tag)
{
    DBGuard<DBType> guard(tag);
    CKeyValueDB &db = guard.db;
    const CDBKey key = Key("tx");
    CDBValue value;

    {
        std::unique_ptr<CDBTransaction> txn = BeginWrite(db);
        BOOST_CHECK(txn->Write(key, Value("committed")));
        BOOST_REQUIRE(txn->Read(key, value));
        BOOST_CHECK(value == Value("committed"));
        BOOST_REQUIRE_MESSAGE(txn->Commit(), "write transaction commit failed");
    }
    BOOST_REQUIRE(ReadValue(db, key, value));
    BOOST_CHECK(value == Value("committed"));

    {
        std::unique_ptr<CDBTransaction> txn = BeginWrite(db);
        BOOST_CHECK(txn->Write(key, Value("aborted")));
        txn->Abort();
    }
    BOOST_REQUIRE(ReadValue(db, key, value));
    BOOST_CHECK(value == Value("committed"));

    {
        std::unique_ptr<CDBTransaction> txn = BeginWrite(db);
        BOOST_CHECK(txn->Erase(key));
        txn->Abort();
    }
    BOOST_REQUIRE(ReadValue(db, key, value));
    BOOST_CHECK(value == Value("committed"));

    {
        std::unique_ptr<CDBTransaction> txn = BeginWrite(db);
        BOOST_CHECK(txn->Write(Key("first"), Value("1")));
        BOOST_CHECK(txn->Write(Key("second"), Value("2")));
        BOOST_REQUIRE_MESSAGE(txn->Commit(), "write transaction commit failed");
    }
    BOOST_REQUIRE(ReadValue(db, Key("first"), value));
    BOOST_CHECK(value == Value("1"));
    BOOST_REQUIRE(ReadValue(db, Key("second"), value));
    BOOST_CHECK(value == Value("2"));
}

template <typename DBType>
void RunIteration(const std::string &tag)
{
    DBGuard<DBType> guard(tag);
    CKeyValueDB &db = guard.db;

    // Insert out of order; both backends use byte-wise key ordering.
    WriteValue(db, Key("c"), Value("3"));
    WriteValue(db, Key("a"), Value("1"));
    WriteValue(db, Key("e"), Value("5"));
    WriteValue(db, Key("d"), Value("4"));

    std::unique_ptr<CDBTransaction> txn = BeginRead(db);
    {
        std::unique_ptr<CDBIterator> it = txn->NewIterator();
        BOOST_REQUIRE_MESSAGE(it.get() != nullptr, "could not create iterator");

        std::vector<CDBKey> keys;
        for (it->SeekToFirst(); it->Valid(); it->Next())
            keys.push_back(it->Key());
        const std::vector<CDBKey> expected{Key("a"), Key("c"), Key("d"), Key("e")};
        BOOST_CHECK(keys == expected);

        it->SeekToLast();
        BOOST_REQUIRE(it->Valid());
        BOOST_CHECK(it->Key() == Key("e"));
        BOOST_CHECK(it->Value() == Value("5"));

        it->Prev();
        BOOST_REQUIRE(it->Valid());
        BOOST_CHECK(it->Key() == Key("d"));

        it->Seek(Key("b"));
        BOOST_REQUIRE(it->Valid());
        BOOST_CHECK(it->Key() == Key("c"));
        BOOST_CHECK(it->Value() == Value("3"));

        it->Seek(Key("f"));
        BOOST_CHECK(!it->Valid());

        it->Seek(Key("a"));
        BOOST_REQUIRE(it->Valid());
        it->Next();
        BOOST_REQUIRE(it->Valid());
        BOOST_CHECK(it->Key() == Key("c"));
    }
    BOOST_REQUIRE_MESSAGE(txn->Commit(), "read transaction commit failed");
}

template <typename DBType>
void RunPersistence(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);

    {
        DBType db;
        BOOST_REQUIRE_MESSAGE(db.Open(dir.string()),
                              "could not open " << tag << " database in " << dir);
        WriteValue(db, Key("persistent"), Value("value"));
        db.Close();
    }

    {
        DBType db;
        BOOST_REQUIRE_MESSAGE(db.Open(dir.string()),
                              "could not reopen " << tag << " database in " << dir);

        CDBValue value;
        BOOST_REQUIRE(ReadValue(db, Key("persistent"), value));
        BOOST_CHECK(value == Value("value"));
        db.Close();
    }

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

template <typename DBType>
void RunRepeatedReadTransactions(const std::string &tag)
{
    DBGuard<DBType> guard(tag);
    WriteValue(guard.db, Key("key"), Value("value"));

    // A leaked read transaction exhausts/reuses the LMDB reader slot and makes
    // the second or subsequent begin fail.  Exercise both Commit and Abort.
    for (int i = 0; i < 100; ++i) {
        CDBValue value;
        std::unique_ptr<CDBTransaction> txn = BeginRead(guard.db);
        BOOST_REQUIRE(txn->Read(Key("key"), value));
        BOOST_CHECK(value == Value("value"));
        if (i % 2 == 0)
            BOOST_REQUIRE_MESSAGE(txn->Commit(), "read transaction commit failed");
        else
            txn->Abort();
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(bdb_kvdb_basic_crud)
{
    RunBasicCrud<CBDBDatabase>("bdb_basic");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_basic_crud)
{
    RunBasicCrud<CLMDBDatabase>("lmdb_basic");
}

BOOST_AUTO_TEST_CASE(bdb_kvdb_transactions)
{
    RunTransactions<CBDBDatabase>("bdb_transactions");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_transactions)
{
    RunTransactions<CLMDBDatabase>("lmdb_transactions");
}

BOOST_AUTO_TEST_CASE(bdb_kvdb_iteration)
{
    RunIteration<CBDBDatabase>("bdb_iteration");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_iteration)
{
    RunIteration<CLMDBDatabase>("lmdb_iteration");
}

BOOST_AUTO_TEST_CASE(bdb_kvdb_persistence)
{
    RunPersistence<CBDBDatabase>("bdb_persistence");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_persistence)
{
    RunPersistence<CLMDBDatabase>("lmdb_persistence");
}

BOOST_AUTO_TEST_CASE(bdb_kvdb_repeated_read_transactions)
{
    RunRepeatedReadTransactions<CBDBDatabase>("bdb_reads");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_repeated_read_transactions)
{
    RunRepeatedReadTransactions<CLMDBDatabase>("lmdb_reads");
}

BOOST_AUTO_TEST_SUITE_END()
