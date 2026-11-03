// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <atomic>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <boost/test/unit_test.hpp>

#ifndef WINDOWS
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "allocators.h"
#include "bdb_kv.h"
#include "db.h"
#include "lmdb_kv.h"
#include "main.h"
#include "util.h"
#include "wallet.h"
#include "walletdb.h"

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

/** Temporarily removes or overrides one command-line argument. */
class ArgOverride
{
public:
    explicit ArgOverride(const std::string &name) : name(name),
        fHadValue(mapArgs.count(name) != 0)
    {
        if (fHadValue)
            strValue = mapArgs[name];
        mapArgs.erase(name);
    }

    ~ArgOverride()
    {
        if (fHadValue)
            mapArgs[name] = strValue;
        else
            mapArgs.erase(name);
    }

    void Set(const std::string &value) { mapArgs[name] = value; }

private:
    std::string name;
    std::string strValue;
    bool fHadValue;
};

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
        BOOST_CHECK(!it->Error());
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

// LMDB allows exactly one write transaction per environment.  The adapter
// serializes writers with a non-blocking lock, so a second writer fails to
// start while the first one is active.
void RunWriterSerialization(const std::string &tag)
{
    DBGuard<CLMDBDatabase> guard(tag);
    CKeyValueDB &db = guard.db;
    CDBValue value;

    std::unique_ptr<CDBTransaction> first = BeginWrite(db);
    BOOST_CHECK(first->Write(Key("key"), Value("uncommitted")));

    // A second writer must not start while the first one holds the slot.
    BOOST_CHECK(db.BeginTransaction(false) == nullptr);

    // Readers are not blocked by the writer, but they see the last committed
    // snapshot rather than the pending write.
    BOOST_CHECK(!ReadValue(db, Key("key"), value));

    BOOST_REQUIRE_MESSAGE(first->Commit(), "write transaction commit failed");
    BOOST_REQUIRE(ReadValue(db, Key("key"), value));
    BOOST_CHECK(value == Value("uncommitted"));

    // Committing releases the writer slot.
    std::unique_ptr<CDBTransaction> second = BeginWrite(db);
    BOOST_CHECK(second->Write(Key("key"), Value("aborted")));
    second->Abort();

    // ...and so does aborting.
    std::unique_ptr<CDBTransaction> third = BeginWrite(db);
    BOOST_CHECK(third->Write(Key("key"), Value("committed")));
    BOOST_REQUIRE_MESSAGE(third->Commit(), "write transaction commit failed");

    BOOST_REQUIRE(ReadValue(db, Key("key"), value));
    BOOST_CHECK(value == Value("committed"));
}

// Read transactions are not tied to a thread because the environment is
// opened with MDB_NOTLS.  A transaction may be finished on another thread as
// long as it is not used concurrently.
void RunTransactionThreadHandoff(const std::string &tag)
{
    DBGuard<CLMDBDatabase> guard(tag);
    WriteValue(guard.db, Key("key"), Value("value"));

    std::unique_ptr<CDBTransaction> txn = BeginRead(guard.db);
    CDBValue value;
    BOOST_REQUIRE(txn->Read(Key("key"), value));
    BOOST_CHECK(value == Value("value"));

    bool committed = false;
    std::thread thread([&txn, &committed]() { committed = txn->Commit(); });
    thread.join();

    BOOST_CHECK(committed);
}

void RunConcurrentReaders(const std::string &tag)
{
    DBGuard<CLMDBDatabase> guard(tag);
    WriteValue(guard.db, Key("counter"), Value("42"));

    constexpr int nThreads = 8;
    constexpr int nReads = 200;
    std::atomic<int> failures(0);
    std::vector<std::thread> threads;

    for (int t = 0; t < nThreads; ++t) {
        threads.emplace_back([&guard, &failures]() {
            for (int i = 0; i < nReads; ++i) {
                CDBValue value;
                std::unique_ptr<CDBTransaction> txn = guard.db.BeginTransaction(true);
                if (!txn.get()) {
                    ++failures;
                    continue;
                }
                if (!txn->Read(Key("counter"), value) || value != Value("42"))
                    ++failures;
                if (!txn->Commit())
                    ++failures;
            }
        });
    }

    for (std::thread &thread : threads)
        thread.join();

    BOOST_CHECK_EQUAL(failures.load(), 0);
}

void RunConcurrentWriters(const std::string &tag)
{
    DBGuard<CLMDBDatabase> guard(tag);
    WriteValue(guard.db, Key("counter"), Value("0"));

    constexpr int nThreads = 4;
    constexpr int nWrites = 50;
    std::atomic<int> failures(0);
    std::atomic<int> busyRetries(0);
    std::atomic<int> committed(0);
    std::vector<std::thread> threads;

    for (int t = 0; t < nThreads; ++t) {
        threads.emplace_back([&guard, &failures, &busyRetries, &committed]() {
            int done = 0;
            while (done < nWrites) {
                std::unique_ptr<CDBTransaction> txn = guard.db.BeginTransaction(false);
                if (!txn.get()) {
                    ++busyRetries;
                    std::this_thread::yield();
                    continue;
                }

                CDBValue value;
                if (!txn->Read(Key("counter"), value)) {
                    txn->Abort();
                    ++failures;
                    continue;
                }

                int counter = 0;
                try {
                    counter = std::stoi(std::string(value.begin(), value.end()));
                } catch (...) {
                    txn->Abort();
                    ++failures;
                    continue;
                }

                if (!txn->Write(Key("counter"), Value(std::to_string(counter + 1)))) {
                    txn->Abort();
                    ++failures;
                    continue;
                }
                if (!txn->Commit()) {
                    ++failures;
                    continue;
                }

                ++committed;
                ++done;
            }
        });
    }

    for (std::thread &thread : threads)
        thread.join();

    BOOST_CHECK_EQUAL(failures.load(), 0);
    BOOST_CHECK_EQUAL(committed.load(), nThreads * nWrites);
    BOOST_TEST_MESSAGE("writer contention retries: " << busyRetries.load());

    CDBValue value;
    BOOST_REQUIRE(ReadValue(guard.db, Key("counter"), value));
    BOOST_CHECK_EQUAL(std::stoi(std::string(value.begin(), value.end())), nThreads * nWrites);
}

template <typename DBType>
void RunPrefixIteration(const std::string &tag)
{
    DBGuard<DBType> guard(tag);
    CKeyValueDB &db = guard.db;

    WriteValue(db, Key("ab"), Value("ab"));
    WriteValue(db, Key("abc1"), Value("1"));
    WriteValue(db, Key("abc2"), Value("2"));
    WriteValue(db, Key("abd"), Value("abd"));
    WriteValue(db, Key("b"), Value("b"));

    // Prefix that ends in 0xff exercises the explicit upper-bound path.
    const CDBKey lowPrefix{0xfe, 0xff};
    WriteValue(db, lowPrefix, Value("low"));
    WriteValue(db, CDBKey{0xfe, 0xff, 0x01}, Value("low1"));
    WriteValue(db, CDBKey{0xfe, 0xff, 0x02}, Value("low2"));
    WriteValue(db, CDBKey{0xff}, Value("high"));

    // All-0xff prefix has no upper bound and exercises the DB_LAST path.
    const CDBKey highPrefix{0xff};
    WriteValue(db, CDBKey{0xff, 0x01}, Value("high1"));
    WriteValue(db, CDBKey{0xff, 0x02}, Value("high2"));

    std::unique_ptr<CDBTransaction> txn = BeginRead(db);
    {
        std::unique_ptr<CDBIterator> it = txn->NewIterator(Key("abc"));
        BOOST_REQUIRE_MESSAGE(it.get() != nullptr, "could not create prefixed iterator");

        std::vector<CDBKey> keys;
        for (it->SeekToFirst(); it->Valid(); it->Next())
            keys.push_back(it->Key());
        BOOST_CHECK(keys == (std::vector<CDBKey>{Key("abc1"), Key("abc2")}));

        it->SeekToLast();
        BOOST_REQUIRE(it->Valid());
        BOOST_CHECK(it->Key() == Key("abc2"));
        BOOST_CHECK(it->Value() == Value("2"));

        it->Prev();
        BOOST_REQUIRE(it->Valid());
        BOOST_CHECK(it->Key() == Key("abc1"));

        // A seek below the prefix starts at the first matching key.
        it->Seek(Key("ab"));
        BOOST_REQUIRE(it->Valid());
        BOOST_CHECK(it->Key() == Key("abc1"));

        it->Seek(Key("abc2"));
        BOOST_REQUIRE(it->Valid());
        BOOST_CHECK(it->Key() == Key("abc2"));

        // The next key after the prefix ends iteration.
        it->Next();
        BOOST_CHECK(!it->Valid());

        it->Seek(Key("abcd"));
        BOOST_CHECK(!it->Valid());
    }

    {
        std::unique_ptr<CDBIterator> it = txn->NewIterator(lowPrefix);
        std::vector<CDBKey> keys;
        for (it->SeekToFirst(); it->Valid(); it->Next())
            keys.push_back(it->Key());
        const std::vector<CDBKey> expected{
            lowPrefix,
            CDBKey{0xfe, 0xff, 0x01},
            CDBKey{0xfe, 0xff, 0x02},
        };
        BOOST_CHECK(keys == expected);

        it->SeekToLast();
        BOOST_REQUIRE(it->Valid());
        BOOST_CHECK((it->Key() == CDBKey{0xfe, 0xff, 0x02}));
    }

    {
        std::unique_ptr<CDBIterator> it = txn->NewIterator(highPrefix);
        it->SeekToLast();
        BOOST_REQUIRE(it->Valid());
        BOOST_CHECK((it->Key() == CDBKey{0xff, 0x02}));

        std::vector<CDBKey> keys;
        for (it->SeekToFirst(); it->Valid(); it->Next())
            keys.push_back(it->Key());
        const std::vector<CDBKey> expected{
            CDBKey{0xff},
            CDBKey{0xff, 0x01},
            CDBKey{0xff, 0x02},
        };
        BOOST_CHECK(keys == expected);
    }
    BOOST_REQUIRE_MESSAGE(txn->Commit(), "read transaction commit failed");
}

void RunSharedEnvironment(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);

    {
        CLMDBEnv env;
        BOOST_REQUIRE_MESSAGE(env.Open(dir.string()), "could not open shared LMDB environment");

        CLMDBDatabase chain;
        CLMDBDatabase wallet;
        BOOST_REQUIRE_MESSAGE(chain.Open(env, "chain", true),
                              "could not open chain sub-database");
        BOOST_REQUIRE_MESSAGE(wallet.Open(env, "wallet", true),
                              "could not open wallet sub-database");

        // Sub-databases are isolated even though they share one environment.
        WriteValue(chain, Key("key"), Value("chain"));
        WriteValue(wallet, Key("key"), Value("wallet"));

        CDBValue value;
        BOOST_REQUIRE(ReadValue(chain, Key("key"), value));
        BOOST_CHECK(value == Value("chain"));
        BOOST_REQUIRE(ReadValue(wallet, Key("key"), value));
        BOOST_CHECK(value == Value("wallet"));

        // Closing a database handle must leave the shared environment open.
        chain.Close();
        BOOST_CHECK(env.IsOpen());

        CLMDBDatabase chainAgain;
        BOOST_REQUIRE_MESSAGE(chainAgain.Open(env, "chain", false),
                              "could not reopen shared chain sub-database");
        BOOST_REQUIRE(ReadValue(chainAgain, Key("key"), value));
        BOOST_CHECK(value == Value("chain"));

        chainAgain.Close();
        wallet.Close();
        env.Close();
    }

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

void RunNoSyncEnvironment(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);

    {
        CLMDBEnv env;
        BOOST_REQUIRE_MESSAGE(env.Open(dir.string(), true, 0, true),
                              "could not open nosync LMDB environment");
        BOOST_CHECK(env.IsNoSync());

        unsigned int flags = 0;
        BOOST_REQUIRE_EQUAL(mdb_env_get_flags(env.GetEnv(), &flags), 0);
        BOOST_CHECK((flags & MDB_NOSYNC) != 0);

        CLMDBDatabase db;
        BOOST_REQUIRE_MESSAGE(db.Open(env, "main", true),
                              "could not open nosync sub-database");
        WriteValue(db, Key("persistent"), Value("value"));
        db.Close();

        BOOST_CHECK(env.Sync(true));
        // Closing also flushes the environment when it was opened with MDB_NOSYNC.
        env.Close();
    }

    {
        CLMDBEnv env;
        BOOST_REQUIRE_MESSAGE(env.Open(dir.string(), false, 0, false),
                              "could not reopen LMDB environment");
        BOOST_CHECK(!env.IsNoSync());

        unsigned int flags = 0;
        BOOST_REQUIRE_EQUAL(mdb_env_get_flags(env.GetEnv(), &flags), 0);
        BOOST_CHECK((flags & MDB_NOSYNC) == 0);

        CLMDBDatabase db;
        BOOST_REQUIRE_MESSAGE(db.Open(env, "main", false),
                              "could not reopen sub-database");
        CDBValue value;
        BOOST_REQUIRE(ReadValue(db, Key("persistent"), value));
        BOOST_CHECK(value == Value("value"));
        db.Close();
        env.Close();
    }

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

void RunMapSizeAdjust(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);

    {
        CLMDBEnv env;
        BOOST_REQUIRE_MESSAGE(env.Open(dir.string()), "could not open LMDB environment");
        CLMDBDatabase db;
        BOOST_REQUIRE_MESSAGE(db.Open(env, "main", true), "could not open sub-database");
        WriteValue(db, Key("persistent"), Value("value"));
        db.Close();
        env.Close();
    }

    constexpr size_t nSmallMap = 1ULL * 1024ULL * 1024ULL;
    {
        // A map smaller than the existing data file must be enlarged instead of
        // failing to open.  This protects a datadir created with a larger
        // -lmdbmapsize from being started without that option.
        CLMDBEnv env;
        BOOST_REQUIRE_MESSAGE(env.Open(dir.string(), false, nSmallMap, false),
                              "could not reopen LMDB environment with a small map");

        MDB_envinfo info;
        BOOST_REQUIRE_EQUAL(mdb_env_info(env.GetEnv(), &info), 0);
        BOOST_CHECK(info.me_mapsize > nSmallMap);

        CLMDBDatabase db;
        BOOST_REQUIRE_MESSAGE(db.Open(env, "main", false), "could not reopen sub-database");
        CDBValue value;
        BOOST_REQUIRE(ReadValue(db, Key("persistent"), value));
        BOOST_CHECK(value == Value("value"));
        db.Close();
        env.Close();
    }

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

#ifndef WINDOWS
void RunNoSyncCrashConsistency(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);

    // Create the environment and sub-database first so the child only writes.
    {
        CLMDBEnv env;
        BOOST_REQUIRE(env.Open(dir.string(), true, 0, true));
        CLMDBDatabase db;
        BOOST_REQUIRE(db.Open(env, "main", true));
        db.Close();
        env.Close();
    }

    const pid_t pid = fork();
    BOOST_REQUIRE_MESSAGE(pid >= 0, "fork failed");

    if (pid == 0) {
        // Commit with MDB_NOSYNC and terminate without closing the environment.
        // This models a process crash rather than a clean shutdown.
        CLMDBEnv env;
        if (!env.Open(dir.string(), false, 0, true))
            _exit(10);
        CLMDBDatabase db;
        if (!db.Open(env, "main", false))
            _exit(11);
        std::unique_ptr<CDBTransaction> txn = db.BeginTransaction(false);
        if (!txn.get())
            _exit(12);
        if (!txn->Write(Key("crash"), Value("survives")))
            _exit(13);
        if (!txn->Commit())
            _exit(14);
        _exit(0);
    }

    int status = 0;
    BOOST_REQUIRE_EQUAL(waitpid(pid, &status, 0), pid);
    BOOST_REQUIRE(WIFEXITED(status));
    BOOST_REQUIRE_EQUAL(WEXITSTATUS(status), 0);

    // The committed transaction must still be visible after the crash.
    {
        CLMDBEnv env;
        BOOST_REQUIRE(env.Open(dir.string(), false, 0, false));
        CLMDBDatabase db;
        BOOST_REQUIRE(db.Open(env, "main", false));
        CDBValue value;
        BOOST_REQUIRE(ReadValue(db, Key("crash"), value));
        BOOST_CHECK(value == Value("survives"));
        db.Close();
        env.Close();
    }

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}
#endif

void RunChainIndexStartupAction(const std::string & /*tag*/)
{
    BOOST_CHECK_EQUAL(GetChainIndexStartupAction(false, false), CHAIN_INDEX_USE_EXISTING);
    BOOST_CHECK_EQUAL(GetChainIndexStartupAction(true, false), CHAIN_INDEX_USE_EXISTING);
    BOOST_CHECK_EQUAL(GetChainIndexStartupAction(false, true), CHAIN_INDEX_MIGRATE_BDB);
    BOOST_CHECK_EQUAL(GetChainIndexStartupAction(true, true), CHAIN_INDEX_FAIL_MISSING);
}

void RunLMDBMapSizeParsing(const std::string & /*tag*/)
{
    size_t nBytes = 0;
    std::string strError;

    BOOST_REQUIRE(ParseLMDBMapSize("1", nBytes, strError));
    BOOST_CHECK_EQUAL(nBytes, static_cast<size_t>(1024ULL * 1024ULL));

    BOOST_REQUIRE(ParseLMDBMapSize(std::to_string(GetLMDBMaxMapSizeMiB()), nBytes, strError));
    BOOST_CHECK(nBytes > 0);

    BOOST_CHECK(!ParseLMDBMapSize("0", nBytes, strError));
    BOOST_CHECK(!ParseLMDBMapSize("-1", nBytes, strError));
    BOOST_CHECK(!ParseLMDBMapSize("", nBytes, strError));
    BOOST_CHECK(!ParseLMDBMapSize("abc", nBytes, strError));
    BOOST_CHECK(!ParseLMDBMapSize("1024MiB", nBytes, strError));
    BOOST_CHECK(!ParseLMDBMapSize("999999999999999999999999", nBytes, strError));

    const std::string strTooLarge = std::to_string(GetLMDBMaxMapSizeMiB() + 1);
    BOOST_CHECK(!ParseLMDBMapSize(strTooLarge, nBytes, strError));
    BOOST_CHECK(!strError.empty());

    // A 4096 MiB request must not wrap on 32-bit builds, where it is above the
    // supported LMDB address-space range.
    if (GetLMDBMaxMapSizeMiB() < 4096)
        BOOST_CHECK(!ParseLMDBMapSize("4096", nBytes, strError));
    else
        BOOST_REQUIRE(ParseLMDBMapSize("4096", nBytes, strError));
}

void RunLMDBWalletMigrationMapSize(const std::string & /*tag*/)
{
    const size_t nMiB = 1024ULL * 1024ULL;
    const size_t nMaxBytes =
        static_cast<size_t>(GetLMDBMaxMapSizeMiB()) * nMiB;
    const size_t nConfigured = 512ULL * nMiB;

    // A small source fits in the configured map, so nothing changes.
    BOOST_CHECK_EQUAL(
        GetLMDBWalletMapSizeForMigration(nConfigured, 128ULL * nMiB),
        nConfigured);

    // A wallet larger than the configured map gets room for the copy.  This
    // is the size that failed with MDB_MAP_FULL before migration pre-sizing.
    const uintmax_t nHeavyWallet = 1186258944ULL;
    const size_t nSized =
        GetLMDBWalletMapSizeForMigration(nConfigured, nHeavyWallet);
    BOOST_CHECK_GT(nSized, nConfigured);
    BOOST_CHECK_GT(nSized, nHeavyWallet);
    BOOST_CHECK_LE(nSized, nMaxBytes);
    const size_t nPageSize = GetSystemPageSize();
    if (nPageSize > 0)
        BOOST_CHECK_EQUAL(nSized % nPageSize, 0);

    // An explicit map that is already large enough is never reduced.
    BOOST_CHECK_EQUAL(
        GetLMDBWalletMapSizeForMigration(nMaxBytes, 128ULL * nMiB),
        nMaxBytes);

    // The result is capped at the platform's LMDB address-space limit, even
    // for a source that cannot possibly fit.
    BOOST_CHECK_EQUAL(
        GetLMDBWalletMapSizeForMigration(0, (std::numeric_limits<uintmax_t>::max)()),
        nMaxBytes);
}

void RunBlockIndexRollback(const std::string & /*tag*/)
{
    const uint256 hash("0x00000000000000000000000000000000000000000000000000000000deadbeef");
    BOOST_REQUIRE(mapBlockIndex.count(hash) == 0);

    // A failed AddToBlockIndex() must not leave the candidate behind.
    CBlockIndex* pindex = new CBlockIndex();
    mapBlockIndex[hash] = pindex;
    RollbackBlockIndexEntry(hash, pindex);
    BOOST_CHECK(mapBlockIndex.count(hash) == 0);

    // The rollback must not erase an entry that belongs to another object.
    CBlockIndex* pindexKept = new CBlockIndex();
    CBlockIndex* pindexOther = new CBlockIndex();
    mapBlockIndex[hash] = pindexKept;
    RollbackBlockIndexEntry(hash, pindexOther);
    BOOST_CHECK_EQUAL(mapBlockIndex.count(hash), 1u);
    BOOST_CHECK(mapBlockIndex[hash] == pindexKept);

    RollbackBlockIndexEntry(hash, pindexKept);
    BOOST_CHECK(mapBlockIndex.count(hash) == 0);
}

void RunChainBackendMarker(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);
    std::string marker;

    BOOST_CHECK(!ReadChainBackendMarker(dir, marker));
    BOOST_CHECK(!HasLMDBChainIndex(dir));
    BOOST_CHECK(CheckChainBackendCompatibility(dir, DB_BACKEND_BDB));
    BOOST_CHECK(CheckChainBackendCompatibility(dir, DB_BACKEND_LMDB));

    BOOST_REQUIRE(WriteChainBackendMarker(dir, "bdb"));
    BOOST_REQUIRE(ReadChainBackendMarker(dir, marker));
    BOOST_CHECK_EQUAL(marker, "bdb");
    BOOST_CHECK(CheckChainBackendCompatibility(dir, DB_BACKEND_BDB));
    BOOST_CHECK(CheckChainBackendCompatibility(dir, DB_BACKEND_LMDB));

    // Switching to LMDB must block a later default BDB start.
    BOOST_REQUIRE(WriteChainBackendMarker(dir, "lmdb"));
    BOOST_REQUIRE(ReadChainBackendMarker(dir, marker));
    BOOST_CHECK_EQUAL(marker, "lmdb");
    BOOST_CHECK(!CheckChainBackendCompatibility(dir, DB_BACKEND_BDB));
    BOOST_CHECK(CheckChainBackendCompatibility(dir, DB_BACKEND_LMDB));

    // Unknown markers are rejected instead of guessing.
    BOOST_REQUIRE(WriteChainBackendMarker(dir, "sqlite"));
    BOOST_CHECK(!CheckChainBackendCompatibility(dir, DB_BACKEND_BDB));
    BOOST_CHECK(!CheckChainBackendCompatibility(dir, DB_BACKEND_LMDB));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    BOOST_REQUIRE(!ec);

    // Legacy LMDB datadirs have no marker; an existing environment is
    // authoritative.
    const std::filesystem::path legacy = MakeTempDir(tag + "_legacy");
    {
        CLMDBDatabase stale;
        BOOST_REQUIRE(stale.Open((legacy / "blkindex").string()));
        WriteValue(stale, Key("canary"), Value("legacy lmdb index"));
        stale.Close();
    }
    BOOST_CHECK(HasLMDBChainIndex(legacy));
    BOOST_CHECK(!CheckChainBackendCompatibility(legacy, DB_BACKEND_BDB));
    BOOST_CHECK(CheckChainBackendCompatibility(legacy, DB_BACKEND_LMDB));

    // A truncated placeholder is an incomplete environment, not an index.
    // Fail closed so a default BDB start cannot silently use a stale
    // blkindex.dat while the user believes the LMDB index is present.
    std::filesystem::resize_file(legacy / "blkindex" / "data.mdb", 0, ec);
    BOOST_REQUIRE(!ec);
    BOOST_CHECK(!HasLMDBChainIndex(legacy));
    BOOST_CHECK(!CheckChainBackendCompatibility(legacy, DB_BACKEND_BDB));
    BOOST_CHECK(!CheckChainBackendCompatibility(legacy, DB_BACKEND_LMDB));

    std::filesystem::remove_all(legacy, ec);
}

CDataStream TestStreamFromBytes(const CDBKey& data)
{
    CDataStream stream(SER_DISK, CLIENT_VERSION);
    if (!data.empty())
        stream.write((const char*)&data[0], data.size());
    return stream;
}

std::string TestDecodeString(const CDBValue& value)
{
    CDataStream stream = TestStreamFromBytes(value);
    std::string decoded;
    stream >> decoded;
    return decoded;
}

/** Test-only access to the protected CDB read/write/scan helpers. */
class WalletDBTestAccess : public CWalletDB
{
public:
    WalletDBTestAccess(const char* file, const char* mode) : CWalletDB(file, mode) {}
    using CDB::Read;
    using CDB::Write;
    using CDB::Erase;
    using CDB::Exists;
    using CDB::GetScan;
};

template <typename DBType>
void RunLargeValueIteration(const std::string &tag)
{
    DBGuard<DBType> guard(tag);

    CDBValue large(20000);
    for (size_t i = 0; i < large.size(); ++i)
        large[i] = static_cast<unsigned char>((i * 31 + 7) & 0xff);
    WriteValue(guard.db, Key("large"), large);

    std::unique_ptr<CDBTransaction> txn = BeginRead(guard.db);
    {
        std::unique_ptr<CDBIterator> it = txn->NewIterator();
        BOOST_REQUIRE(it.get() != nullptr);
        it->SeekToFirst();
        BOOST_REQUIRE(it->Valid());
        BOOST_CHECK(it->Key() == Key("large"));
        BOOST_CHECK(it->Value() == large);
        it->Next();
        BOOST_CHECK(!it->Valid());
    }
    BOOST_REQUIRE_MESSAGE(txn->Commit(), "read transaction commit failed");
}

void RunWalletBackendMarker(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);
    std::string marker;

    BOOST_CHECK(!ReadWalletBackendMarker(dir, marker));
    BOOST_CHECK(!HasLMDBWallet(dir));
    BOOST_CHECK(CheckWalletBackendCompatibility(dir, DB_BACKEND_BDB));
    BOOST_CHECK(CheckWalletBackendCompatibility(dir, DB_BACKEND_LMDB));

    BOOST_REQUIRE(WriteWalletBackendMarker(dir, "bdb"));
    BOOST_REQUIRE(ReadWalletBackendMarker(dir, marker));
    BOOST_CHECK_EQUAL(marker, "bdb");
    BOOST_CHECK(CheckWalletBackendCompatibility(dir, DB_BACKEND_BDB));

    // A bdb marker is authoritative too: even a leftover wallet/ directory
    // must not let an LMDB start adopt the data directory without an explicit
    // migration.
    BOOST_CHECK(!CheckWalletBackendCompatibility(dir, DB_BACKEND_LMDB));
    {
        CLMDBDatabase stale;
        BOOST_REQUIRE(stale.Open((dir / "wallet").string()));
        WriteValue(stale, Key("canary"), Value("stale lmdb wallet"));
        stale.Close();
    }
    BOOST_CHECK(HasLMDBWallet(dir));
    BOOST_CHECK(!CheckWalletBackendCompatibility(dir, DB_BACKEND_LMDB));

    // Switching to LMDB must block a later BDB start.
    BOOST_REQUIRE(WriteWalletBackendMarker(dir, "lmdb"));
    BOOST_REQUIRE(ReadWalletBackendMarker(dir, marker));
    BOOST_CHECK_EQUAL(marker, "lmdb");
    BOOST_CHECK(!CheckWalletBackendCompatibility(dir, DB_BACKEND_BDB));
    BOOST_CHECK(CheckWalletBackendCompatibility(dir, DB_BACKEND_LMDB));

    // Unknown markers are rejected instead of guessing.
    BOOST_REQUIRE(WriteWalletBackendMarker(dir, "sqlite"));
    BOOST_CHECK(!CheckWalletBackendCompatibility(dir, DB_BACKEND_BDB));
    BOOST_CHECK(!CheckWalletBackendCompatibility(dir, DB_BACKEND_LMDB));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    BOOST_REQUIRE(!ec);

    // Legacy LMDB wallets have no marker; an existing environment is
    // authoritative.
    const std::filesystem::path legacy = MakeTempDir(tag + "_legacy");
    {
        CLMDBDatabase stale;
        BOOST_REQUIRE(stale.Open((legacy / "wallet").string()));
        WriteValue(stale, Key("canary"), Value("legacy lmdb wallet"));
        stale.Close();
    }
    BOOST_CHECK(HasLMDBWallet(legacy));
    BOOST_CHECK(!CheckWalletBackendCompatibility(legacy, DB_BACKEND_BDB));
    BOOST_CHECK(CheckWalletBackendCompatibility(legacy, DB_BACKEND_LMDB));

    // An empty or truncated placeholder is an incomplete environment and is
    // rejected for both backends instead of silently falling back to
    // wallet.dat.
    std::filesystem::resize_file(legacy / "wallet" / "data.mdb", 0, ec);
    BOOST_REQUIRE(!ec);
    BOOST_CHECK(!HasLMDBWallet(legacy));
    BOOST_CHECK(!CheckWalletBackendCompatibility(legacy, DB_BACKEND_BDB));
    BOOST_CHECK(!CheckWalletBackendCompatibility(legacy, DB_BACKEND_LMDB));

    std::filesystem::remove_all(legacy, ec);
}

void RunWalletStartupAction(const std::string & /*tag*/)
{
    // Existing LMDB data always wins, regardless of the marker or wallet.dat.
    BOOST_CHECK(GetWalletStartupAction(false, false, false) == WALLET_USE_EXISTING);
    BOOST_CHECK(GetWalletStartupAction(false, false, true) == WALLET_USE_EXISTING);
    BOOST_CHECK(GetWalletStartupAction(true, false, false) == WALLET_USE_EXISTING);
    BOOST_CHECK(GetWalletStartupAction(true, false, true) == WALLET_USE_EXISTING);

    // No marker and an empty LMDB wallet: migrate wallet.dat when present,
    // otherwise create a new wallet.
    BOOST_CHECK(GetWalletStartupAction(false, true, false) == WALLET_INIT_NEW);
    BOOST_CHECK(GetWalletStartupAction(false, true, true) == WALLET_MIGRATE_BDB);

    // A marker saying LMDB is authoritative makes an empty wallet data loss,
    // even when a stale wallet.dat is still lying around.
    BOOST_CHECK(GetWalletStartupAction(true, true, false) == WALLET_FAIL_MISSING);
    BOOST_CHECK(GetWalletStartupAction(true, true, true) == WALLET_FAIL_MISSING);
}

void RunWalletLMDBBackend(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);
    struct Guard {
        std::filesystem::path dir;
        ~Guard() {
            CloseLMDBWalletDB();
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } guard{dir};

    BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));
    BOOST_CHECK(IsLMDBWalletEnabled());

    std::string marker;
    BOOST_REQUIRE(ReadWalletBackendMarker(dir, marker));
    BOOST_CHECK_EQUAL(marker, "lmdb");
    BOOST_CHECK(HasLMDBWallet(dir));

    {
        WalletDBTestAccess db("wallet.dat", "cr+");
        BOOST_CHECK_MESSAGE(db.Write(std::string("probe"), std::string("one")),
                            "wallet write failed");
        std::string value;
        BOOST_REQUIRE(db.Read(std::string("probe"), value));
        BOOST_CHECK_EQUAL(value, "one");
        BOOST_CHECK(db.Exists(std::string("probe")));
    }

    {
        // An aborted transaction must not become visible.
        WalletDBTestAccess db("wallet.dat", "r+");
        BOOST_REQUIRE(db.TxnBegin());
        BOOST_CHECK(db.Write(std::string("aborted"), std::string("no")));
        BOOST_REQUIRE(db.TxnAbort());
        BOOST_CHECK(!db.Exists(std::string("aborted")));
    }

    {
        WalletDBTestAccess db("wallet.dat", "r+");
        BOOST_REQUIRE(db.TxnBegin());
        BOOST_CHECK(db.Write(std::string("committed"), std::string("yes")));
        BOOST_REQUIRE(db.TxnCommit());
    }

    {
        WalletDBTestAccess db("wallet.dat", "r");
        CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
        ssPrefix << std::string("probe");
        std::unique_ptr<CDBScan> scan =
            db.GetScan(CDBKey(ssPrefix.begin(), ssPrefix.end()));
        BOOST_REQUIRE(scan.get() != nullptr);
        scan->SeekToFirst();
        BOOST_REQUIRE(scan->Valid());
        BOOST_CHECK(scan->Key() == CDBKey(ssPrefix.begin(), ssPrefix.end()));
        BOOST_CHECK_EQUAL(TestDecodeString(scan->Value()), "one");
        scan->Next();
        BOOST_CHECK(!scan->Valid());
    }

    // The records must survive closing and reopening the environment.
    CloseLMDBWalletDB();
    BOOST_CHECK(!IsLMDBWalletEnabled());
    BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));
    {
        WalletDBTestAccess db("wallet.dat", "r");
        std::string value;
        BOOST_REQUIRE(db.Read(std::string("probe"), value));
        BOOST_CHECK_EQUAL(value, "one");
        BOOST_REQUIRE(db.Read(std::string("committed"), value));
        BOOST_CHECK_EQUAL(value, "yes");
        BOOST_CHECK(!db.Exists(std::string("aborted")));
    }
    {
        WalletDBTestAccess db("wallet.dat", "r+");
        BOOST_CHECK(db.Erase(std::string("probe")));
    }
    {
        WalletDBTestAccess db("wallet.dat", "r");
        BOOST_CHECK(!db.Exists(std::string("probe")));
    }
}

void RunLMDBEnvironmentStats(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);
    struct Guard {
        std::filesystem::path dir;
        ~Guard() {
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } guard{dir};

    const size_t nMapSize = 8 * 1024 * 1024;
    CLMDBEnv env;
    BOOST_REQUIRE(env.Open(dir.string(), true, nMapSize, true));
    CLMDBDatabase db;
    BOOST_REQUIRE(db.Open(env, "main", true));

    CLMDBStats envStats;
    BOOST_REQUIRE(env.GetStats(envStats));
    BOOST_CHECK(envStats.fOpen);
    BOOST_CHECK(!envStats.fReadOnly);
    BOOST_CHECK(envStats.fNoSync);
    BOOST_CHECK(!envStats.fWriterActive);
    BOOST_CHECK(envStats.fAutoGrow);
    BOOST_CHECK_EQUAL(envStats.nMapSize, nMapSize);
    BOOST_CHECK_GE(envStats.nMaxMapSize, envStats.nMapSize);
    BOOST_CHECK_GT(envStats.nPageSize, 0U);
    BOOST_CHECK_GT(envStats.nUsedBytes, 0U);
    BOOST_CHECK_LT(envStats.nFreeBytes, envStats.nMapSize);
    BOOST_CHECK_GE(envStats.nUtilization, 0.0);
    BOOST_CHECK_LE(envStats.nUtilization, 100.0);
    BOOST_CHECK_GT(envStats.nMaxReaders, 0U);

    CLMDBDBStats dbStats;
    BOOST_REQUIRE(db.GetStats(dbStats));
    BOOST_CHECK(dbStats.fOpen);
    BOOST_CHECK_EQUAL(dbStats.nEntries, 0U);
    BOOST_CHECK_GT(dbStats.nPageSize, 0U);

    {
        std::unique_ptr<CDBTransaction> txn = db.BeginTransaction(false);
        BOOST_REQUIRE(txn);
        BOOST_CHECK(txn->Write(Key("one"), Value("1")));
        BOOST_CHECK(txn->Write(Key("two"), Value("2")));
        BOOST_CHECK(txn->Write(Key("three"), Value("3")));

        // The writer slot is part of the transaction state diagnostics.
        BOOST_REQUIRE(env.GetStats(envStats));
        BOOST_CHECK(envStats.fWriterActive);

        BOOST_REQUIRE(txn->Commit());
    }

    BOOST_REQUIRE(env.GetStats(envStats));
    BOOST_CHECK(!envStats.fWriterActive);
    BOOST_REQUIRE(db.GetStats(dbStats));
    BOOST_CHECK_EQUAL(dbStats.nEntries, 3U);
    BOOST_CHECK_GE(dbStats.nDepth, 1U);
    BOOST_CHECK_GE(dbStats.nLeafPages, 1U);

    db.Close();
    env.Close();
    BOOST_CHECK(!env.GetStats(envStats));
    BOOST_CHECK(!db.GetStats(dbStats));

    // Reopening read-only must report the mode and still expose the pages.
    CLMDBEnv ro;
    BOOST_REQUIRE(ro.Open(dir.string(), false, nMapSize, false,
                          "-lmdbmapsize", true));
    BOOST_REQUIRE(ro.GetStats(envStats));
    BOOST_CHECK(envStats.fReadOnly);
    BOOST_CHECK(!envStats.fNoSync);
    BOOST_CHECK(!envStats.fAutoGrow);
    BOOST_CHECK_EQUAL(envStats.nMaxMapSize, envStats.nMapSize);

    MDB_dbi dbi = 0;
    BOOST_REQUIRE(ro.OpenDbi("main", dbi, false));
    BOOST_REQUIRE(ro.GetDbStats(dbi, dbStats));
    BOOST_CHECK_EQUAL(dbStats.nEntries, 3U);
    ro.Close();
}

CDBKey NumberedKey(const char *prefix, unsigned int n)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s-%06u", prefix, n);
    return Key(buf);
}

void RunLMDBRuntimeGrowth(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);
    struct Guard {
        std::filesystem::path dir;
        ~Guard() {
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } guard{dir};

    const size_t nMiB = 1024ULL * 1024ULL;
    const size_t nInitial = 1 * nMiB;
    const size_t nMax = 8 * nMiB;

    CLMDBEnv env;
    BOOST_REQUIRE_MESSAGE(
        env.Open(dir.string(), true, nInitial, true, "-lmdbmapsize", false,
                  nMax, true),
        "could not open small LMDB environment");
    CLMDBDatabase db;
    BOOST_REQUIRE(db.Open(env, "main", true));

    CLMDBStats stats;
    BOOST_REQUIRE(env.GetStats(stats));
    BOOST_CHECK(stats.fAutoGrow);
    BOOST_CHECK_EQUAL(stats.nMaxMapSize, nMax);
    BOOST_CHECK_EQUAL(stats.nMapSize, nInitial);

    // Seed committed records so replay can be checked against a non-empty
    // environment.
    WriteValue(db, Key("keep"), Value("before"));
    WriteValue(db, Key("erase-me"), Value("old"));
    WriteValue(db, Key("dup"), Value("first"));

    std::unique_ptr<CDBTransaction> txn = BeginWrite(db);
    BOOST_REQUIRE(txn->Write(Key("keep"), Value("after")));
    BOOST_REQUIRE(txn->Erase(Key("erase-me")));

    // A failed no-overwrite write must not be replayed as a successful one.
    BOOST_CHECK(!txn->Write(Key("dup"), Value("second"), false));

    const CDBValue large(48 * 1024, 'x');
    bool fGrew = false;
    for (unsigned int i = 0; i < 512; ++i) {
        BOOST_REQUIRE(txn->Write(NumberedKey("bulk", i), large));
        BOOST_REQUIRE(env.GetStats(stats));
        if (stats.nMapSize > nInitial) {
            fGrew = true;
            break;
        }
    }
    BOOST_REQUIRE_MESSAGE(fGrew, "LMDB map did not grow on MDB_MAP_FULL");
    BOOST_CHECK_LE(stats.nMapSize, nMax);
    BOOST_CHECK_GT(stats.nPageSize, 0U);
    BOOST_CHECK_EQUAL(stats.nMapSize % stats.nPageSize, 0U);
    BOOST_CHECK_EQUAL(stats.nMaxMapSize % stats.nPageSize, 0U);

    // The transaction continues after replay; writes made after growth commit
    // together with every replayed record.
    BOOST_REQUIRE(txn->Write(Key("after-growth"), Value("ok")));
    BOOST_REQUIRE(txn->Commit());

    CDBValue value;
    BOOST_REQUIRE(ReadValue(db, Key("keep"), value));
    BOOST_CHECK(value == Value("after"));
    BOOST_REQUIRE(ReadValue(db, Key("after-growth"), value));
    BOOST_CHECK(value == Value("ok"));
    BOOST_REQUIRE(ReadValue(db, Key("dup"), value));
    BOOST_CHECK(value == Value("first"));
    BOOST_CHECK(!ReadValue(db, Key("erase-me"), value));
    BOOST_REQUIRE(ReadValue(db, Key("bulk-000000"), value));
    BOOST_CHECK(value == large);

    BOOST_REQUIRE(env.GetStats(stats));
    BOOST_CHECK_EQUAL(stats.fWriterActive, false);

    db.Close();
    env.Close();
}

void RunLMDBRuntimeGrowthMaximum(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);
    struct Guard {
        std::filesystem::path dir;
        ~Guard() {
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } guard{dir};

    const size_t nMiB = 1024ULL * 1024ULL;
    const size_t nInitial = 1 * nMiB;
    const size_t nMax = 2 * nMiB;

    CLMDBEnv env;
    BOOST_REQUIRE(env.Open(dir.string(), true, nInitial, true,
                           "-lmdbmapsize", false, nMax, true));
    CLMDBDatabase db;
    BOOST_REQUIRE(db.Open(env, "main", true));

    std::unique_ptr<CDBTransaction> txn = BeginWrite(db);
    const CDBValue large(64 * 1024, 'y');
    bool fFailed = false;
    for (unsigned int i = 0; i < 512; ++i) {
        if (!txn->Write(NumberedKey("exhaust", i), large)) {
            fFailed = true;
            break;
        }
    }
    BOOST_REQUIRE_MESSAGE(fFailed, "writes did not fail at the growth ceiling");

    // A failed growth aborts the transaction; nothing it wrote may become
    // visible, even records written before the first MDB_MAP_FULL.
    txn->Abort();

    CLMDBStats stats;
    BOOST_REQUIRE(env.GetStats(stats));
    BOOST_CHECK_EQUAL(stats.nMapSize, nMax);
    BOOST_CHECK_EQUAL(stats.nMaxMapSize, nMax);
    BOOST_CHECK_EQUAL(stats.nMapSize % stats.nPageSize, 0U);

    CDBValue value;
    BOOST_CHECK(!ReadValue(db, NumberedKey("exhaust", 0), value));
    BOOST_CHECK(!ReadValue(db, NumberedKey("exhaust", 1), value));

    db.Close();
    env.Close();
}

void RunLMDBFixedMapSize(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);
    struct Guard {
        std::filesystem::path dir;
        ~Guard() {
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } guard{dir};

    const size_t nMapSize = 1 * 1024ULL * 1024ULL;

    CLMDBEnv env;
    // fAutoGrow=false ignores the maximum and fixes the map at nMapSize.
    BOOST_REQUIRE(env.Open(dir.string(), true, nMapSize, true,
                           "-lmdbmapsize", false, 8 * 1024ULL * 1024ULL,
                           false));
    CLMDBDatabase db;
    BOOST_REQUIRE(db.Open(env, "main", true));

    CLMDBStats stats;
    BOOST_REQUIRE(env.GetStats(stats));
    BOOST_CHECK(!stats.fAutoGrow);
    BOOST_CHECK_EQUAL(stats.nMapSize, nMapSize);
    BOOST_CHECK_EQUAL(stats.nMaxMapSize, nMapSize);

    std::unique_ptr<CDBTransaction> txn = BeginWrite(db);
    const CDBValue large(64 * 1024, 'z');
    bool fFailed = false;
    for (unsigned int i = 0; i < 512; ++i) {
        if (!txn->Write(NumberedKey("fixed", i), large)) {
            fFailed = true;
            break;
        }
    }
    BOOST_REQUIRE(fFailed);
    txn->Abort();

    BOOST_REQUIRE(env.GetStats(stats));
    BOOST_CHECK_EQUAL(stats.nMapSize, nMapSize);

    db.Close();
    env.Close();
}

void RunLMDBMapSizeResolution(const std::string & /*tag*/)
{
    size_t nMapSize = 0;
    size_t nMaxMapSize = 0;
    std::string strError;

    BOOST_REQUIRE(ResolveLMDBMapSizes("64", "4096", 1024, true,
                                      nMapSize, nMaxMapSize, strError));
    BOOST_CHECK_EQUAL(nMapSize, 64ULL * 1024ULL * 1024ULL);
    BOOST_CHECK_EQUAL(nMaxMapSize, 4096ULL * 1024ULL * 1024ULL);

    // Empty values select the supplied initial default and the build ceiling.
    BOOST_REQUIRE(ResolveLMDBMapSizes("", "", 1024, true,
                                      nMapSize, nMaxMapSize, strError));
    BOOST_CHECK_EQUAL(nMapSize, 1024ULL * 1024ULL * 1024ULL);
    BOOST_CHECK_EQUAL(nMaxMapSize,
                      static_cast<size_t>(GetLMDBDefaultMaxMapSizeMiB()) *
                      1024ULL * 1024ULL);

    // Disabling runtime growth makes the initial map the fixed limit.
    BOOST_REQUIRE(ResolveLMDBMapSizes("128", "4096", 1024, false,
                                      nMapSize, nMaxMapSize, strError));
    BOOST_CHECK_EQUAL(nMapSize, 128ULL * 1024ULL * 1024ULL);
    BOOST_CHECK_EQUAL(nMaxMapSize, nMapSize);

    // A ceiling below the initial size is a configuration error.
    BOOST_CHECK(!ResolveLMDBMapSizes("512", "256", 1024, true,
                                     nMapSize, nMaxMapSize, strError));
    BOOST_CHECK(!strError.empty());

    BOOST_CHECK(!ResolveLMDBMapSizes("512", "not-a-number", 1024, true,
                                     nMapSize, nMaxMapSize, strError));
}

void RunWalletLMDBDiagnostics(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);
    struct Guard {
        std::filesystem::path dir;
        ~Guard() {
            CloseLMDBWalletDB();
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } guard{dir};

    BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));

    DBDiagnostics diag = GetDBDiagnostics(dir, dir);
    BOOST_CHECK_EQUAL(diag.wallet.strRole, "wallet");
    BOOST_CHECK_EQUAL(diag.wallet.strActiveBackend, "lmdb");
    BOOST_CHECK(diag.wallet.fLMDBEnabled);
    BOOST_CHECK(diag.wallet.fOpenedCleanly);
    BOOST_CHECK(diag.wallet.fEnvironmentOpen);
    BOOST_CHECK(diag.wallet.fDatabaseOpen);
    BOOST_CHECK(diag.wallet.fMarkerPresent);
    BOOST_CHECK_EQUAL(diag.wallet.strMarker, "lmdb");
    BOOST_CHECK(diag.wallet.fMarkerMatchesBackend);
    BOOST_CHECK(diag.wallet.strError.empty());
    BOOST_CHECK_EQUAL(diag.wallet.strPath, (dir / "wallet").string());
    BOOST_CHECK_GT(diag.wallet.env.nMapSize, 0U);
    BOOST_CHECK_GT(diag.wallet.env.nPageSize, 0U);
    BOOST_CHECK_GT(diag.wallet.env.nUsedBytes, 0U);
    BOOST_CHECK_GE(diag.wallet.env.nUtilization, 0.0);
    BOOST_CHECK_LE(diag.wallet.env.nUtilization, 100.0);
    BOOST_CHECK_GT(diag.wallet.db.nPageSize, 0U);

    const size_t nBefore = diag.wallet.db.nEntries;
    {
        WalletDBTestAccess db("wallet.dat", "cr+");
        BOOST_CHECK(db.Write(std::string("diagnostic-probe"), std::string("1")));
    }
    diag = GetDBDiagnostics(dir, dir);
    BOOST_CHECK_GT(diag.wallet.db.nEntries, nBefore);

    // A BDB chain backend is reported without LMDB environment counters.
    if (!IsLMDBChainEnabled()) {
        BOOST_CHECK_EQUAL(diag.chain.strActiveBackend, "bdb");
        BOOST_CHECK(!diag.chain.fLMDBEnabled);
        BOOST_CHECK(diag.chain.fOpenedCleanly);
        BOOST_CHECK_EQUAL(diag.chain.env.nMapSize, 0U);
    }

    // Closing the environment must show up as a problem instead of
    // pretending the wallet is still healthy.
    CloseLMDBWalletDB();
    diag = GetDBDiagnostics(dir, dir);
    BOOST_CHECK(!diag.wallet.fLMDBEnabled);
    BOOST_CHECK(!diag.wallet.fEnvironmentOpen);
    BOOST_CHECK(!diag.wallet.fDatabaseOpen);
    BOOST_CHECK(!diag.wallet.fMarkerMatchesBackend);
}

void RunWalletLMDBStartupRefusal(const std::string &tag)
{
    struct Guard {
        ~Guard() { CloseLMDBWalletDB(); }
    } guard;

    {
        // A marker that says LMDB is authoritative must not fall back to an
        // empty wallet.
        const std::filesystem::path dir = MakeTempDir(tag + "_missing");
        BOOST_REQUIRE(WriteWalletBackendMarker(dir, "lmdb"));
        BOOST_CHECK(!InitLMDBWalletDBForTest(dir));
        BOOST_CHECK(!IsLMDBWalletEnabled());

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
}

// Regression: an existing wallet.dat is copied into an empty LMDB wallet
// before wallet.backend is written.  The test uses the mocked Berkeley DB
// environment for the source records and a temporary directory for the LMDB
// side, so it never touches the configured data directory.
void RunWalletLMDBMigration(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);
    struct Guard {
        std::filesystem::path dir;
        ~Guard() {
            CloseLMDBWalletDB();
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } guard{dir};

    CloseLMDBWalletDB();
    BOOST_REQUIRE(!IsLMDBWalletEnabled());

    {
        // Records in the Berkeley DB wallet that startup must carry over.
        WalletDBTestAccess db("wallet.dat", "cr+");
        BOOST_REQUIRE(db.Write(std::string("migration-probe"),
                               std::string("value")));
    }
    {
        // InitLMDBWalletDB() only migrates when wallet.dat exists on disk.
        std::ofstream wallet(dir / "wallet.dat", std::ios::trunc);
        BOOST_REQUIRE(wallet.good());
        wallet << "berkeley db wallet";
    }

    BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));
    BOOST_CHECK(IsLMDBWalletEnabled());

    std::string marker;
    BOOST_REQUIRE(ReadWalletBackendMarker(dir, marker));
    BOOST_CHECK_EQUAL(marker, "lmdb");
    BOOST_CHECK(HasLMDBWallet(dir));

    // The Berkeley DB file is the migration source and must survive untouched.
    BOOST_CHECK(std::filesystem::exists(dir / "wallet.dat"));

    {
        WalletDBTestAccess db("wallet.dat", "r");
        std::string value;
        BOOST_REQUIRE(db.Read(std::string("migration-probe"), value));
        BOOST_CHECK_EQUAL(value, "value");
    }

    // A restart must use the populated LMDB wallet, not migrate again.
    CloseLMDBWalletDB();
    BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));
    BOOST_CHECK(IsLMDBWalletEnabled());
    {
        WalletDBTestAccess db("wallet.dat", "r");
        std::string value;
        BOOST_REQUIRE(db.Read(std::string("migration-probe"), value));
        BOOST_CHECK_EQUAL(value, "value");
    }

    // A crash after the transaction commits but before the marker is written
    // must adopt the populated LMDB wallet, not re-import stale wallet.dat.
    CloseLMDBWalletDB();
    {
        std::error_code ec;
        BOOST_REQUIRE(std::filesystem::remove(dir / "wallet.backend", ec));
        BOOST_REQUIRE(!ec);
    }
    BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));
    BOOST_CHECK(IsLMDBWalletEnabled());
    BOOST_REQUIRE(ReadWalletBackendMarker(dir, marker));
    BOOST_CHECK_EQUAL(marker, "lmdb");
    {
        WalletDBTestAccess db("wallet.dat", "r");
        std::string value;
        BOOST_REQUIRE(db.Read(std::string("migration-probe"), value));
        BOOST_CHECK_EQUAL(value, "value");
    }
}

// Regression: wallet.backend is authoritative in both directions.  A bdb
// marker must refuse -walletbackend=lmdb even when a leftover wallet/
// contains a real LMDB environment, otherwise a stale environment could be
// adopted and the marker silently rewritten to lmdb.
void RunWalletBDBMarkerAuthority(const std::string &tag)
{
    struct Guard {
        ~Guard() { CloseLMDBWalletDB(); }
    } guard;

    {
        // The marker alone is enough, even with an empty wallet/ directory.
        const std::filesystem::path dir = MakeTempDir(tag + "_dir");
        BOOST_REQUIRE(WriteWalletBackendMarker(dir, "bdb"));
        BOOST_REQUIRE(std::filesystem::create_directories(dir / "wallet"));

        BOOST_CHECK(!CheckWalletBackendCompatibility(dir, DB_BACKEND_LMDB));
        BOOST_CHECK(!InitLMDBWalletDBForTest(dir));
        BOOST_CHECK(!IsLMDBWalletEnabled());

        std::string marker;
        BOOST_REQUIRE(ReadWalletBackendMarker(dir, marker));
        BOOST_CHECK_EQUAL(marker, "bdb");

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    {
        // Full reported scenario: bdb marker, an existing wallet.dat, and a
        // real LMDB environment left in wallet/.
        const std::filesystem::path dir = MakeTempDir(tag + "_stale");
        BOOST_REQUIRE(WriteWalletBackendMarker(dir, "bdb"));
        {
            std::ofstream wallet(dir / "wallet.dat", std::ios::trunc);
            BOOST_REQUIRE(wallet.good());
            wallet << "berkeley db wallet";
        }
        {
            CLMDBDatabase stale;
            BOOST_REQUIRE(stale.Open((dir / "wallet").string()));
            WriteValue(stale, Key("canary"), Value("stale lmdb wallet"));
            stale.Close();
        }
        BOOST_REQUIRE(HasLMDBWallet(dir));

        BOOST_CHECK(!InitLMDBWalletDBForTest(dir));
        BOOST_CHECK(!IsLMDBWalletEnabled());

        std::string marker;
        BOOST_REQUIRE(ReadWalletBackendMarker(dir, marker));
        BOOST_CHECK_EQUAL(marker, "bdb");

        // The stale environment was neither adopted nor modified.
        {
            CLMDBDatabase stale;
            BOOST_REQUIRE(stale.Open((dir / "wallet").string()));
            CDBValue value;
            BOOST_REQUIRE(ReadValue(stale, Key("canary"), value));
            BOOST_CHECK(value == Value("stale lmdb wallet"));
            stale.Close();
        }

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
}

// The rewrite failure tests exercise the filesystem steps of
// RewriteWalletLMDB() explicitly.  The live wallet is a real LMDB environment
// rooted at a temporary directory; wallet.dat must never appear as a Berkeley
// DB file, because that would mean a failed rewrite silently changed backends.
class WalletRewriteHarness
{
public:
    explicit WalletRewriteHarness(const std::string &tag)
        : dir(MakeTempDir(tag))
    {
    }

    ~WalletRewriteHarness()
    {
        ClearTestWalletRewriteFailures();
        CloseLMDBWalletDB();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    void Setup()
    {
        ClearTestWalletRewriteFailures();
        BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));
        BOOST_REQUIRE(IsLMDBWalletEnabled());
        WalletDBTestAccess db("wallet.dat", "cr+");
        BOOST_REQUIRE(db.Write(std::string("rewrite-base"), std::string("one")));
    }

    const std::filesystem::path &Dir() const { return dir; }

    void ExpectLMDBMarker() const
    {
        std::string marker;
        BOOST_REQUIRE(ReadWalletBackendMarker(dir, marker));
        BOOST_CHECK_EQUAL(marker, "lmdb");
    }

    void ExpectNoBDBWallet() const
    {
        BOOST_CHECK(!std::filesystem::exists(dir / "wallet.dat"));
    }

    std::string Read(const std::string &key) const
    {
        WalletDBTestAccess db("wallet.dat", "r");
        std::string value;
        BOOST_REQUIRE_MESSAGE(db.Read(key, value), "cannot read " << key);
        return value;
    }

    void Write(const std::string &key, const std::string &value)
    {
        WalletDBTestAccess db("wallet.dat", "r+");
        BOOST_CHECK_MESSAGE(db.Write(key, value), "cannot write " << key);
    }

    bool TryWrite(const std::string &key, const std::string &value)
    {
        WalletDBTestAccess db("wallet.dat", "r+");
        return db.Write(key, value);
    }

    void Reopen()
    {
        CloseLMDBWalletDB();
        BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));
        BOOST_CHECK(IsLMDBWalletEnabled());
        ExpectLMDBMarker();
    }

    void ArmFailingRewrite()
    {
        ClearTestWalletRewriteFailures();
        SetTestWalletRewriteAbort(true);
    }

private:
    std::filesystem::path dir;
};

// A. Moving wallet/ to wallet.old fails.  Nothing has moved yet, so the
// original environment must be reopened and stay authoritative.
void RunWalletRewriteRenameOldFailure(const std::string &tag)
{
    WalletRewriteHarness h(tag);
    h.Setup();
    h.ArmFailingRewrite();
    SetTestWalletRewriteFailure("wallet-rewrite-rename-old");

    BOOST_CHECK(!CDB::Rewrite("wallet.dat"));
    BOOST_CHECK(!TestWalletRewriteAborted());
    BOOST_CHECK(IsLMDBWalletEnabled());
    h.ExpectLMDBMarker();
    BOOST_CHECK(std::filesystem::exists(h.Dir() / "wallet"));
    BOOST_CHECK(!std::filesystem::exists(h.Dir() / "wallet.old"));
    BOOST_CHECK(!std::filesystem::exists(h.Dir() / "wallet.rewrite"));
    h.ExpectNoBDBWallet();

    BOOST_CHECK_EQUAL(h.Read("rewrite-base"), "one");

    // A write after the failure must go to LMDB, not Berkeley DB.
    h.Write("rewrite-after-rename-old", "lmdb");
    h.ExpectNoBDBWallet();
    h.Reopen();
    BOOST_CHECK_EQUAL(h.Read("rewrite-base"), "one");
    BOOST_CHECK_EQUAL(h.Read("rewrite-after-rename-old"), "lmdb");
}

// B. Installing wallet.rewrite as wallet/ fails.  The old environment must
// be restored and reopened, not left in wallet.old.
void RunWalletRewriteInstallFailure(const std::string &tag)
{
    WalletRewriteHarness h(tag);
    h.Setup();
    h.ArmFailingRewrite();
    SetTestWalletRewriteFailure("wallet-rewrite-install");

    BOOST_CHECK(!CDB::Rewrite("wallet.dat"));
    BOOST_CHECK(!TestWalletRewriteAborted());
    BOOST_CHECK(IsLMDBWalletEnabled());
    h.ExpectLMDBMarker();
    BOOST_CHECK(std::filesystem::exists(h.Dir() / "wallet"));
    BOOST_CHECK(!std::filesystem::exists(h.Dir() / "wallet.old"));
    BOOST_CHECK(!std::filesystem::exists(h.Dir() / "wallet.rewrite"));
    h.ExpectNoBDBWallet();

    BOOST_CHECK_EQUAL(h.Read("rewrite-base"), "one");

    h.Write("rewrite-after-install", "lmdb");
    h.ExpectNoBDBWallet();
    h.Reopen();
    BOOST_CHECK_EQUAL(h.Read("rewrite-base"), "one");
    BOOST_CHECK_EQUAL(h.Read("rewrite-after-install"), "lmdb");
}

// C. The compacted environment is installed but cannot be reopened.  The
// rewrite may roll back to the old environment, or stop; it must never let
// the process continue with Berkeley DB writes.
void RunWalletRewriteReopenFailure(const std::string &tag)
{
    WalletRewriteHarness h(tag);
    h.Setup();

    // The installed copy cannot be opened: wallet.old is restored and
    // reopened, so LMDB stays usable.
    h.ArmFailingRewrite();
    SetTestWalletRewriteFailure("wallet-rewrite-reopen-installed");

    BOOST_CHECK(!CDB::Rewrite("wallet.dat"));
    BOOST_CHECK(!TestWalletRewriteAborted());
    BOOST_CHECK(IsLMDBWalletEnabled());
    h.ExpectLMDBMarker();
    BOOST_CHECK(std::filesystem::exists(h.Dir() / "wallet"));
    BOOST_CHECK(!std::filesystem::exists(h.Dir() / "wallet.old"));
    BOOST_CHECK(!std::filesystem::exists(h.Dir() / "wallet.rewrite"));
    h.ExpectNoBDBWallet();

    BOOST_CHECK_EQUAL(h.Read("rewrite-base"), "one");
    h.Write("rewrite-after-reopen-fallback", "lmdb");
    h.Reopen();
    BOOST_CHECK_EQUAL(h.Read("rewrite-after-reopen-fallback"), "lmdb");

    // Neither the installed copy nor the restored copy can be reopened: no
    // usable environment remains, so the rewrite must stop.  The wallet marker
    // stays lmdb, writes fail instead of reaching Berkeley DB, and startup
    // recovers the staged copy.
    h.ArmFailingRewrite();
    SetTestWalletRewriteFailure("wallet-rewrite-reopen-installed");
    SetTestWalletRewriteFailure("wallet-rewrite-reopen-restored");

    BOOST_CHECK(!CDB::Rewrite("wallet.dat"));
    BOOST_CHECK(TestWalletRewriteAborted());
    BOOST_CHECK(IsLMDBWalletEnabled());
    h.ExpectLMDBMarker();
    BOOST_CHECK(!h.TryWrite("bdb-fallback", "must-not-happen"));
    h.ExpectNoBDBWallet();

    h.Reopen();
    BOOST_CHECK(!std::filesystem::exists(h.Dir() / "wallet.rewrite"));
    BOOST_CHECK(!std::filesystem::exists(h.Dir() / "wallet.old"));
    BOOST_CHECK_EQUAL(h.Read("rewrite-base"), "one");
    BOOST_CHECK_EQUAL(h.Read("rewrite-after-reopen-fallback"), "lmdb");
}

// The compacted copy is installed and active, but the old plaintext copy
// cannot be removed.  The rewrite reports failure while leaving LMDB usable;
// startup recovery removes the leftover copy.
void RunWalletRewriteCleanupFailure(const std::string &tag)
{
    WalletRewriteHarness h(tag);
    h.Setup();
    h.ArmFailingRewrite();
    SetTestWalletRewriteFailure("wallet-rewrite-remove-old");

    BOOST_CHECK(!CDB::Rewrite("wallet.dat"));
    BOOST_CHECK(!TestWalletRewriteAborted());
    BOOST_CHECK(IsLMDBWalletEnabled());
    h.ExpectLMDBMarker();
    BOOST_CHECK(std::filesystem::exists(h.Dir() / "wallet"));
    BOOST_CHECK(std::filesystem::exists(h.Dir() / "wallet.old"));
    h.ExpectNoBDBWallet();

    BOOST_CHECK_EQUAL(h.Read("rewrite-base"), "one");
    h.Write("rewrite-after-cleanup-failure", "lmdb");
    h.Reopen();
    BOOST_CHECK(!std::filesystem::exists(h.Dir() / "wallet.old"));
    BOOST_CHECK_EQUAL(h.Read("rewrite-after-cleanup-failure"), "lmdb");
}

// Offline verification backs both backup integrity checks and -checklmdb.  It
// must reject every incomplete environment without modifying it, and accept a
// complete one with or without a full record scan.
void RunLMDBEnvironmentVerify(const std::string &tag)
{
    const std::filesystem::path root = MakeTempDir(tag);
    struct Guard {
        std::filesystem::path dir;
        ~Guard() {
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } guard{root};

    CLMDBVerifyResult verify;

    // A missing directory and a path that is a regular file are not
    // environments.
    BOOST_CHECK(!VerifyLMDBEnvironment((root / "missing").string(), false, verify));
    BOOST_CHECK(!verify.fDirectoryExists);
    BOOST_CHECK(!verify.strError.empty());

    {
        std::ofstream file(root / "not-a-directory", std::ios::trunc);
        BOOST_REQUIRE(file.good());
        file << "x";
    }
    BOOST_CHECK(!VerifyLMDBEnvironment((root / "not-a-directory").string(),
                                       false, verify));
    BOOST_CHECK(!verify.fDirectoryExists);

    // An empty directory has no data.mdb.
    const std::filesystem::path empty = root / "empty";
    BOOST_REQUIRE(std::filesystem::create_directories(empty));
    BOOST_CHECK(!VerifyLMDBEnvironment(empty.string(), false, verify));
    BOOST_CHECK(verify.fDirectoryExists);
    BOOST_CHECK(!verify.fDataFileExists);
    BOOST_CHECK(!verify.fOpened);

    // A data.mdb shorter than the two LMDB meta pages is rejected before LMDB
    // maps it.
    const std::filesystem::path small = root / "small";
    BOOST_REQUIRE(std::filesystem::create_directories(small));
    {
        std::ofstream data(small / "data.mdb", std::ios::trunc);
        BOOST_REQUIRE(data.good());
        data << "not an lmdb environment";
    }
    BOOST_CHECK(!VerifyLMDBEnvironment(small.string(), false, verify));
    BOOST_CHECK(verify.fDataFileExists);
    BOOST_CHECK(!verify.fDataFileSizeSane);
    BOOST_CHECK(!verify.fOpened);

    // Build a real environment with a few records, then copy it without
    // lock.mdb exactly as a compacted backup would look.
    const std::filesystem::path source = root / "source";
    const size_t nMapSize = 8 * 1024 * 1024;
    {
        CLMDBEnv env;
        BOOST_REQUIRE(env.Open(source.string(), true, nMapSize, true));
        CLMDBDatabase db;
        BOOST_REQUIRE(db.Open(env, "main", true));
        {
            std::unique_ptr<CDBTransaction> txn = db.BeginTransaction(false);
            BOOST_REQUIRE(txn);
            BOOST_CHECK(txn->Write(Key("one"), Value("1")));
            BOOST_CHECK(txn->Write(Key("two"), Value("2")));
            BOOST_CHECK(txn->Write(Key("three"), Value("3")));
            BOOST_REQUIRE(txn->Commit());
        }
        db.Close();
        env.Close();
    }

    const std::filesystem::path backup = root / "backup";
    std::error_code ec;
    std::filesystem::copy(source, backup,
                          std::filesystem::copy_options::recursive, ec);
    BOOST_REQUIRE(!ec);
    std::filesystem::remove(backup / "lock.mdb", ec);
    BOOST_REQUIRE(!ec);

    BOOST_CHECK(VerifyLMDBEnvironment(backup.string(), false, verify));
    BOOST_CHECK(verify.fDirectoryExists);
    BOOST_CHECK(verify.fDataFileExists);
    BOOST_CHECK(!verify.fLockFileExists);
    BOOST_CHECK(verify.fDataFileSizeSane);
    BOOST_CHECK(verify.fOpened);
    BOOST_CHECK(verify.fMainDatabase);
    BOOST_CHECK(verify.fComplete);
    BOOST_CHECK(verify.fRecordsReadable);
    BOOST_CHECK_EQUAL(verify.nEntries, 3U);
    BOOST_CHECK_GT(verify.nPageSize, 0U);
    BOOST_CHECK_GT(verify.nRequiredBytes, 0U);
    BOOST_CHECK_GE(verify.nDataFileBytes, verify.nRequiredBytes);
    BOOST_CHECK(verify.strError.empty());

    // MDB_NOLOCK verification must not create lock.mdb in the backup.
    BOOST_CHECK(!std::filesystem::exists(backup / "lock.mdb"));

    // A full scan reads every record and reports the same entry count and
    // transaction as the metadata-only check.
    CLMDBVerifyResult deep;
    BOOST_CHECK(VerifyLMDBEnvironment(backup.string(), true, deep));
    BOOST_CHECK(deep.fFullScan);
    BOOST_CHECK(deep.fRecordsReadable);
    BOOST_CHECK_EQUAL(deep.nEntries, 3U);
    BOOST_CHECK_EQUAL(deep.nLastTxnId, verify.nLastTxnId);

    // Truncating the data file below the last page the meta page refers to is
    // detected even when both meta pages are still present.
    const std::filesystem::path truncated = root / "truncated";
    std::filesystem::copy(backup, truncated,
                          std::filesystem::copy_options::recursive, ec);
    BOOST_REQUIRE(!ec);
    const uintmax_t nMetaBytes =
        2ULL * (GetSystemPageSize() > 0 ? GetSystemPageSize() : 4096ULL);
    const uintmax_t nCut =
        std::filesystem::file_size(truncated / "data.mdb", ec);
    BOOST_REQUIRE(!ec);
    BOOST_REQUIRE_GT(nCut, nMetaBytes);
    std::filesystem::resize_file(truncated / "data.mdb", nMetaBytes, ec);
    BOOST_REQUIRE(!ec);
    BOOST_CHECK(!VerifyLMDBEnvironment(truncated.string(), false, verify));
    BOOST_CHECK(verify.fOpened);
    BOOST_CHECK_GT(verify.nRequiredBytes, verify.nDataFileBytes);
    BOOST_CHECK(!verify.fComplete);

    // Zeroed meta pages are not a valid LMDB file.
    const std::filesystem::path corrupt = root / "corrupt";
    std::filesystem::copy(backup, corrupt,
                          std::filesystem::copy_options::recursive, ec);
    BOOST_REQUIRE(!ec);
    {
        std::fstream data(corrupt / "data.mdb",
                          std::ios::in | std::ios::out | std::ios::binary);
        BOOST_REQUIRE(data.good());
        const std::vector<char> zeros(8192, 0);
        data.write(zeros.data(), zeros.size());
        data.flush();
        BOOST_REQUIRE(data.good());
    }
    BOOST_CHECK(!VerifyLMDBEnvironment(corrupt.string(), false, verify));
    BOOST_CHECK(!verify.fOpened);
    BOOST_CHECK(!verify.fComplete);
    BOOST_CHECK(!verify.strError.empty());
}

// backupwallet on LMDB must produce a verified point-in-time copy that can be
// restored, and must refuse to overwrite an existing non-empty destination.
void RunWalletLMDBBackup(const std::string &tag)
{
    const std::filesystem::path dir = MakeTempDir(tag);
    struct Guard {
        std::filesystem::path dir;
        ~Guard() {
            CloseLMDBWalletDB();
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } guard{dir};

    // Without an active LMDB wallet there is nothing to copy.
    CloseLMDBWalletDB();
    BOOST_CHECK(!BackupLMDBWallet((dir / "inactive").string()));

    BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));
    {
        WalletDBTestAccess db("wallet.dat", "cr+");
        BOOST_REQUIRE(db.Write(std::string("backup-probe"), std::string("one")));
        BOOST_REQUIRE(db.Write(std::string("backup-second"), std::string("two")));
    }

    const DBDiagnostics before = GetDBDiagnostics(dir, dir);
    const size_t nEntries = before.wallet.db.nEntries;
    BOOST_CHECK_GT(nEntries, 0U);

    // A path that does not exist names a new environment directory.
    const std::filesystem::path dest = dir / "backup";
    BOOST_REQUIRE(BackupLMDBWallet(dest.string()));
    BOOST_CHECK(std::filesystem::exists(dest / "data.mdb"));

    // A compacted copy contains no lock.mdb.
    BOOST_CHECK(!std::filesystem::exists(dest / "lock.mdb"));

    CLMDBVerifyResult verify;
    BOOST_REQUIRE(VerifyLMDBEnvironment(dest.string(), true, verify));
    BOOST_CHECK_EQUAL(verify.nEntries, nEntries);

    // A successful backup must not leave a staging directory behind.
    for (const auto &entry : std::filesystem::directory_iterator(dir)) {
        const std::string name = entry.path().filename().string();
        BOOST_CHECK_MESSAGE(name.find("backup.tmp-") == std::string::npos,
                            "leftover staging directory " << name);
    }

    // An existing directory receives the copy under <destination>/wallet,
    // matching Berkeley DB backupwallet.
    const std::filesystem::path root = dir / "backup-root";
    BOOST_REQUIRE(std::filesystem::create_directories(root));
    BOOST_REQUIRE(BackupLMDBWallet(root.string()));
    BOOST_REQUIRE(VerifyLMDBEnvironment((root / "wallet").string(), true, verify));
    BOOST_CHECK_EQUAL(verify.nEntries, nEntries);

    // An existing directory is a backup root: the copy goes to its wallet/
    // subdirectory.  A non-empty wallet/ target is refused and left untouched.
    const std::filesystem::path nonEmpty = dir / "non-empty";
    BOOST_REQUIRE(std::filesystem::create_directories(nonEmpty / "wallet"));
    {
        std::ofstream file(nonEmpty / "wallet" / "keep", std::ios::trunc);
        BOOST_REQUIRE(file.good());
        file << "keep";
    }
    BOOST_CHECK(!BackupLMDBWallet(nonEmpty.string()));
    BOOST_CHECK(std::filesystem::exists(nonEmpty / "wallet" / "keep"));
    for (const auto &entry : std::filesystem::directory_iterator(nonEmpty)) {
        const std::string name = entry.path().filename().string();
        BOOST_CHECK_MESSAGE(name.find("wallet.tmp-") == std::string::npos,
                            "failed backup left staging directory " << name);
    }

    // A regular file at the destination is refused too.
    {
        std::ofstream file(dir / "not-a-backup", std::ios::trunc);
        BOOST_REQUIRE(file.good());
        file << "keep";
    }
    BOOST_CHECK(!BackupLMDBWallet((dir / "not-a-backup").string()));

    // Restore the earlier snapshot: a record written after the backup must
    // disappear, while the records captured by the backup must survive.
    {
        WalletDBTestAccess db("wallet.dat", "cr+");
        BOOST_REQUIRE(db.Write(std::string("after-backup"), std::string("gone")));
    }
    CloseLMDBWalletDB();

    std::error_code ec;
    std::filesystem::rename(dir / "wallet", dir / "wallet.live", ec);
    BOOST_REQUIRE(!ec);
    std::filesystem::copy(root / "wallet", dir / "wallet",
                          std::filesystem::copy_options::recursive, ec);
    BOOST_REQUIRE(!ec);
    BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));

    {
        WalletDBTestAccess db("wallet.dat", "r");
        std::string value;
        BOOST_REQUIRE(db.Read(std::string("backup-probe"), value));
        BOOST_CHECK_EQUAL(value, "one");
        BOOST_REQUIRE(db.Read(std::string("backup-second"), value));
        BOOST_CHECK_EQUAL(value, "two");
        BOOST_CHECK(!db.Exists(std::string("after-backup")));
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

BOOST_AUTO_TEST_CASE(lmdb_kvdb_writer_serialization)
{
    RunWriterSerialization("lmdb_writer_serialization");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_transaction_thread_handoff)
{
    RunTransactionThreadHandoff("lmdb_thread_handoff");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_concurrent_readers)
{
    RunConcurrentReaders("lmdb_concurrent_readers");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_concurrent_writers)
{
    RunConcurrentWriters("lmdb_concurrent_writers");
}

BOOST_AUTO_TEST_CASE(bdb_kvdb_prefix_iteration)
{
    RunPrefixIteration<CBDBDatabase>("bdb_prefix");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_prefix_iteration)
{
    RunPrefixIteration<CLMDBDatabase>("lmdb_prefix");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_shared_environment)
{
    RunSharedEnvironment("lmdb_shared_env");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_nosync_environment)
{
    RunNoSyncEnvironment("lmdb_nosync");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_map_size_adjust)
{
    RunMapSizeAdjust("lmdb_mapsize");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_stats)
{
    RunLMDBEnvironmentStats("lmdb_stats");
}

BOOST_AUTO_TEST_CASE(lmdb_environment_verify)
{
    RunLMDBEnvironmentVerify("lmdb_verify");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_runtime_growth)
{
    RunLMDBRuntimeGrowth("lmdb_runtime_growth");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_runtime_growth_maximum)
{
    RunLMDBRuntimeGrowthMaximum("lmdb_runtime_growth_max");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_fixed_map_size)
{
    RunLMDBFixedMapSize("lmdb_fixed_map");
}

BOOST_AUTO_TEST_CASE(wallet_lmdb_diagnostics)
{
    RunWalletLMDBDiagnostics("wallet_lmdb_diagnostics");
}

BOOST_AUTO_TEST_CASE(lmdb_mapsize_parsing)
{
    RunLMDBMapSizeParsing("lmdb_mapsize_parse");
}

BOOST_AUTO_TEST_CASE(lmdb_mapsize_resolution)
{
    RunLMDBMapSizeResolution("lmdb_mapsize_resolution");
}

BOOST_AUTO_TEST_CASE(lmdb_wallet_migration_mapsize)
{
    RunLMDBWalletMigrationMapSize("lmdb_wallet_migration_mapsize");
}

BOOST_AUTO_TEST_CASE(chain_index_startup_action)
{
    RunChainIndexStartupAction("chain_index_startup_action");
}

BOOST_AUTO_TEST_CASE(chain_index_failed_write_rollback)
{
    RunBlockIndexRollback("chain_index_rollback");
}

#ifndef WINDOWS
BOOST_AUTO_TEST_CASE(lmdb_kvdb_nosync_crash_consistency)
{
    RunNoSyncCrashConsistency("lmdb_nosync_crash");
}
#endif

BOOST_AUTO_TEST_CASE(chain_backend_marker)
{
    RunChainBackendMarker("chain_backend_marker");
}

BOOST_AUTO_TEST_CASE(bdb_kvdb_large_value_iteration)
{
    RunLargeValueIteration<CBDBDatabase>("bdb_large_values");
}

BOOST_AUTO_TEST_CASE(lmdb_kvdb_large_value_iteration)
{
    RunLargeValueIteration<CLMDBDatabase>("lmdb_large_values");
}

BOOST_AUTO_TEST_CASE(wallet_backend_marker)
{
    RunWalletBackendMarker("wallet_backend_marker");
}

BOOST_AUTO_TEST_CASE(wallet_backend_default_lmdb)
{
    ArgOverride backend("-walletbackend");

    // No explicit switch: production selects LMDB.
    BOOST_CHECK_EQUAL(GetConfiguredWalletBackend(), DB_BACKEND_LMDB);

    // Explicit Berkeley DB remains available for compatibility and recovery.
    backend.Set("bdb");
    BOOST_CHECK_EQUAL(GetConfiguredWalletBackend(), DB_BACKEND_BDB);
    backend.Set("BDB");
    BOOST_CHECK_EQUAL(GetConfiguredWalletBackend(), DB_BACKEND_BDB);

    backend.Set("lmdb");
    BOOST_CHECK_EQUAL(GetConfiguredWalletBackend(), DB_BACKEND_LMDB);
}

BOOST_AUTO_TEST_CASE(wallet_startup_action)
{
    RunWalletStartupAction("wallet_startup_action");
}

BOOST_AUTO_TEST_CASE(wallet_lmdb_backend)
{
    RunWalletLMDBBackend("wallet_lmdb_backend");
}

BOOST_AUTO_TEST_CASE(wallet_lmdb_backup)
{
    RunWalletLMDBBackup("wallet_lmdb_backup");
}

BOOST_AUTO_TEST_CASE(wallet_lmdb_startup_refusal)
{
    RunWalletLMDBStartupRefusal("wallet_lmdb_startup_refusal");
}

BOOST_AUTO_TEST_CASE(wallet_lmdb_migration)
{
    RunWalletLMDBMigration("wallet_lmdb_migration");
}

BOOST_AUTO_TEST_CASE(wallet_lmdb_rewrite_rename_old_failure)
{
    RunWalletRewriteRenameOldFailure("wallet_lmdb_rewrite_rename_old_failure");
}

BOOST_AUTO_TEST_CASE(wallet_lmdb_rewrite_install_failure)
{
    RunWalletRewriteInstallFailure("wallet_lmdb_rewrite_install_failure");
}

BOOST_AUTO_TEST_CASE(wallet_lmdb_rewrite_reopen_failure)
{
    RunWalletRewriteReopenFailure("wallet_lmdb_rewrite_reopen_failure");
}

BOOST_AUTO_TEST_CASE(wallet_lmdb_rewrite_cleanup_failure)
{
    RunWalletRewriteCleanupFailure("wallet_lmdb_rewrite_cleanup_failure");
}

BOOST_AUTO_TEST_CASE(wallet_bdb_marker_authority)
{
    RunWalletBDBMarkerAuthority("wallet_bdb_marker_authority");
}

BOOST_AUTO_TEST_SUITE_END()
