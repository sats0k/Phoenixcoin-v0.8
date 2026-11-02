// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

// Reproducible wallet backend benchmark.  It is a separate binary because the
// unit-test fixture deliberately uses an in-memory Berkeley DB environment;
// timings and database sizes are only meaningful with the real on-disk
// backends.
//
// Typical use:
//
//   src/wallet_perf seed /tmp/wallet-perf/seed
//   cp -a /tmp/wallet-perf/seed /tmp/wallet-perf/bdb
//   cp -a /tmp/wallet-perf/seed /tmp/wallet-perf/lmdb
//   src/wallet_perf bdb /tmp/wallet-perf/bdb
//   src/wallet_perf lmdb /tmp/wallet-perf/lmdb
//
// The seed phase writes a wallet with realistic record counts: transactions
// with multiple inputs and outputs, legacy keys, keypool entries, redeem
// scripts, watch-only scripts and address book labels.  The bdb and lmdb
// phases run the identical operations so their numbers are comparable.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "checkpoints.h"
#include "db.h"
#include "main.h"
#include "script.h"
#include "ui_interface.h"
#include "util.h"
#include "wallet.h"
#include "walletdb.h"

CWallet *pwalletMain = nullptr;
CClientUIInterface uiInterface;
enum Checkpoints::CPMode CheckpointsMode;
uint nMsgSleep = 20;

// init.o provides the daemon's implementations but also main(), which this
// benchmark replaces.
void StartShutdown() {}
void Shutdown(void * /*parg*/) {}

namespace {

using Clock = std::chrono::steady_clock;

double ElapsedMs(const Clock::time_point &start)
{
    return std::chrono::duration<double, std::milli>(Clock::now() - start)
        .count();
}

std::string GetOpt(const std::map<std::string, std::string> &opts,
                   const std::string &name, const std::string &fallback)
{
    const auto it = opts.find(name);
    return it == opts.end() ? fallback : it->second;
}

unsigned int GetOptUInt(const std::map<std::string, std::string> &opts,
                        const std::string &name, unsigned int fallback)
{
    const std::string value = GetOpt(opts, name, "");
    if (value.empty())
        return fallback;
    return static_cast<unsigned int>(std::strtoul(value.c_str(), nullptr, 10));
}

void Emit(const char *backend, const std::string &metric, double value,
          const char *unit, const std::string &note = std::string())
{
    std::string safeNote = note;
    std::replace(safeNote.begin(), safeNote.end(), ',', ';');
    printf("%s,%s,%.3f,%s,%s\n", backend, metric.c_str(), value, unit,
                safeNote.c_str());
}

uintmax_t DirectorySize(const std::filesystem::path &path)
{
    std::error_code ec;
    if (!std::filesystem::exists(path, ec))
        return 0;
    if (std::filesystem::is_regular_file(path, ec))
        return std::filesystem::file_size(path, ec);

    uintmax_t total = 0;
    for (const auto &entry :
         std::filesystem::recursive_directory_iterator(path, ec)) {
        if (ec)
            break;
        if (entry.is_regular_file(ec))
            total += entry.file_size(ec);
    }
    return total;
}

uint256 MakeHash(uint64_t value, uint64_t salt)
{
    unsigned char bytes[32] = {};
    for (int i = 0; i < 8; ++i) {
        bytes[i] = static_cast<unsigned char>((value >> (8 * i)) & 0xff);
        bytes[8 + i] = static_cast<unsigned char>((salt >> (8 * i)) & 0xff);
        bytes[16 + i] = static_cast<unsigned char>((value * 131 + salt) >> (8 * i));
        bytes[24 + i] = static_cast<unsigned char>((value * 7919 + salt) >> (8 * i));
    }
    uint256 hash;
    std::memcpy(hash.begin(), bytes, sizeof(bytes));
    return hash;
}

CTransaction MakeTransaction(uint64_t index, uint64_t salt,
                             const std::vector<CPubKey> &keys)
{
    CTransaction tx;
    tx.nVersion = 1;
    tx.nLockTime = static_cast<unsigned int>(100000 + index);

    const unsigned int inputs = 1 + static_cast<unsigned int>(index % 3);
    tx.vin.resize(inputs);
    for (unsigned int i = 0; i < inputs; ++i) {
        tx.vin[i].prevout = COutPoint(MakeHash(index * 4 + i, salt), i);
        tx.vin[i].scriptSig = CScript()
            << OP_0 << std::vector<unsigned char>{0x01, 0x02, 0x03, 0x04};
    }

    const unsigned int outputs = 2 + static_cast<unsigned int>(index % 2);
    tx.vout.resize(outputs);
    for (unsigned int i = 0; i < outputs; ++i) {
        // Never pay the default key: AddToWallet() would rotate it out of the
        // keypool, which is real behaviour but would skew the pool shape.
        const size_t keyIndex = 1 + (index + i) % (keys.size() - 1);
        tx.vout[i].nValue = COIN * (1 + ((index + i) % 50));
        tx.vout[i].scriptPubKey.SetDestination(keys[keyIndex].GetID());
    }
    return tx;
}

bool AddBenchTransaction(CWallet &wallet, uint64_t index, uint64_t salt,
                         const std::vector<CPubKey> &keys)
{
    const CTransaction tx = MakeTransaction(index, salt, keys);
    CWalletTx wtx(&wallet, tx);
    wtx.strFromAccount = "bench-" + std::to_string(index % 16);
    wtx.mapValue["comment"] = "wallet backend benchmark";
    wtx.mapValue["label"] = "tx-" + std::to_string(index % 64);
    wtx.nTimeReceived = static_cast<unsigned int>(1300000000 + index);
    wtx.nTimeSmart = wtx.nTimeReceived + 10;
    wtx.fTimeReceivedIsTxTime = 1;
    wtx.fFromMe = (index % 3 == 0);
    if (index % 5 == 0)
        wtx.hashBlock = MakeHash(index, salt ^ 0x9e3779b97f4a7c15ULL);
    wtx.nIndex = (index % 5 == 0) ? static_cast<int>(index % 4) : -1;
    wtx.MarkDirty();
    return wallet.AddToWallet(wtx);
}

std::vector<CScript> MakeRedeemScripts(size_t count, uint64_t salt)
{
    std::vector<CScript> scripts;
    scripts.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const uint64_t value = salt + i;
        std::vector<unsigned char> data(8);
        for (int j = 0; j < 8; ++j)
            data[j] = static_cast<unsigned char>((value >> (8 * j)) & 0xff);
        CScript script;
        script << OP_RETURN << data;
        scripts.push_back(script);
    }
    return scripts;
}

std::vector<CScript> MakeWatchScripts(size_t count, uint64_t salt)
{
    std::vector<CScript> scripts;
    scripts.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        CKey key;
        key.MakeNewKey(true);
        const uint64_t value = salt + i;
        std::vector<unsigned char> data(20);
        for (int j = 0; j < 20; ++j)
            data[j] = static_cast<unsigned char>(
                (value >> (8 * (j % 8))) & 0xff);
        data[0] = static_cast<unsigned char>(i & 0xff);
        data[1] = static_cast<unsigned char>((i >> 8) & 0xff);
        CScript script;
        script.SetDestination(CKeyID(uint160(data)));
        scripts.push_back(script);
    }
    return scripts;
}

std::vector<CKeyID> WalletKeyIDs(const CWallet &wallet)
{
    std::set<CKeyID> ids;
    wallet.GetKeys(ids);
    return std::vector<CKeyID>(ids.begin(), ids.end());
}

void SetBenchArgs()
{
    mapArgs["-keypool"] = "100";
    mapArgs["-privdb"] = "1";
}

int Seed(const std::filesystem::path &dir,
         const std::map<std::string, std::string> &opts)
{
    const unsigned int nTx = GetOptUInt(opts, "tx", 10000);
    const unsigned int nKeys = std::max(2U, GetOptUInt(opts, "keys", 1000));
    const unsigned int nScripts = GetOptUInt(opts, "scripts", 200);
    const unsigned int nKeyPool = GetOptUInt(opts, "keypool", 100);

    SetBenchArgs();
    std::filesystem::create_directories(dir);
    if (!bitdb.Open(dir)) {
        std::fprintf(stderr, "cannot open Berkeley DB environment in %s\n",
                     dir.string().c_str());
        return 1;
    }

    std::vector<CPubKey> pubKeys;
    {
        CWallet wallet("wallet.dat");
        bool fFirstRun = false;
        if (wallet.LoadWallet(fFirstRun) != DB_LOAD_OK) {
            std::fprintf(stderr, "cannot create wallet\n");
            return 1;
        }

        pubKeys.reserve(nKeys);
        for (unsigned int i = 0; i < nKeys; ++i)
            pubKeys.push_back(wallet.GenerateNewKey());
        if (pubKeys.size() < 2) {
            std::fprintf(stderr, "not enough keys generated\n");
            return 1;
        }

        const std::vector<CScript> redeem =
            MakeRedeemScripts(nScripts, 0x11111111ULL);
        const std::vector<CScript> watch =
            MakeWatchScripts(nScripts, 0x22222222ULL);
        for (unsigned int i = 0; i < nScripts; ++i) {
            if (!wallet.AddCScript(redeem[i]) ||
                !wallet.AddWatchOnly(watch[i])) {
                std::fprintf(stderr, "cannot add script record\n");
                return 1;
            }
        }

        const std::vector<CKeyID> ids = WalletKeyIDs(wallet);
        for (unsigned int i = 0; i < nScripts && i < ids.size(); ++i) {
            if (!wallet.SetAddressBookName(ids[i],
                                           "label-" + std::to_string(i))) {
                std::fprintf(stderr, "cannot add address book record\n");
                return 1;
            }
        }

        if (!wallet.NewKeyPool(nKeyPool)) {
            std::fprintf(stderr, "cannot create keypool\n");
            return 1;
        }

        for (unsigned int i = 0; i < nTx; ++i) {
            if (!AddBenchTransaction(wallet, i, 0x33333333ULL, pubKeys)) {
                std::fprintf(stderr, "cannot add transaction %u\n", i);
                return 1;
            }
        }

        // Make the hybrid pool part of the persisted wallet as well.
        if (!wallet.EnsureHybridKeyPool(20)) {
            std::fprintf(stderr, "cannot create hybrid keypool\n");
            return 1;
        }

        printf("seeded %u transactions, %u keys, %u scripts, "
                    "%u keypool entries\n",
                    nTx, nKeys, nScripts, nKeyPool);
    }

    bitdb.Flush(true);
    bitdb.Close();

    Emit("seed", "wallet_file_bytes", DirectorySize(dir / "wallet.dat"),
         "bytes", "Berkeley DB wallet.dat");
    Emit("seed", "wallet_dir_bytes", DirectorySize(dir), "bytes",
         "whole seed data directory");
    return 0;
}

struct BenchmarkConfig
{
    unsigned int insertTx = 1000;
    unsigned int insertKeys = 200;
    unsigned int lookupOps = 1000000;
    unsigned int diskLookupOps = 2000;
    unsigned int recordOps = 200;
    unsigned int keypool = 100;
};

class WalletDBReadBench : public CWalletDB
{
public:
    explicit WalletDBReadBench(const std::string &file)
        : CWalletDB(file, "r") {}
    using CDB::Read;
};

void RunOperations(const char *backend, CWallet &wallet, uint64_t salt,
                   const BenchmarkConfig &cfg)
{
    std::vector<uint256> txids;
    txids.reserve(wallet.mapWallet.size());
    for (const auto &entry : wallet.mapWallet)
        txids.push_back(entry.first);
    if (txids.empty()) {
        std::fprintf(stderr, "wallet has no transactions\n");
        return;
    }

    std::vector<CPubKey> pubKeys;
    {
        std::set<CKeyID> ids;
        wallet.GetKeys(ids);
        for (const CKeyID &id : ids) {
            CKey key;
            if (wallet.GetKey(id, key))
                pubKeys.push_back(key.GetPubKey());
            if (pubKeys.size() >= cfg.insertKeys + 4)
                break;
        }
    }
    if (pubKeys.size() < 2) {
        std::fprintf(stderr, "wallet has no usable keys\n");
        return;
    }

    // In-memory lookup, which is what wallet RPC paths normally use.
    {
        CWalletTx found;
        uint64_t checksum = 0;
        const auto start = Clock::now();
        for (unsigned int i = 0; i < cfg.lookupOps; ++i) {
            const uint256 &txid = txids[i % txids.size()];
            if (wallet.GetTransaction(txid, found))
                checksum += found.GetHash().GetLow64();
        }
        const double ms = ElapsedMs(start);
        Emit(backend, "tx_lookup_memory_total", ms, "ms",
             "GetTransaction from loaded map");
        Emit(backend, "tx_lookup_memory_ns_per_op",
             ms * 1000000.0 / std::max(1U, cfg.lookupOps), "ns/op",
             "checksum " + std::to_string(checksum));
    }

    // One direct database read per transaction, with the handle kept open.
    {
        WalletDBReadBench db("wallet.dat");
        CWalletTx wtx;
        uint64_t hits = 0;
        const auto start = Clock::now();
        for (unsigned int i = 0; i < cfg.diskLookupOps; ++i) {
            const uint256 &txid =
                txids[(static_cast<size_t>(i) * 2654435761U) % txids.size()];
            if (db.Read(std::make_pair(std::string("tx"), txid), wtx))
                ++hits;
        }
        const double ms = ElapsedMs(start);
        Emit(backend, "tx_lookup_disk_total", ms, "ms",
             "direct wallet record reads, hits " + std::to_string(hits));
        Emit(backend, "tx_lookup_disk_us_per_op",
             ms * 1000.0 / std::max(1U, cfg.diskLookupOps), "us/op",
             "direct wallet record reads");
    }

    // Transaction insertion into the already loaded wallet.
    {
        const auto start = Clock::now();
        for (unsigned int i = 0; i < cfg.insertTx; ++i) {
            if (!AddBenchTransaction(wallet, 1000000 + i, salt, pubKeys))
                std::fprintf(stderr, "insert transaction %u failed\n", i);
        }
        const double ms = ElapsedMs(start);
        Emit(backend, "tx_insert_total", ms, "ms",
             std::to_string(cfg.insertTx) + " transactions");
        Emit(backend, "tx_insert_us_per_op",
             ms * 1000.0 / std::max(1U, cfg.insertTx), "us/op",
             "AddToWallet including disk write");
        Emit(backend, "tx_insert_ops_per_sec",
             cfg.insertTx * 1000.0 / std::max(1.0, ms), "tx/s",
             "AddToWallet including disk write");
    }

    // Key generation plus persistence.
    {
        const auto start = Clock::now();
        for (unsigned int i = 0; i < cfg.insertKeys; ++i)
            wallet.GenerateNewKey();
        const double ms = ElapsedMs(start);
        Emit(backend, "key_insert_total", ms, "ms",
             std::to_string(cfg.insertKeys) + " keys");
        Emit(backend, "key_insert_ms_per_op",
             ms / std::max(1U, cfg.insertKeys), "ms/op",
             "GenerateNewKey including disk write");
    }

    // Legacy keypool reset and refill.
    {
        const auto start = Clock::now();
        if (!wallet.NewKeyPool(cfg.keypool))
            std::fprintf(stderr, "keypool refill failed\n");
        const double ms = ElapsedMs(start);
        Emit(backend, "keypool_refill_total", ms, "ms",
             std::to_string(cfg.keypool) + " keys");
        Emit(backend, "keypool_refill_keys_per_sec",
             cfg.keypool * 1000.0 / std::max(1.0, ms), "keys/s",
             "NewKeyPool including disk writes");
    }

    // The wallet format has no descriptor records.  These are the closest
    // persisted script/address operations it does have.
    {
        const std::vector<CScript> redeem =
            MakeRedeemScripts(cfg.recordOps, salt ^ 0x44444444ULL);
        const std::vector<CScript> watch =
            MakeWatchScripts(cfg.recordOps, salt ^ 0x55555555ULL);

        {
            const auto start = Clock::now();
            for (const CScript &script : redeem)
                wallet.AddCScript(script);
            const double ms = ElapsedMs(start);
            Emit(backend, "descriptor_equiv_add_script_total", ms, "ms",
                 std::to_string(cfg.recordOps) + " redeem scripts");
            Emit(backend, "descriptor_equiv_add_script_us_per_op",
                 ms * 1000.0 / std::max(1U, cfg.recordOps), "us/op",
                 "AddCScript; wallet has no descriptor records");
        }

        {
            const auto start = Clock::now();
            for (const CScript &script : watch)
                wallet.AddWatchOnly(script);
            const double ms = ElapsedMs(start);
            Emit(backend, "descriptor_equiv_add_watch_total", ms, "ms",
                 std::to_string(cfg.recordOps) + " watch-only scripts");
            Emit(backend, "descriptor_equiv_add_watch_us_per_op",
                 ms * 1000.0 / std::max(1U, cfg.recordOps), "us/op",
                 "AddWatchOnly; wallet has no descriptor records");
        }

        const std::vector<CKeyID> ids = WalletKeyIDs(wallet);
        const unsigned int labels =
            std::min<unsigned int>(cfg.recordOps, ids.size());
        {
            const auto start = Clock::now();
            for (unsigned int i = 0; i < labels; ++i) {
                wallet.SetAddressBookName(
                    ids[i], "perf-label-" + std::to_string(i));
            }
            const double ms = ElapsedMs(start);
            Emit(backend, "descriptor_equiv_address_label_total", ms, "ms",
                 std::to_string(labels) + " address book updates");
            Emit(backend, "descriptor_equiv_address_label_us_per_op",
                 ms * 1000.0 / std::max(1U, labels), "us/op",
                 "SetAddressBookName; wallet has no descriptor records");
        }
    }
}

int RunBDB(const std::filesystem::path &dir,
           const std::map<std::string, std::string> &opts)
{
    SetBenchArgs();
    BenchmarkConfig cfg;
    cfg.insertTx = GetOptUInt(opts, "insert-tx", cfg.insertTx);
    cfg.insertKeys = GetOptUInt(opts, "insert-keys", cfg.insertKeys);
    cfg.lookupOps = GetOptUInt(opts, "lookup-ops", cfg.lookupOps);
    cfg.diskLookupOps =
        GetOptUInt(opts, "disk-lookup-ops", cfg.diskLookupOps);
    cfg.recordOps = GetOptUInt(opts, "record-ops", cfg.recordOps);
    cfg.keypool = GetOptUInt(opts, "keypool", cfg.keypool);

    const auto startupStart = Clock::now();
    if (!bitdb.Open(dir)) {
        std::fprintf(stderr, "cannot open Berkeley DB environment in %s\n",
                     dir.string().c_str());
        return 1;
    }
    const double envOpenMs = ElapsedMs(startupStart);

    std::unique_ptr<CWallet> wallet(new CWallet("wallet.dat"));
    bool fFirstRun = false;
    const auto loadStart = Clock::now();
    const DBErrors result = wallet->LoadWallet(fFirstRun);
    const double loadMs = ElapsedMs(loadStart);
    if (result != DB_LOAD_OK) {
        std::fprintf(stderr, "wallet load returned %d\n", result);
        return 1;
    }
    const double startupMs = ElapsedMs(startupStart);

    Emit("bdb", "startup_env_open", envOpenMs, "ms",
         "Berkeley DB environment open");
    Emit("bdb", "startup_load_wallet", loadMs, "ms",
         "CWallet::LoadWallet on the large wallet");
    Emit("bdb", "wallet_startup_total", startupMs, "ms",
         "environment open plus wallet load");

    RunOperations("bdb", *wallet, 0x66666666ULL, cfg);

    const auto shutdownStart = Clock::now();
    wallet.reset();
    bitdb.Flush(true);
    bitdb.Close();
    Emit("bdb", "wallet_shutdown_total", ElapsedMs(shutdownStart), "ms",
         "wallet delete, flush and environment close");

    Emit("bdb", "db_wallet_file_bytes", DirectorySize(dir / "wallet.dat"),
         "bytes", "Berkeley DB wallet.dat");
    Emit("bdb", "db_dir_bytes", DirectorySize(dir), "bytes",
         "whole data directory after benchmark");
    return 0;
}

int RunLMDB(const std::filesystem::path &dir,
            const std::map<std::string, std::string> &opts)
{
    SetBenchArgs();
    BenchmarkConfig cfg;
    cfg.insertTx = GetOptUInt(opts, "insert-tx", cfg.insertTx);
    cfg.insertKeys = GetOptUInt(opts, "insert-keys", cfg.insertKeys);
    cfg.lookupOps = GetOptUInt(opts, "lookup-ops", cfg.lookupOps);
    cfg.diskLookupOps =
        GetOptUInt(opts, "disk-lookup-ops", cfg.diskLookupOps);
    cfg.recordOps = GetOptUInt(opts, "record-ops", cfg.recordOps);
    cfg.keypool = GetOptUInt(opts, "keypool", cfg.keypool);

    const auto migrationStart = Clock::now();
    if (!bitdb.Open(dir)) {
        std::fprintf(stderr, "cannot open Berkeley DB environment in %s\n",
                     dir.string().c_str());
        return 1;
    }
    const double migrationOpenMs = ElapsedMs(migrationStart);

    const auto migrateStart = Clock::now();
    if (!InitLMDBWalletDBForTest(dir)) {
        std::fprintf(stderr, "LMDB wallet migration failed in %s\n",
                     dir.string().c_str());
        return 1;
    }
    const double migrateMs = ElapsedMs(migrateStart);
    Emit("lmdb", "migration_env_open", migrationOpenMs, "ms",
         "Berkeley DB source environment open");
    Emit("lmdb", "wallet_migration_total", migrateMs, "ms",
         "migrate wallet.dat into an LMDB environment");
    Emit("lmdb", "migration_total_with_env_open",
         ElapsedMs(migrationStart), "ms",
         "source environment open plus migration");
    Emit("lmdb", "db_after_migration_bytes", DirectorySize(dir / "wallet"),
         "bytes", "LMDB wallet directory immediately after migration");

    // Restart the LMDB wallet and measure the cold open/load path that a
    // normal daemon start uses after migration.
    CloseLMDBWalletDB();
    const auto startupStart = Clock::now();
    if (!InitLMDBWalletDBForTest(dir)) {
        std::fprintf(stderr, "LMDB wallet reopen failed in %s\n",
                     dir.string().c_str());
        return 1;
    }
    const double envOpenMs = ElapsedMs(startupStart);

    std::unique_ptr<CWallet> wallet(new CWallet("wallet.dat"));
    bool fFirstRun = false;
    const auto loadStart = Clock::now();
    const DBErrors result = wallet->LoadWallet(fFirstRun);
    const double loadMs = ElapsedMs(loadStart);
    if (result != DB_LOAD_OK) {
        std::fprintf(stderr, "wallet load returned %d\n", result);
        return 1;
    }
    const double startupMs = ElapsedMs(startupStart);

    Emit("lmdb", "startup_env_open", envOpenMs, "ms",
         "LMDB environment reopen");
    Emit("lmdb", "startup_load_wallet", loadMs, "ms",
         "CWallet::LoadWallet on the large wallet");
    Emit("lmdb", "wallet_startup_total", startupMs, "ms",
         "environment reopen plus wallet load");

    RunOperations("lmdb", *wallet, 0x77777777ULL, cfg);

    const auto shutdownStart = Clock::now();
    wallet.reset();
    CloseLMDBWalletDB();
    Emit("lmdb", "wallet_shutdown_total", ElapsedMs(shutdownStart), "ms",
         "wallet delete and LMDB environment close");
    bitdb.Flush(true);
    bitdb.Close();

    Emit("lmdb", "db_wallet_data_bytes",
         DirectorySize(dir / "wallet" / "data.mdb"), "bytes",
         "LMDB data.mdb");
    Emit("lmdb", "db_wallet_dir_bytes", DirectorySize(dir / "wallet"),
         "bytes", "LMDB wallet directory after benchmark");
    Emit("lmdb", "db_dir_bytes", DirectorySize(dir), "bytes",
         "whole data directory after benchmark");
    return 0;
}

void Usage(const char *program)
{
    std::fprintf(stderr,
                 "usage: %s seed <dir> [--tx=N] [--keys=N] [--scripts=N] "
                 "[--keypool=N]\n"
                 "       %s bdb <dir> [--insert-tx=N] [--insert-keys=N] "
                 "[--lookup-ops=N] [--disk-lookup-ops=N] [--record-ops=N] "
                 "[--keypool=N]\n"
                 "       %s lmdb <dir> [same options as bdb]\n",
                 program, program, program);
}

} // namespace

int main(int argc, char *argv[])
{
    fPrintToConsole = true;
    fPrintToDebugger = false;

    if (argc < 3) {
        Usage(argv[0]);
        return 1;
    }

    const std::string mode = argv[1];
    const std::filesystem::path dir = argv[2];

    std::map<std::string, std::string> opts;
    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg.rfind("--", 0) != 0)
            continue;
        const size_t eq = arg.find('=');
        if (eq == std::string::npos)
            opts[arg.substr(2)] = "1";
        else
            opts[arg.substr(2, eq - 2)] = arg.substr(eq + 1);
    }

    printf("backend,metric,value,unit,note\n");
    if (mode == "seed")
        return Seed(dir, opts);
    if (mode == "bdb")
        return RunBDB(dir, opts);
    if (mode == "lmdb")
        return RunLMDB(dir, opts);

    Usage(argv[0]);
    return 1;
}
