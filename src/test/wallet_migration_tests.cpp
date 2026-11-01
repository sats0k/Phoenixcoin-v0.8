// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

#include "base58.h"
#include "db.h"
#include "key.h"
#include "main.h"
#include "script.h"
#include "util.h"
#include "wallet.h"
#include "walletdb.h"

BOOST_AUTO_TEST_SUITE(wallet_migration_tests)

namespace {

static std::filesystem::path MakeTempDir(const std::string &tag)
{
    static std::atomic<unsigned int> counter(0);
    std::filesystem::path dir = std::filesystem::temp_directory_path() /
        ("phoenixcoin_wallet_migration_" + tag + "_" +
         std::to_string(GetTimeMillis()) + "_" +
         std::to_string(counter.fetch_add(1)));

    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    BOOST_REQUIRE_MESSAGE(!ec, "could not create temp directory " << dir
                          << ": " << ec.message());
    return dir;
}

struct TempDirGuard
{
    std::filesystem::path dir;

    explicit TempDirGuard(const std::string &tag) : dir(MakeTempDir(tag)) {}

    ~TempDirGuard()
    {
        CloseLMDBWalletDB();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

/** Test-only access to the protected CDB cursor/erase helpers. */
class WalletDBTestAccess : public CWalletDB
{
public:
    WalletDBTestAccess(const std::string &file, const char *mode)
        : CWalletDB(file, mode) {}

    using CDB::EraseKV;
    using CDB::GetScan;
    using CDB::ReadKV;
    using CDB::WriteKV;
};

/**
 * Creates the on-disk wallet.dat placeholder that startup uses to decide that
 * a BDB wallet exists, then migrates the records held by the mocked Berkeley
 * DB environment into a temporary LMDB wallet.
 *
 * The mock environment keeps wallet.dat in memory, so the placeholder is only
 * a startup signal; the records themselves come from WalletDBTestAccess.
 */
static void MigrateMockWallet(const std::filesystem::path &dir)
{
    CloseLMDBWalletDB();
    {
        std::ofstream wallet(dir / "wallet.dat", std::ios::trunc);
        BOOST_REQUIRE(wallet.good());
        wallet << "berkeley db wallet";
    }

    BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));
    BOOST_CHECK(IsLMDBWalletEnabled());
}

/** Simulates a daemon restart of the LMDB wallet in dir. */
static void RestartLMDBWallet(const std::filesystem::path &dir)
{
    CloseLMDBWalletDB();
    BOOST_REQUIRE(InitLMDBWalletDBForTest(dir));
    BOOST_CHECK(IsLMDBWalletEnabled());
}

static uint256 HashFromHex(const char *hex)
{
    uint256 hash;
    hash.SetHex(hex);
    return hash;
}

static std::map<CDBKey, CDBValue> CaptureRecords()
{
    std::map<CDBKey, CDBValue> records;

    WalletDBTestAccess db("wallet.dat", "r");
    std::unique_ptr<CDBScan> scan = db.GetScan();
    BOOST_REQUIRE(scan.get() != nullptr);

    for (scan->SeekToFirst(); scan->Valid(); scan->Next())
        records[scan->Key()] = scan->Value();
    BOOST_REQUIRE(!scan->Error());
    return records;
}

static std::string RecordType(const CDBKey &key)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    if (!key.empty())
        ss.write((const char *)&key[0], key.size());

    std::string type;
    try {
        ss >> type;
    } catch (...) {
        return std::string();
    }
    return type;
}

static size_t CountRecordsOfType(const std::map<CDBKey, CDBValue> &records,
                                 const std::string &type)
{
    size_t n = 0;
    for (const auto &record : records)
        if (RecordType(record.first) == type)
            ++n;
    return n;
}

template <typename Container>
static bool FileContainsBytes(const std::filesystem::path &path,
                              const Container &needle)
{
    if (needle.empty())
        return false;

    std::ifstream file(path, std::ios::binary);
    BOOST_REQUIRE_MESSAGE(file.good(), "cannot open " << path);
    const std::vector<unsigned char> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    return std::search(data.begin(), data.end(),
                       needle.begin(), needle.end()) != data.end();
}

struct TxSnapshot
{
    uint256 hash;
    uint256 hashBlock;
    int nIndex;
    std::vector<uint256> vMerkleBranch;
    std::vector<uint256> vtxPrev;
    mapValue_t mapValue;
    unsigned int fTimeReceivedIsTxTime;
    unsigned int nTimeReceived;
    unsigned int nTimeSmart;
    int fFromMe;
    std::vector<char> vfSpent;
    std::vector<unsigned char> vfChange;
    int64 nOrderPos;
    std::string strFromAccount;
    size_t nVin;
    size_t nVout;
    int64 nValueOut;
};

static TxSnapshot CaptureTx(const CWalletTx &wtx)
{
    TxSnapshot tx;
    tx.hash = wtx.GetHash();
    tx.hashBlock = wtx.hashBlock;
    tx.nIndex = wtx.nIndex;
    tx.vMerkleBranch = wtx.vMerkleBranch;
    for (const CMerkleTx &prev : wtx.vtxPrev)
        tx.vtxPrev.push_back(prev.GetHash());
    tx.mapValue = wtx.mapValue;
    tx.fTimeReceivedIsTxTime = wtx.fTimeReceivedIsTxTime;
    tx.nTimeReceived = wtx.nTimeReceived;
    tx.nTimeSmart = wtx.nTimeSmart;
    tx.fFromMe = wtx.fFromMe;
    tx.vfSpent = wtx.vfSpent;
    tx.vfChange = wtx.vfChange;
    tx.nOrderPos = wtx.nOrderPos;
    tx.strFromAccount = wtx.strFromAccount;
    tx.nVin = wtx.vin.size();
    tx.nVout = wtx.vout.size();
    tx.nValueOut = 0;
    for (const CTxOut &out : wtx.vout)
        tx.nValueOut += out.nValue;
    return tx;
}

struct WalletSnapshot
{
    bool crypted = false;
    bool locked = false;
    int version = 0;
    int64 timeFirstKey = 0;
    int64 orderPosNext = 0;
    CPubKey defaultKey;
    std::set<CKeyID> keyIDs;
    std::map<CKeyID, CPubKey> pubKeys;
    std::map<CKeyID, CKeyMetadata> keyMetadata;
    std::map<CKeyID, CPrivKey> secrets;
    std::set<int64> keyPool;
    std::map<int64, CKeyPool> keyPoolEntries;
    std::map<CTxDestination, std::string> addressBook;
    std::map<CScript, bool> watchOnly;
    std::map<CScriptID, std::pair<bool, CScript>> scripts;
    std::map<uint256, TxSnapshot> txs;
};

/**
 * Captures every wallet-level fact the migration must preserve.  Secret
 * material is only read while it is available (unencrypted or unlocked); the
 * encrypted case is covered by the raw record comparison and by signing after
 * an unlock.
 *
 * This wallet format has no HD key chain and no external/internal keypool
 * split, so HD metadata maps to CKeyMetadata and both keypool halves map to the
 * single setKeyPool.  It also has no first-class abandoned flag; callers store
 * that state in CWalletTx::mapValue, which is compared verbatim.
 */
static WalletSnapshot CaptureWalletSnapshot(
    CWallet &wallet,
    const std::vector<CScript> &knownScripts,
    const std::vector<CScript> &knownWatchScripts)
{
    WalletSnapshot snapshot;
    snapshot.crypted = wallet.IsCrypted();
    snapshot.locked = wallet.IsLocked();
    snapshot.version = wallet.GetVersion();
    snapshot.timeFirstKey = wallet.nTimeFirstKey;
    snapshot.orderPosNext = wallet.nOrderPosNext;
    snapshot.defaultKey = wallet.vchDefaultKey;

    wallet.GetKeys(snapshot.keyIDs);
    for (const CKeyID &keyID : snapshot.keyIDs) {
        CPubKey pubKey;
        if (wallet.GetPubKey(keyID, pubKey))
            snapshot.pubKeys[keyID] = pubKey;

        if (!snapshot.locked) {
            CKey key;
            if (wallet.GetKey(keyID, key))
                snapshot.secrets[keyID] = key.GetPrivKey();
        }
    }

    snapshot.keyMetadata = wallet.mapKeyMetadata;
    snapshot.keyPool = wallet.setKeyPool;
    snapshot.addressBook = wallet.mapAddressBook;

    {
        CWalletDB db("wallet.dat", "r");
        for (int64 nIndex : wallet.setKeyPool) {
            CKeyPool keypool;
            BOOST_REQUIRE_MESSAGE(db.ReadPool(nIndex, keypool),
                                  "keypool entry " << nIndex << " unreadable");
            snapshot.keyPoolEntries[nIndex] = keypool;
        }
    }

    for (const CScript &script : knownWatchScripts)
        snapshot.watchOnly[script] = wallet.HaveWatchOnly(script);

    for (const CScript &script : knownScripts) {
        const CScriptID scriptID = script.GetID();
        CScript stored;
        const bool found = wallet.GetCScript(scriptID, stored);
        snapshot.scripts[scriptID] = std::make_pair(found, stored);
    }

    for (const auto &entry : wallet.mapWallet)
        snapshot.txs[entry.first] = CaptureTx(entry.second);

    return snapshot;
}

static void CheckTxEqual(const TxSnapshot &expected, const TxSnapshot &actual,
                         const std::string &phase)
{
    BOOST_CHECK_MESSAGE(expected.hash == actual.hash,
                        phase << ": transaction hash changed");
    BOOST_CHECK_MESSAGE(expected.hashBlock == actual.hashBlock,
                        phase << ": block association changed for "
                              << expected.hash.ToString());
    BOOST_CHECK_MESSAGE((actual.nIndex) == (expected.nIndex),
                        phase << ": block index changed");
    BOOST_CHECK_MESSAGE(expected.vMerkleBranch == actual.vMerkleBranch,
                        phase << ": merkle branch changed");
    BOOST_CHECK_MESSAGE(expected.vtxPrev == actual.vtxPrev,
                        phase << ": previous transaction set changed");
    BOOST_CHECK_MESSAGE(expected.mapValue == actual.mapValue,
                        phase << ": transaction metadata changed");
    BOOST_CHECK_MESSAGE((actual.fTimeReceivedIsTxTime) == (expected.fTimeReceivedIsTxTime),
                        phase << ": time-received flag changed");
    BOOST_CHECK_MESSAGE((actual.nTimeReceived) == (expected.nTimeReceived),
                        phase << ": receive time changed");
    BOOST_CHECK_MESSAGE((actual.nTimeSmart) == (expected.nTimeSmart),
                        phase << ": smart time changed");
    BOOST_CHECK_MESSAGE((actual.fFromMe) == (expected.fFromMe),
                        phase << ": from-me flag changed");
    BOOST_CHECK_MESSAGE(expected.vfSpent == actual.vfSpent,
                        phase << ": per-output spent state changed");
    BOOST_CHECK_MESSAGE(expected.vfChange == actual.vfChange,
                        phase << ": change state changed");
    BOOST_CHECK_MESSAGE((actual.nOrderPos) == (expected.nOrderPos),
                        phase << ": order position changed");
    BOOST_CHECK_MESSAGE((actual.strFromAccount) == (expected.strFromAccount),
                        phase << ": source account changed");
    BOOST_CHECK_MESSAGE((actual.nVin) == (expected.nVin),
                        phase << ": input count changed");
    BOOST_CHECK_MESSAGE((actual.nVout) == (expected.nVout),
                        phase << ": output count changed");
    BOOST_CHECK_MESSAGE((actual.nValueOut) == (expected.nValueOut),
                        phase << ": output value changed");
}

static void CheckSnapshotsEqual(const WalletSnapshot &expected,
                                const WalletSnapshot &actual,
                                const std::string &phase)
{
    BOOST_CHECK_MESSAGE((actual.crypted) == (expected.crypted),
                        phase << ": encryption flag changed");
    BOOST_CHECK_MESSAGE((actual.locked) == (expected.locked),
                        phase << ": lock state changed");
    BOOST_CHECK_MESSAGE((actual.version) == (expected.version),
                        phase << ": wallet version changed");
    BOOST_CHECK_MESSAGE((actual.timeFirstKey) == (expected.timeFirstKey),
                        phase << ": first key time changed");
    BOOST_CHECK_MESSAGE((actual.orderPosNext) == (expected.orderPosNext),
                        phase << ": next order position changed");
    BOOST_CHECK_MESSAGE(expected.defaultKey == actual.defaultKey,
                        phase << ": default key changed");

    BOOST_CHECK_MESSAGE((actual.keyIDs.size()) == (expected.keyIDs.size()),
                        phase << ": key count changed");
    BOOST_CHECK_MESSAGE(expected.keyIDs == actual.keyIDs,
                        phase << ": key IDs changed");
    BOOST_CHECK_MESSAGE((actual.pubKeys.size()) == (expected.pubKeys.size()),
                        phase << ": public key count changed");
    for (const auto &entry : expected.pubKeys) {
        const auto it = actual.pubKeys.find(entry.first);
        BOOST_REQUIRE_MESSAGE(it != actual.pubKeys.end(),
                              phase << ": public key missing for "
                                    << entry.first.ToString());
        BOOST_CHECK_MESSAGE(it->second == entry.second,
                            phase << ": public key changed for "
                                  << entry.first.ToString());
    }

    BOOST_CHECK_MESSAGE((actual.keyMetadata.size()) == (expected.keyMetadata.size()),
                        phase << ": key metadata count changed");
    for (const auto &entry : expected.keyMetadata) {
        const auto it = actual.keyMetadata.find(entry.first);
        BOOST_REQUIRE_MESSAGE(it != actual.keyMetadata.end(),
                              phase << ": key metadata missing for "
                                    << entry.first.ToString());
        BOOST_CHECK_MESSAGE((it->second.nVersion) == (entry.second.nVersion),
                            phase << ": metadata version changed");
        BOOST_CHECK_MESSAGE((it->second.nCreateTime) == (entry.second.nCreateTime),
                            phase << ": metadata creation time changed");
    }

    BOOST_CHECK_MESSAGE((actual.secrets.size()) == (expected.secrets.size()),
                        phase << ": readable secret count changed");
    for (const auto &entry : expected.secrets) {
        const auto it = actual.secrets.find(entry.first);
        BOOST_REQUIRE_MESSAGE(it != actual.secrets.end(),
                              phase << ": private key missing for "
                                    << entry.first.ToString());
        BOOST_CHECK_MESSAGE(it->second == entry.second,
                            phase << ": private key material changed for "
                                  << entry.first.ToString());
    }

    BOOST_CHECK_MESSAGE((actual.keyPool.size()) == (expected.keyPool.size()),
                        phase << ": keypool size changed");
    BOOST_CHECK_MESSAGE(expected.keyPool == actual.keyPool,
                        phase << ": keypool indices changed");
    BOOST_CHECK_MESSAGE((actual.keyPoolEntries.size()) == (expected.keyPoolEntries.size()),
                        phase << ": keypool record count changed");
    for (const auto &entry : expected.keyPoolEntries) {
        const auto it = actual.keyPoolEntries.find(entry.first);
        BOOST_REQUIRE_MESSAGE(it != actual.keyPoolEntries.end(),
                              phase << ": keypool record missing for index "
                                    << entry.first);
        BOOST_CHECK_MESSAGE((it->second.nTime) == (entry.second.nTime),
                            phase << ": keypool time changed");
        BOOST_CHECK_MESSAGE(it->second.vchPubKey == entry.second.vchPubKey,
                            phase << ": keypool key changed for index "
                                  << entry.first);
    }

    BOOST_CHECK_MESSAGE((actual.addressBook.size()) == (expected.addressBook.size()),
                        phase << ": address book size changed");
    for (const auto &entry : expected.addressBook) {
        const auto it = actual.addressBook.find(entry.first);
        BOOST_REQUIRE_MESSAGE(it != actual.addressBook.end(),
                              phase << ": address book entry missing");
        BOOST_CHECK_MESSAGE((it->second) == (entry.second),
                            phase << ": address label changed");
    }

    BOOST_CHECK_MESSAGE((actual.watchOnly.size()) == (expected.watchOnly.size()),
                        phase << ": watch-only probe set changed");
    for (const auto &entry : expected.watchOnly) {
        const auto it = actual.watchOnly.find(entry.first);
        BOOST_REQUIRE_MESSAGE(it != actual.watchOnly.end(),
                              phase << ": watch-only probe missing");
        BOOST_CHECK_MESSAGE((it->second) == (entry.second),
                            phase << ": watch-only script state changed");
    }

    BOOST_CHECK_MESSAGE((actual.scripts.size()) == (expected.scripts.size()),
                        phase << ": script probe set changed");
    for (const auto &entry : expected.scripts) {
        const auto it = actual.scripts.find(entry.first);
        BOOST_REQUIRE_MESSAGE(it != actual.scripts.end(),
                              phase << ": script missing");
        BOOST_CHECK_MESSAGE((it->second.first) == (entry.second.first),
                            phase << ": script presence changed");
        BOOST_CHECK_MESSAGE(it->second.second == entry.second.second,
                            phase << ": script contents changed");
    }

    BOOST_CHECK_MESSAGE((actual.txs.size()) == (expected.txs.size()),
                        phase << ": transaction count changed");
    for (const auto &entry : expected.txs) {
        const auto it = actual.txs.find(entry.first);
        BOOST_REQUIRE_MESSAGE(it != actual.txs.end(),
                              phase << ": transaction missing "
                                    << entry.first.ToString());
        CheckTxEqual(entry.second, it->second, phase);
    }
}

struct BuiltWallet
{
    std::vector<CPubKey> pubKeys;
    std::vector<CScript> scripts;
    std::vector<CScript> watchScripts;
    std::vector<uint256> txids;
};

/**
 * Populates wallet.dat with every record type the migration has to preserve:
 * regular and uncompressed keys, key metadata, a watch-only script, a redeem
 * script, address labels, a default key, a fully populated keypool, and
 * transactions with block, timestamp, order, label, spent and
 * abandoned/conflicted metadata.
 */
static BuiltWallet BuildRichWallet(CWallet &wallet)
{
    BuiltWallet built;

    bool fFirstRun = false;
    BOOST_REQUIRE(wallet.LoadWallet(fFirstRun) == DB_LOAD_OK);

    for (int i = 0; i < 2; ++i) {
        const CPubKey pubKey = wallet.GenerateNewKey();
        built.pubKeys.push_back(pubKey);
    }

    CKey uncompressed;
    uncompressed.MakeNewKey(false);
    BOOST_REQUIRE(wallet.AddKey(uncompressed));
    built.pubKeys.push_back(uncompressed.GetPubKey());

    CKey watchKey;
    watchKey.MakeNewKey(true);
    CScript watchScript;
    watchScript.SetDestination(watchKey.GetPubKey().GetID());
    BOOST_REQUIRE(wallet.AddWatchOnly(watchScript));
    built.watchScripts.push_back(watchScript);

    CScript redeemScript;
    redeemScript << OP_2 << built.pubKeys[0] << built.pubKeys[1] << OP_2
                 << OP_CHECKMULTISIG;
    BOOST_REQUIRE(wallet.AddCScript(redeemScript));
    built.scripts.push_back(redeemScript);

    BOOST_REQUIRE(wallet.SetDefaultKey(built.pubKeys[0]));
    BOOST_REQUIRE(wallet.SetAddressBookName(built.pubKeys[0].GetID(),
                                            "primary"));
    BOOST_REQUIRE(wallet.SetAddressBookName(built.pubKeys[1].GetID(),
                                            "savings"));
    BOOST_REQUIRE(wallet.SetAddressBookName(watchScript.GetID(),
                                            "watch-only"));

    // Reset the single keypool to a known shape.  This wallet has no separate
    // external/internal pool; both roles are exercised in the keypool test.
    BOOST_REQUIRE(wallet.NewKeyPool(4));

    static std::atomic<unsigned int> txNonce(0);
    for (int variant = 0; variant < 2; ++variant) {
        CTransaction tx;
        tx.nVersion = 1;
        tx.nLockTime = 1000 + txNonce.fetch_add(1);

        tx.vin.resize(1);
        if (variant == 0) {
            tx.vin[0].prevout.SetNull();
            tx.vin[0].scriptSig = CScript() << OP_1 << OP_2;
        } else {
            uint256 prev;
            prev.SetHex("00000000000000000000000000000000000000000000000000000000000000ff");
            tx.vin[0].prevout = COutPoint(prev, 0);
            tx.vin[0].scriptSig = CScript() << OP_0;
        }

        tx.vout.resize(2);
        tx.vout[0].nValue = COIN * (1 + variant);
        // Never pay the default key: AddToWallet() would rotate it out of the
        // keypool, which is real wallet behaviour but would make the keypool
        // shape this test compares depend on transaction contents.
        tx.vout[0].scriptPubKey.SetDestination(
            built.pubKeys[1].GetID());
        tx.vout[1].nValue = COIN * 2;
        tx.vout[1].scriptPubKey.SetDestination(
            built.pubKeys[2].GetID());

        CWalletTx wtx(&wallet, tx);
        BOOST_REQUIRE(wallet.AddToWallet(wtx));

        CWalletTx &stored = wallet.mapWallet[tx.GetHash()];
        stored.strFromAccount = (variant == 0) ? "account-a" : "account-b";
        stored.mapValue["comment"] = "migration transaction";
        stored.mapValue["label"] = "tx-label";
        if (variant == 0)
            stored.mapValue["abandoned"] = "1";
        else
            stored.mapValue["conflicted"] = "1";
        stored.hashBlock = (variant == 0)
            ? HashFromHex("00000000000000000000000000000000000000000000000000000000000000aa")
            : uint256();
        stored.nIndex = (variant == 0) ? 3 : -1;
        stored.fTimeReceivedIsTxTime = (variant == 0);
        stored.nTimeReceived = 1300000000u + variant;
        stored.nTimeSmart = 1300000100u + variant;
        stored.fFromMe = (variant != 0);
        stored.MarkSpent(variant % stored.vout.size());
        stored.MarkDirty();
        BOOST_REQUIRE(stored.WriteToDisk());

        built.txids.push_back(stored.GetHash());
    }

    return built;
}

static CWallet *LoadWalletOrFail()
{
    CWallet *wallet = new CWallet("wallet.dat");
    bool fFirstRun = false;
    const DBErrors result = wallet->LoadWallet(fFirstRun);
    BOOST_REQUIRE_MESSAGE(result == DB_LOAD_OK,
                          "wallet load returned " << result);
    return wallet;
}

static void CheckSigningWorks(CWallet &wallet, const CKeyID &keyID,
                              const std::string &phase)
{
    CKey key;
    BOOST_REQUIRE_MESSAGE(wallet.GetKey(keyID, key),
                          phase << ": wallet refused to return the signing key");
    BOOST_CHECK_MESSAGE(key.GetPubKey().GetID() == keyID,
                        phase << ": key does not match its ID");

    const uint256 hash = SerializeHash(std::string("wallet-migration-signing"));
    std::vector<unsigned char> signature;
    BOOST_REQUIRE_MESSAGE(key.Sign(hash, signature),
                          phase << ": signing failed");
    BOOST_CHECK_MESSAGE(key.Verify(hash, signature),
                        phase << ": signature does not verify");
}

struct KeyPoolArgGuard
{
    bool hadValue = false;
    std::string oldValue;

    explicit KeyPoolArgGuard(const std::string &value)
    {
        const auto it = mapArgs.find("-keypool");
        if (it != mapArgs.end()) {
            hadValue = true;
            oldValue = it->second;
        }
        mapArgs["-keypool"] = value;
    }

    ~KeyPoolArgGuard()
    {
        if (hadValue)
            mapArgs["-keypool"] = oldValue;
        else
            mapArgs.erase("-keypool");
    }
};

} // namespace

/**
 * The migration must preserve the wallet's semantic state, not just its record
 * count: keys and metadata, scripts, watch-only entries, address labels,
 * transactions (including order, block association, timestamps and
 * abandoned/conflicted metadata), keypool records, and ordering state.  The
 * raw records are also compared byte-for-byte, which covers encrypted key
 * material that cannot be inspected while the wallet is locked.
 */
BOOST_AUTO_TEST_CASE(wallet_migration_preserves_semantic_state)
{
    TempDirGuard guard("wallet_semantics");
    CloseLMDBWalletDB();

    BuiltWallet built;
    {
        CWallet wallet("wallet.dat");
        built = BuildRichWallet(wallet);
    }

    std::unique_ptr<CWallet> expectedWallet(LoadWalletOrFail());
    const WalletSnapshot expected = CaptureWalletSnapshot(
        *expectedWallet, built.scripts, built.watchScripts);
    expectedWallet.reset();
    const std::map<CDBKey, CDBValue> expectedRecords = CaptureRecords();
    BOOST_REQUIRE(!expectedRecords.empty());
    BOOST_CHECK_GE(CountRecordsOfType(expectedRecords, "key"), 7U);
    BOOST_CHECK_EQUAL(CountRecordsOfType(expectedRecords, "ckey"), 0U);
    BOOST_CHECK_EQUAL(CountRecordsOfType(expectedRecords, "pool"), 4U);

    MigrateMockWallet(guard.dir);

    // The Berkeley DB source survives untouched.
    BOOST_CHECK(std::filesystem::exists(guard.dir / "wallet.dat"));

    std::unique_ptr<CWallet> migratedWallet(LoadWalletOrFail());
    const WalletSnapshot migrated = CaptureWalletSnapshot(
        *migratedWallet, built.scripts, built.watchScripts);
    migratedWallet.reset();

    const std::map<CDBKey, CDBValue> migratedRecords = CaptureRecords();
    BOOST_CHECK_MESSAGE((migratedRecords.size()) == (expectedRecords.size()),
                        "LMDB wallet record count differs");
    BOOST_CHECK_MESSAGE(migratedRecords == expectedRecords,
                        "LMDB wallet records differ from wallet.dat");
    BOOST_CHECK_EQUAL(CountRecordsOfType(migratedRecords, "ckey"), 0U);

    CheckSnapshotsEqual(expected, migrated, "migrated wallet");

    // A restart must load the same wallet state from LMDB only.
    RestartLMDBWallet(guard.dir);

    std::unique_ptr<CWallet> restartedWallet(LoadWalletOrFail());
    const WalletSnapshot restarted = CaptureWalletSnapshot(
        *restartedWallet, built.scripts, built.watchScripts);
    CheckSnapshotsEqual(expected, restarted, "restarted wallet");
}

/**
 * Covers the single keypool this wallet format has.  The "external" side is
 * setKeyPool and its persisted pool records; the "internal" side is a key
 * temporarily removed by ReserveKeyFromKeyPool and then returned or kept.
 * Also checks sequential next indices, ownership of every pool key, and refill
 * after a key is consumed.
 */
BOOST_AUTO_TEST_CASE(wallet_migration_preserves_keypool_lifecycle)
{
    TempDirGuard guard("wallet_keypool");
    CloseLMDBWalletDB();

    BuiltWallet built;
    {
        CWallet wallet("wallet.dat");
        built = BuildRichWallet(wallet);
    }

    std::unique_ptr<CWallet> expectedWallet(LoadWalletOrFail());
    const WalletSnapshot expected = CaptureWalletSnapshot(
        *expectedWallet, built.scripts, built.watchScripts);
    expectedWallet.reset();

    MigrateMockWallet(guard.dir);
    RestartLMDBWallet(guard.dir);

    KeyPoolArgGuard keyPoolArg("4");

    std::unique_ptr<CWallet> wallet(LoadWalletOrFail());
    BOOST_REQUIRE(!wallet->IsCrypted());
    CheckSnapshotsEqual(expected, CaptureWalletSnapshot(
        *wallet, built.scripts, built.watchScripts), "keypool baseline");

    // Every persisted pool record is owned by a wallet key, and the reserve
    // key set is exactly the set of pool public keys.
    std::set<CKeyID> poolKeyIDs;
    {
        CWalletDB db("wallet.dat", "r");
        for (int64 nIndex : wallet->setKeyPool) {
            CKeyPool keypool;
            BOOST_REQUIRE(db.ReadPool(nIndex, keypool));
            BOOST_REQUIRE(keypool.vchPubKey.IsValid());

            const CKeyID keyID = keypool.vchPubKey.GetID();
            poolKeyIDs.insert(keyID);
            BOOST_CHECK_MESSAGE(wallet->HaveKey(keyID),
                                "keypool key " << nIndex << " is not owned");

            CPubKey pubKey;
            BOOST_REQUIRE(wallet->GetPubKey(keyID, pubKey));
            BOOST_CHECK(pubKey == keypool.vchPubKey);
        }
    }

    std::set<CKeyID> reserveKeys;
    wallet->GetAllReserveKeys(reserveKeys);
    BOOST_CHECK(reserveKeys == poolKeyIDs);

    // Refill to target+1 and check the next index continues sequentially.
    const int64 nNextBeforeTopUp = *wallet->setKeyPool.rbegin() + 1;
    BOOST_REQUIRE(wallet->TopUpKeyPool());
    BOOST_CHECK_EQUAL(wallet->setKeyPool.size(), 5U);
    BOOST_CHECK(wallet->setKeyPool.count(nNextBeforeTopUp) == 1);
    BOOST_CHECK_EQUAL(*wallet->setKeyPool.rbegin(), nNextBeforeTopUp);

    // Reserve the oldest key: it leaves the set but its record remains, so a
    // return can put it back exactly where it was.
    const int64 nOldest = *wallet->setKeyPool.begin();
    int64 nReservedIndex = -1;
    CKeyPool reserved;
    wallet->ReserveKeyFromKeyPool(nReservedIndex, reserved);
    BOOST_CHECK_EQUAL(nReservedIndex, nOldest);
    BOOST_CHECK(wallet->setKeyPool.count(nOldest) == 0);
    BOOST_CHECK(reserved.vchPubKey.IsValid());
    {
        CWalletDB db("wallet.dat", "r");
        CKeyPool stored;
        BOOST_REQUIRE(db.ReadPool(nOldest, stored));
        BOOST_CHECK(stored.vchPubKey == reserved.vchPubKey);
    }
    BOOST_CHECK(wallet->HaveKey(reserved.vchPubKey.GetID()));

    wallet->ReturnKey(nReservedIndex);
    BOOST_CHECK(wallet->setKeyPool.count(nOldest) == 1);

    // Keep consumes the reserved key permanently.
    wallet->ReserveKeyFromKeyPool(nReservedIndex, reserved);
    BOOST_REQUIRE_EQUAL(nReservedIndex, nOldest);
    wallet->KeepKey(nReservedIndex);
    BOOST_CHECK(wallet->setKeyPool.count(nOldest) == 0);
    {
        CWalletDB db("wallet.dat", "r");
        CKeyPool stored;
        BOOST_CHECK(!db.ReadPool(nOldest, stored));
    }
    BOOST_CHECK(wallet->HaveKey(reserved.vchPubKey.GetID()));

    // Refill after consumption creates a new sequential index.
    const int64 nNextBeforeRefill = *wallet->setKeyPool.rbegin() + 1;
    BOOST_REQUIRE(wallet->TopUpKeyPool());
    BOOST_CHECK_EQUAL(wallet->setKeyPool.size(), 5U);
    BOOST_CHECK(wallet->setKeyPool.count(nNextBeforeRefill) == 1);
    BOOST_CHECK_EQUAL(*wallet->setKeyPool.rbegin(), nNextBeforeRefill);

    // GetKeyFromPool allocates and keeps the oldest remaining key.
    const int64 nToAllocate = *wallet->setKeyPool.begin();
    CPubKey allocated;
    BOOST_REQUIRE(wallet->GetKeyFromPool(allocated, false));
    BOOST_CHECK(allocated.IsValid());
    BOOST_CHECK(wallet->HaveKey(allocated.GetID()));
    BOOST_CHECK(wallet->setKeyPool.count(nToAllocate) == 0);
    {
        CWalletDB db("wallet.dat", "r");
        CKeyPool stored;
        BOOST_CHECK(!db.ReadPool(nToAllocate, stored));
    }
}

/**
 * Encryption lifecycle on a migrated wallet:
 *
 *   unencrypted -> migrate -> sign -> encrypt -> restart
 *               -> still encrypted -> unlock -> sign -> lock
 *               -> restart -> unlock -> sign
 *
 * It also checks that encryption removes every plaintext key record and that
 * the compacted LMDB files no longer contain the old private-key bytes.
 */
BOOST_AUTO_TEST_CASE(wallet_migration_encryption_lifecycle)
{
    TempDirGuard guard("wallet_encryption");
    CloseLMDBWalletDB();

    BuiltWallet built;
    {
        CWallet wallet("wallet.dat");
        built = BuildRichWallet(wallet);
    }

    MigrateMockWallet(guard.dir);

    const SecureString passphrase("correct horse battery staple\n");
    const SecureString wrongPassphrase("not the passphrase\n");

    const std::map<CDBKey, CDBValue> plaintextRecords = CaptureRecords();
    BOOST_CHECK_GE(CountRecordsOfType(plaintextRecords, "key"), 7U);
    BOOST_CHECK_EQUAL(CountRecordsOfType(plaintextRecords, "ckey"), 0U);

    std::unique_ptr<CWallet> wallet(LoadWalletOrFail());
    BOOST_REQUIRE(!wallet->IsCrypted());
    BOOST_REQUIRE(!wallet->IsLocked());

    // An unencrypted migrated wallet can sign straight away.
    const CKeyID signingKeyID = built.pubKeys[0].GetID();
    CheckSigningWorks(*wallet, signingKeyID, "unencrypted migrated wallet");

    // Remember the plaintext secrets so the on-disk scan below can prove they
    // are gone after encryption and compaction.
    std::vector<CPrivKey> plaintextSecrets;
    {
        std::set<CKeyID> keyIDs;
        wallet->GetKeys(keyIDs);
        for (const CKeyID &keyID : keyIDs) {
            CKey key;
            if (wallet->GetKey(keyID, key)) {
                const CPrivKey secret = key.GetPrivKey();
                plaintextSecrets.push_back(secret);
            }
        }
    }
    BOOST_REQUIRE(!plaintextSecrets.empty());

    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->IsLocked());

    // The encrypted wallet must not retain plaintext key records and must
    // carry encrypted key and master-key records instead.
    const std::map<CDBKey, CDBValue> encryptedRecords = CaptureRecords();
    BOOST_CHECK_EQUAL(CountRecordsOfType(encryptedRecords, "key"), 0U);
    BOOST_CHECK_EQUAL(CountRecordsOfType(encryptedRecords, "wkey"), 0U);
    BOOST_CHECK_GT(CountRecordsOfType(encryptedRecords, "ckey"), 0U);
    BOOST_CHECK_GT(CountRecordsOfType(encryptedRecords, "mkey"), 0U);

    // Locked means the key material is not reachable.
    CKey lockedKey;
    BOOST_CHECK(!wallet->GetKey(signingKeyID, lockedKey));
    wallet.reset();

    // Restart: the migration target must still be an encrypted wallet.
    RestartLMDBWallet(guard.dir);

    std::unique_ptr<CWallet> restarted(LoadWalletOrFail());
    BOOST_CHECK(restarted->IsCrypted());
    BOOST_CHECK(restarted->IsLocked());
    BOOST_CHECK(!restarted->Unlock(wrongPassphrase));
    BOOST_CHECK(restarted->IsLocked());
    BOOST_REQUIRE(restarted->Unlock(passphrase));
    BOOST_CHECK(!restarted->IsLocked());
    CheckSigningWorks(*restarted, signingKeyID, "unlocked after restart");

    BOOST_REQUIRE(restarted->Lock());
    BOOST_CHECK(restarted->IsLocked());
    restarted.reset();

    // A second restart still loads a locked wallet, and unlocking works again.
    RestartLMDBWallet(guard.dir);

    std::unique_ptr<CWallet> secondRestart(LoadWalletOrFail());
    BOOST_CHECK(secondRestart->IsCrypted());
    BOOST_CHECK(secondRestart->IsLocked());
    BOOST_REQUIRE(secondRestart->Unlock(passphrase));
    CheckSigningWorks(*secondRestart, signingKeyID, "unlocked after second restart");
    BOOST_REQUIRE(secondRestart->Lock());

    // No plaintext private-key bytes may survive in the compacted environment.
    const std::filesystem::path dataFile = guard.dir / "wallet" / "data.mdb";
    BOOST_REQUIRE(std::filesystem::exists(dataFile));
    for (const CPrivKey &secret : plaintextSecrets) {
        BOOST_CHECK_MESSAGE(!FileContainsBytes(dataFile, secret),
                            "plaintext private key material leaked into "
                            "the LMDB wallet");
    }
}

BOOST_AUTO_TEST_SUITE_END()
