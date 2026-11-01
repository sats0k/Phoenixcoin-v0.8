// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <functional>
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
#include "hs/rpchybrid.h"
#include "hs/walletdb_hybrid.h"
#include "hs/wallethybrid.h"
#include "key.h"
#include "main.h"
#include "script.h"
#include "util.h"
#include "wallet.h"
#include "walletdb.h"

extern CWallet *pwalletMain;

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

/**
 * Summarizes how two wallet record sets differ, by record type.  Used in test
 * failure messages so an unexpected write names the record family that leaked
 * instead of dumping raw keys.
 */
static std::string DescribeRecordDelta(
    const std::map<CDBKey, CDBValue> &before,
    const std::map<CDBKey, CDBValue> &after)
{
    std::map<std::string, std::pair<size_t, size_t>> counts;
    for (const auto &record : before)
        ++counts[RecordType(record.first)].first;
    for (const auto &record : after)
        ++counts[RecordType(record.first)].second;

    std::string delta;
    for (const auto &entry : counts) {
        if (entry.second.first == entry.second.second)
            continue;
        if (!delta.empty())
            delta += ", ";
        delta += entry.first + " " + std::to_string(entry.second.first) +
                 "->" + std::to_string(entry.second.second);
    }
    return delta.empty() ? std::string("no record-count change") : delta;
}

/** Returns the key IDs carried by "key"/"ckey" records. */
static std::set<CKeyID> KeyRecordIDs(const std::map<CDBKey, CDBValue> &records,
                                     const std::string &type)
{
    std::set<CKeyID> ids;
    for (const auto &record : records) {
        if (RecordType(record.first) != type)
            continue;

        CDataStream ss(SER_DISK, CLIENT_VERSION);
        if (!record.first.empty())
            ss.write((const char *)&record.first[0], record.first.size());

        std::string recordType;
        std::vector<unsigned char> rawPubKey;
        try {
            ss >> recordType >> rawPubKey;
        } catch (...) {
            continue;
        }

        const CPubKey pubKey(rawPubKey);
        if (pubKey.IsValid())
            ids.insert(pubKey.GetID());
    }
    return ids;
}

/** Returns the hybrid IDs carried by "hyb"/"hybaddr" records. */
static std::set<CHybridKeyID>
HybridRecordIDs(const std::map<CDBKey, CDBValue> &records,
                const std::string &type)
{
    std::set<CHybridKeyID> ids;
    for (const auto &record : records) {
        if (RecordType(record.first) != type)
            continue;

        CDataStream ss(SER_DISK, CLIENT_VERSION);
        if (!record.first.empty())
            ss.write((const char *)&record.first[0], record.first.size());

        std::string recordType;
        CHybridKeyID hybridID;
        try {
            ss >> recordType >> hybridID;
        } catch (...) {
            continue;
        }
        ids.insert(hybridID);
    }
    return ids;
}

/** Parses the at-rest "hyb" records into their disk representation. */
static std::map<CHybridKeyID, CHybridKeyDisk>
ReadHybridDiskRecords(const std::map<CDBKey, CDBValue> &records)
{
    std::map<CHybridKeyID, CHybridKeyDisk> disks;
    for (const auto &record : records) {
        if (RecordType(record.first) != "hyb")
            continue;

        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (!record.first.empty())
            ssKey.write((const char *)&record.first[0], record.first.size());

        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        if (!record.second.empty())
            ssValue.write((const char *)&record.second[0], record.second.size());

        std::string recordType;
        CHybridKeyID hybridID;
        CHybridKeyDisk disk;
        try {
            ssKey >> recordType >> hybridID;
            ssValue >> disk;
        } catch (...) {
            continue;
        }
        disks[hybridID] = disk;
    }
    return disks;
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

struct HybridKeySnapshot
{
    CPrivKey secpPriv;
    CPubKey secpPub;
    std::string mldsaAlg;
    int64 nCreateTime = 0;
    bool haveSigner = false;
    std::vector<unsigned char> mldsaPubKey;
};

struct HybridKeyDiskSnapshot
{
    uint8_t nVersion = 0;
    int32_t nCreateTime = 0;
    CPrivKey secpPriv;
    CPubKey secpPub;
    std::string mldsaAlg;
    std::vector<unsigned char> mldsaPrivKey;
    std::vector<unsigned char> vchCryptedPrivate;
    uint256 hashChecksum;
    bool fLegacyDisk = false;
};

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
    std::map<CHybridKeyID, HybridKeySnapshot> hybridKeys;
    std::map<CHybridKeyID, HybridKeyDiskSnapshot> hybridKeyDisk;
    std::map<CHybridKeyID, CHybridAddressEntry> hybridAddressBook;
    std::set<CHybridKeyID> usedHybridKeys;
    std::set<CHybridKeyID> unusedHybridKeys;
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
 * that state in CWalletTx::mapValue, which is compared verbatim.  Hybrid keys
 * are captured separately from the ordinary keystore: the decrypted key with
 * its embedded ML-DSA signer, the encrypted/plain at-rest disk form, and the
 * hybrid address book.
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

    // Hybrid keys live in three places: the decrypted in-memory map (with the
    // ML-DSA signer embedded in CHybridKey, there is no separate signer map),
    // the encrypted-at-rest disk map, and the hybrid address book.  All three
    // must survive migration unchanged.
    for (const auto &entry : wallet.mapHybridKeys) {
        HybridKeySnapshot hybrid;
        hybrid.secpPriv = entry.second.secpPriv;
        hybrid.secpPub = entry.second.secpPub;
        hybrid.mldsaAlg = entry.second.mldsaAlg;
        hybrid.nCreateTime = entry.second.nCreateTime;
        hybrid.haveSigner = entry.second.mldsaSigner != nullptr;
        if (entry.second.mldsaSigner)
            hybrid.mldsaPubKey = entry.second.mldsaSigner->GetPublicKey();
        snapshot.hybridKeys[entry.first] = hybrid;
    }

    for (const auto &entry : wallet.mapHybridKeyDisk) {
        HybridKeyDiskSnapshot disk;
        disk.nVersion = entry.second.nVersion;
        disk.nCreateTime = entry.second.nCreateTime;
        disk.secpPriv = entry.second.secpPriv;
        disk.secpPub = entry.second.secpPub;
        disk.mldsaAlg = entry.second.mldsaAlg;
        disk.mldsaPrivKey = entry.second.mldsaPrivKey;
        disk.vchCryptedPrivate = entry.second.vchCryptedPrivate;
        disk.hashChecksum = entry.second.hashChecksum;
        disk.fLegacyDisk = entry.second.fLegacyDisk;
        snapshot.hybridKeyDisk[entry.first] = disk;
    }

    snapshot.hybridAddressBook = wallet.mapHybridAddressBook;
    snapshot.usedHybridKeys = wallet.setUsedHybridKeys;
    snapshot.unusedHybridKeys = wallet.setUnusedHybridKeys;

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

    BOOST_CHECK_MESSAGE((actual.hybridKeys.size()) == (expected.hybridKeys.size()),
                        phase << ": hybrid key count changed");
    for (const auto &entry : expected.hybridKeys) {
        const auto it = actual.hybridKeys.find(entry.first);
        BOOST_REQUIRE_MESSAGE(it != actual.hybridKeys.end(),
                              phase << ": hybrid key missing for "
                                    << entry.first.ToString());
        BOOST_CHECK_MESSAGE(it->second.secpPriv == entry.second.secpPriv,
                            phase << ": hybrid ECDSA secret changed for "
                                  << entry.first.ToString());
        BOOST_CHECK_MESSAGE(it->second.secpPub == entry.second.secpPub,
                            phase << ": hybrid ECDSA public key changed for "
                                  << entry.first.ToString());
        BOOST_CHECK_MESSAGE((it->second.mldsaAlg) == (entry.second.mldsaAlg),
                            phase << ": hybrid ML-DSA algorithm changed for "
                                  << entry.first.ToString());
        BOOST_CHECK_MESSAGE((it->second.nCreateTime) == (entry.second.nCreateTime),
                            phase << ": hybrid creation time changed for "
                                  << entry.first.ToString());
        BOOST_CHECK_MESSAGE((it->second.haveSigner) == (entry.second.haveSigner),
                            phase << ": hybrid signer presence changed for "
                                  << entry.first.ToString());
        BOOST_CHECK_MESSAGE(it->second.mldsaPubKey == entry.second.mldsaPubKey,
                            phase << ": hybrid ML-DSA public key changed for "
                                  << entry.first.ToString());
    }

    BOOST_CHECK_MESSAGE((actual.hybridKeyDisk.size()) == (expected.hybridKeyDisk.size()),
                        phase << ": hybrid disk record count changed");
    for (const auto &entry : expected.hybridKeyDisk) {
        const auto it = actual.hybridKeyDisk.find(entry.first);
        BOOST_REQUIRE_MESSAGE(it != actual.hybridKeyDisk.end(),
                              phase << ": hybrid disk record missing for "
                                    << entry.first.ToString());
        BOOST_CHECK_MESSAGE((it->second.nVersion) == (entry.second.nVersion),
                            phase << ": hybrid disk version changed");
        BOOST_CHECK_MESSAGE((it->second.nCreateTime) == (entry.second.nCreateTime),
                            phase << ": hybrid disk creation time changed");
        BOOST_CHECK_MESSAGE(it->second.secpPriv == entry.second.secpPriv,
                            phase << ": hybrid disk ECDSA secret changed");
        BOOST_CHECK_MESSAGE(it->second.secpPub == entry.second.secpPub,
                            phase << ": hybrid disk ECDSA public key changed");
        BOOST_CHECK_MESSAGE((it->second.mldsaAlg) == (entry.second.mldsaAlg),
                            phase << ": hybrid disk ML-DSA algorithm changed");
        BOOST_CHECK_MESSAGE(it->second.mldsaPrivKey == entry.second.mldsaPrivKey,
                            phase << ": hybrid disk ML-DSA secret changed");
        BOOST_CHECK_MESSAGE(it->second.vchCryptedPrivate ==
                                entry.second.vchCryptedPrivate,
                            phase << ": hybrid disk encrypted secret changed");
        BOOST_CHECK_MESSAGE(it->second.hashChecksum == entry.second.hashChecksum,
                            phase << ": hybrid disk checksum changed");
        BOOST_CHECK_MESSAGE((it->second.fLegacyDisk) == (entry.second.fLegacyDisk),
                            phase << ": hybrid disk layout flag changed");
    }

    BOOST_CHECK_MESSAGE((actual.hybridAddressBook.size()) ==
                            (expected.hybridAddressBook.size()),
                        phase << ": hybrid address book size changed");
    for (const auto &entry : expected.hybridAddressBook) {
        const auto it = actual.hybridAddressBook.find(entry.first);
        BOOST_REQUIRE_MESSAGE(it != actual.hybridAddressBook.end(),
                              phase << ": hybrid address label missing for "
                                    << entry.first.ToString());
        BOOST_CHECK_MESSAGE((it->second.nVersion) == (entry.second.nVersion),
                            phase << ": hybrid address entry version changed");
        BOOST_CHECK_MESSAGE((it->second.nCreateTime) == (entry.second.nCreateTime),
                            phase << ": hybrid address creation time changed");
        BOOST_CHECK_MESSAGE((it->second.strLabel) == (entry.second.strLabel),
                            phase << ": hybrid address label changed");
        BOOST_CHECK_MESSAGE((it->second.strPurpose) == (entry.second.strPurpose),
                            phase << ": hybrid address purpose changed");
    }

    BOOST_CHECK_MESSAGE(expected.usedHybridKeys == actual.usedHybridKeys,
                        phase << ": used hybrid key set changed");
    BOOST_CHECK_MESSAGE(expected.unusedHybridKeys == actual.unusedHybridKeys,
                        phase << ": unused hybrid key set changed");

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

    // Loading the wallet has already topped up the hybrid key pool.  Label one
    // of those keys so the hybrid address book and its "hybaddr" record are
    // part of the state the migration has to preserve.
    BOOST_REQUIRE(!wallet.mapHybridKeys.empty());
    const CHybridKeyID labelledHybridID = wallet.mapHybridKeys.begin()->first;
    BOOST_REQUIRE(wallet.SetHybridAddressBookName(labelledHybridID,
                                                  "hybrid savings"));

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

/**
 * Every hybrid key has three representations that must agree: the legacy
 * ECDSA key in the normal keystore, the hybrid record keyed by CHybridKeyID,
 * and the embedded ML-DSA signer.  This is the invariant the atomic import and
 * the wallet migration both have to preserve.
 */
static void CheckHybridKeyInvariants(CWallet &wallet, const std::string &phase)
{
    BOOST_REQUIRE_MESSAGE(!wallet.IsLocked(),
                          phase << ": hybrid invariants need an unlocked wallet");

    for (const auto &entry : wallet.mapHybridKeys) {
        const CHybridKey &hybrid = entry.second;
        BOOST_REQUIRE_MESSAGE(hybrid.mldsaSigner != nullptr,
                              phase << ": hybrid key has no ML-DSA signer");

        const CKeyID keyID = hybrid.GetKeyID();
        BOOST_CHECK_MESSAGE(wallet.HaveKey(keyID),
                            phase << ": hybrid key has no legacy ECDSA key for "
                                  << entry.first.ToString());

        CPubKey pubKey;
        BOOST_REQUIRE_MESSAGE(wallet.GetPubKey(keyID, pubKey),
                              phase << ": legacy ECDSA public key missing for "
                                    << entry.first.ToString());
        BOOST_CHECK_MESSAGE(pubKey == hybrid.secpPub,
                            phase << ": legacy ECDSA public key changed for "
                                  << entry.first.ToString());

        CKey ecdsa;
        BOOST_REQUIRE_MESSAGE(wallet.GetKey(keyID, ecdsa),
                              phase << ": legacy ECDSA secret missing for "
                                    << entry.first.ToString());
        BOOST_CHECK_MESSAGE(ecdsa.GetPrivKey() == hybrid.secpPriv,
                            phase << ": legacy ECDSA secret changed for "
                                  << entry.first.ToString());

        BOOST_CHECK_MESSAGE(wallet.HaveHybridKey(entry.first),
                            phase << ": hybrid record missing for "
                                  << entry.first.ToString());

        CHybridKey loaded;
        BOOST_REQUIRE_MESSAGE(wallet.GetHybridKey(entry.first, loaded),
                              phase << ": wallet cannot load hybrid key "
                                    << entry.first.ToString());
        BOOST_REQUIRE(loaded.mldsaSigner != nullptr);
        BOOST_CHECK_MESSAGE(loaded.GetHybridID() == entry.first,
                            phase << ": hybrid record does not match its ID");
        BOOST_CHECK_MESSAGE(loaded.mldsaSigner->GetPublicKey() ==
                                hybrid.mldsaSigner->GetPublicKey(),
                            phase << ": hybrid ML-DSA signer changed for "
                                  << entry.first.ToString());
    }
}

static void CheckHybridSigningWorks(CWallet &wallet,
                                    const CHybridKeyID &hybridID,
                                    const std::string &phase)
{
    CHybridKey hybrid;
    BOOST_REQUIRE_MESSAGE(wallet.GetHybridKey(hybridID, hybrid),
                          phase << ": wallet cannot load the hybrid key");
    BOOST_REQUIRE(hybrid.mldsaSigner != nullptr);

    const std::string message = "wallet migration hybrid signature";
    std::vector<unsigned char> signature;
    BOOST_REQUIRE_MESSAGE(SignHybridMessage(hybrid, message, signature),
                          phase << ": hybrid signing failed");
    BOOST_CHECK_MESSAGE(VerifyHybridMessage(signature, hybridID, message),
                        phase << ": hybrid signature does not verify");

    // The ECDSA half must remain usable through the legacy keystore as well.
    CheckSigningWorks(wallet, hybrid.GetKeyID(), phase);
}

/** Temporarily points the RPC handlers at a test wallet. */
struct WalletMainGuard
{
    CWallet *previous;

    explicit WalletMainGuard(CWallet *wallet) : previous(pwalletMain)
    {
        pwalletMain = wallet;
    }

    ~WalletMainGuard() { pwalletMain = previous; }
};

static std::string JsonStringField(const json_spirit::Object &object,
                                   const std::string &name)
{
    return json_spirit::find_value(object, name).get_str();
}

static json_spirit::Object DumpHybridKeyRPC(CWallet &wallet,
                                            const std::string &address)
{
    json_spirit::Array params;
    params.push_back(address);

    WalletMainGuard guard(&wallet);
    return dumphybridkey(params, false).get_obj();
}

static std::string ImportHybridKeyRPC(CWallet &wallet, const std::string &wif,
                                      const std::string &derBase64,
                                      const std::string &label)
{
    json_spirit::Array params;
    params.push_back(wif);
    params.push_back(derBase64);
    params.push_back(label);
    params.push_back(false); // do not rescan the block chain

    WalletMainGuard guard(&wallet);
    return importhybridkey(params, false).get_str();
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
    CheckHybridKeyInvariants(*expectedWallet, "wallet.dat");
    const WalletSnapshot expected = CaptureWalletSnapshot(
        *expectedWallet, built.scripts, built.watchScripts);
    expectedWallet.reset();

    std::set<CHybridKeyID> expectedHybridIDs;
    for (const auto &entry : expected.hybridKeys)
        expectedHybridIDs.insert(entry.first);

    std::set<CHybridKeyID> expectedHybridAddressIDs;
    for (const auto &entry : expected.hybridAddressBook)
        expectedHybridAddressIDs.insert(entry.first);

    const std::map<CDBKey, CDBValue> expectedRecords = CaptureRecords();
    BOOST_REQUIRE(!expectedRecords.empty());
    BOOST_CHECK_GE(CountRecordsOfType(expectedRecords, "key"), 7U);
    BOOST_CHECK_EQUAL(CountRecordsOfType(expectedRecords, "ckey"), 0U);
    BOOST_CHECK_EQUAL(CountRecordsOfType(expectedRecords, "pool"), 4U);
    BOOST_CHECK_MESSAGE(expectedHybridIDs ==
                            HybridRecordIDs(expectedRecords, "hyb"),
                        "wallet.dat hybrid records do not match the loaded keys");
    BOOST_CHECK_MESSAGE(expectedHybridAddressIDs ==
                            HybridRecordIDs(expectedRecords, "hybaddr"),
                        "wallet.dat hybrid address records do not match the "
                        "loaded address book");

    std::set<CKeyID> expectedHybridLegacyIDs;
    for (const auto &entry : expected.hybridKeys)
        expectedHybridLegacyIDs.insert(entry.second.secpPub.GetID());
    const std::set<CKeyID> expectedKeyRecords =
        KeyRecordIDs(expectedRecords, "key");
    for (const CKeyID &keyID : expectedHybridLegacyIDs) {
        BOOST_CHECK_MESSAGE(expectedKeyRecords.count(keyID) == 1,
                            "wallet.dat has no legacy ECDSA key record for "
                            "hybrid key "
                                << keyID.ToString());
    }

    // The at-rest hybrid records and the in-memory keys must describe the same
    // keys, with a valid checksum and plaintext private material while the
    // wallet is unencrypted.
    const std::map<CHybridKeyID, CHybridKeyDisk> expectedDisks =
        ReadHybridDiskRecords(expectedRecords);
    BOOST_CHECK_EQUAL(expectedDisks.size(), expectedHybridIDs.size());
    for (const auto &entry : expectedDisks) {
        const auto memory = expected.hybridKeys.find(entry.first);
        BOOST_REQUIRE(memory != expected.hybridKeys.end());
        BOOST_CHECK(entry.second.CheckChecksum());
        BOOST_CHECK(!entry.second.IsEncrypted());
        BOOST_CHECK(!entry.second.secpPriv.empty());
        BOOST_CHECK(!entry.second.mldsaPrivKey.empty());
        BOOST_CHECK(entry.second.secpPub == memory->second.secpPub);
        BOOST_CHECK_EQUAL(entry.second.nCreateTime, memory->second.nCreateTime);
        BOOST_CHECK_EQUAL(entry.second.mldsaAlg, memory->second.mldsaAlg);
    }

    MigrateMockWallet(guard.dir);

    // The Berkeley DB source survives untouched.
    BOOST_CHECK(std::filesystem::exists(guard.dir / "wallet.dat"));

    std::unique_ptr<CWallet> migratedWallet(LoadWalletOrFail());
    CheckHybridKeyInvariants(*migratedWallet, "migrated wallet");
    const WalletSnapshot migrated = CaptureWalletSnapshot(
        *migratedWallet, built.scripts, built.watchScripts);
    migratedWallet.reset();

    const std::map<CDBKey, CDBValue> migratedRecords = CaptureRecords();
    BOOST_CHECK_MESSAGE((migratedRecords.size()) == (expectedRecords.size()),
                        "LMDB wallet record count differs");
    BOOST_CHECK_MESSAGE(migratedRecords == expectedRecords,
                        "LMDB wallet records differ from wallet.dat");
    BOOST_CHECK_EQUAL(CountRecordsOfType(migratedRecords, "ckey"), 0U);
    BOOST_CHECK_MESSAGE(expectedHybridIDs ==
                            HybridRecordIDs(migratedRecords, "hyb"),
                        "LMDB wallet lost hybrid key records");
    BOOST_CHECK_MESSAGE(expectedHybridAddressIDs ==
                            HybridRecordIDs(migratedRecords, "hybaddr"),
                        "LMDB wallet lost hybrid address records");
    BOOST_CHECK_MESSAGE(KeyRecordIDs(migratedRecords, "key") ==
                            expectedKeyRecords,
                        "LMDB wallet changed legacy ECDSA key records");
    BOOST_CHECK_MESSAGE(ReadHybridDiskRecords(migratedRecords).size() ==
                            expectedDisks.size(),
                        "LMDB wallet hybrid disk record count changed");

    CheckSnapshotsEqual(expected, migrated, "migrated wallet");

    // A restart must load the same wallet state from LMDB only.
    RestartLMDBWallet(guard.dir);

    std::unique_ptr<CWallet> restartedWallet(LoadWalletOrFail());
    CheckHybridKeyInvariants(*restartedWallet, "restarted wallet");
    const WalletSnapshot restarted = CaptureWalletSnapshot(
        *restartedWallet, built.scripts, built.watchScripts);
    CheckSnapshotsEqual(expected, restarted, "restarted wallet");

    const std::map<CDBKey, CDBValue> restartedRecords = CaptureRecords();
    BOOST_CHECK_MESSAGE(expectedHybridIDs ==
                            HybridRecordIDs(restartedRecords, "hyb"),
                        "restarted LMDB wallet lost hybrid key records");
    BOOST_CHECK_MESSAGE(expectedHybridAddressIDs ==
                            HybridRecordIDs(restartedRecords, "hybaddr"),
                        "restarted LMDB wallet lost hybrid address records");
    BOOST_CHECK_MESSAGE(expectedKeyRecords ==
                            KeyRecordIDs(restartedRecords, "key"),
                        "restarted LMDB wallet changed legacy ECDSA key records");
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
 * Hybrid import/export round-trip on the LMDB wallet:
 *
 *   importhybridkey -> dumphybridkey -> restart -> dumphybridkey -> sign -> verify
 *
 * The imported key must create all three links of the hybrid invariant: the
 * legacy ECDSA key, the "hyb" hybrid record, and (with a label) the "hybaddr"
 * address-book record.  All three have to survive a restart and still sign.
 */
BOOST_AUTO_TEST_CASE(wallet_migration_hybrid_import_roundtrip)
{
    TempDirGuard guard("wallet_hybrid_import");
    CloseLMDBWalletDB();

    BuiltWallet built;
    {
        CWallet wallet("wallet.dat");
        built = BuildRichWallet(wallet);
    }

    MigrateMockWallet(guard.dir);

    // Build a standalone hybrid key outside the wallet and export it through
    // the real dumphybridkey RPC path, just as a user's backup would.
    CWallet source;
    CHybridKey sourceKey;
    GenerateHybridKey(sourceKey);
    const CHybridKeyID sourceHybridID = sourceKey.GetHybridID();
    const CKeyID sourceLegacyID = sourceKey.GetKeyID();
    BOOST_REQUIRE(source.AddKey(sourceKey.GetCKey()));
    source.mapHybridKeys.emplace(sourceHybridID, std::move(sourceKey));

    const std::string sourceAddress = CCoinAddress(sourceHybridID).ToString();
    const json_spirit::Object exported = DumpHybridKeyRPC(source, sourceAddress);
    const std::string wif = JsonStringField(exported, "secp_wif");
    const std::string derBase64 =
        JsonStringField(exported, "mldsa_priv_der_b64");
    BOOST_CHECK_EQUAL(JsonStringField(exported, "address"), sourceAddress);
    BOOST_CHECK_EQUAL(JsonStringField(exported, "mldsa_alg"), "p384_mldsa65");
    BOOST_REQUIRE(!wif.empty());
    BOOST_REQUIRE(!derBase64.empty());

    const std::map<CDBKey, CDBValue> beforeImport = CaptureRecords();
    const size_t hybridRecordsBefore = CountRecordsOfType(beforeImport, "hyb");

    {
        std::unique_ptr<CWallet> wallet(LoadWalletOrFail());
        const std::string importedAddress = ImportHybridKeyRPC(
            *wallet, wif, derBase64, "imported hybrid");
        BOOST_CHECK_EQUAL(importedAddress, sourceAddress);

        CheckHybridKeyInvariants(*wallet, "imported wallet");
        BOOST_CHECK(wallet->HaveHybridKey(sourceHybridID));
        BOOST_CHECK(wallet->HaveKey(sourceLegacyID));

        const auto label = wallet->mapHybridAddressBook.find(sourceHybridID);
        BOOST_REQUIRE(label != wallet->mapHybridAddressBook.end());
        BOOST_CHECK_EQUAL(label->second.strLabel, "imported hybrid");

        // dumphybridkey on the wallet must reproduce the imported material.
        const json_spirit::Object dumped =
            DumpHybridKeyRPC(*wallet, sourceAddress);
        BOOST_CHECK_EQUAL(JsonStringField(dumped, "secp_wif"), wif);
        BOOST_CHECK_EQUAL(JsonStringField(dumped, "mldsa_priv_der_b64"),
                          derBase64);
    }

    const std::map<CDBKey, CDBValue> afterImport = CaptureRecords();
    BOOST_CHECK_EQUAL(CountRecordsOfType(afterImport, "hyb"),
                      hybridRecordsBefore + 1);
    BOOST_CHECK(HybridRecordIDs(afterImport, "hyb").count(sourceHybridID) == 1);
    BOOST_CHECK(HybridRecordIDs(afterImport, "hybaddr").count(sourceHybridID) ==
                1);
    BOOST_CHECK(KeyRecordIDs(afterImport, "key").count(sourceLegacyID) == 1);

    const std::map<CHybridKeyID, CHybridKeyDisk> importedDisks =
        ReadHybridDiskRecords(afterImport);
    const auto importedDisk = importedDisks.find(sourceHybridID);
    BOOST_REQUIRE(importedDisk != importedDisks.end());
    BOOST_CHECK(importedDisk->second.CheckChecksum());
    BOOST_CHECK(importedDisk->second.secpPub.GetID() == sourceLegacyID);
    BOOST_CHECK(!importedDisk->second.fLegacyDisk);

    // Restart and repeat the dump from the LMDB wallet only.
    RestartLMDBWallet(guard.dir);

    std::unique_ptr<CWallet> restarted(LoadWalletOrFail());
    CheckHybridKeyInvariants(*restarted, "imported wallet after restart");

    const json_spirit::Object redumped =
        DumpHybridKeyRPC(*restarted, sourceAddress);
    BOOST_CHECK_EQUAL(JsonStringField(redumped, "secp_wif"), wif);
    BOOST_CHECK_EQUAL(JsonStringField(redumped, "mldsa_priv_der_b64"),
                      derBase64);

    const std::map<CDBKey, CDBValue> afterRestart = CaptureRecords();
    BOOST_CHECK(HybridRecordIDs(afterRestart, "hyb").count(sourceHybridID) == 1);
    BOOST_CHECK(HybridRecordIDs(afterRestart, "hybaddr").count(sourceHybridID) ==
                1);
    BOOST_CHECK(KeyRecordIDs(afterRestart, "key").count(sourceLegacyID) == 1);

    CheckHybridSigningWorks(*restarted, sourceHybridID,
                            "imported wallet after restart");
}

struct ExportedHybridKey
{
    CHybridKeyID hybridID;
    CKeyID legacyID;
    std::string address;
    std::string wif;
    std::string derBase64;
};

/** Creates a hybrid key outside the wallet and exports it through the RPC. */
static ExportedHybridKey MakeExportedHybridKey()
{
    CWallet source;
    CHybridKey sourceKey;
    GenerateHybridKey(sourceKey);

    ExportedHybridKey exported;
    exported.hybridID = sourceKey.GetHybridID();
    exported.legacyID = sourceKey.GetKeyID();

    BOOST_REQUIRE(source.AddKey(sourceKey.GetCKey()));
    source.mapHybridKeys.emplace(exported.hybridID, std::move(sourceKey));

    exported.address = CCoinAddress(exported.hybridID).ToString();
    const json_spirit::Object dumped =
        DumpHybridKeyRPC(source, exported.address);
    exported.wif = JsonStringField(dumped, "secp_wif");
    exported.derBase64 = JsonStringField(dumped, "mldsa_priv_der_b64");
    BOOST_REQUIRE(!exported.wif.empty());
    BOOST_REQUIRE(!exported.derBase64.empty());
    return exported;
}

/**
 * Runs one hybrid import with a failure injected at failureType (or at the
 * commit when fFailCommit is set), then proves that the aborted transaction
 * left neither in-memory nor on-disk state behind.  The one-shot injection is
 * consumed by the failed attempt, so the identical retry must succeed.
 */
static void RunHybridImportRollback(const std::string &tag,
                                    const std::string &failureType,
                                    bool fFailCommit)
{
    TempDirGuard guard("hybrid_atomic_" + tag);
    CloseLMDBWalletDB();

    BuiltWallet built;
    {
        CWallet wallet("wallet.dat");
        built = BuildRichWallet(wallet);
    }
    MigrateMockWallet(guard.dir);

    const ExportedHybridKey imported = MakeExportedHybridKey();

    // Load first: opening the wallet may normalise/backfill records (for
    // example the used-hybrid-key set), and those load-time writes are not
    // part of the import transaction under test.
    std::unique_ptr<CWallet> wallet(LoadWalletOrFail());
    const WalletSnapshot before = CaptureWalletSnapshot(
        *wallet, built.scripts, built.watchScripts);
    const std::map<CDBKey, CDBValue> beforeRecords = CaptureRecords();

    if (fFailCommit)
        SetTestWalletCommitFailure();
    else
        SetTestWalletWriteFailure(failureType);

    bool fFailed = false;
    try {
        ImportHybridKeyRPC(*wallet, imported.wif, imported.derBase64,
                           "atomic import");
    } catch (const json_spirit::Object &) {
        fFailed = true;
    } catch (const std::exception &) {
        fFailed = true;
    }
    ClearTestWalletWriteFailures();

    BOOST_CHECK_MESSAGE(fFailed,
                        tag << ": injected failure did not fail the import");
    BOOST_CHECK_MESSAGE(!wallet->HaveHybridKey(imported.hybridID),
                        tag << ": failed import left the hybrid key in memory");
    BOOST_CHECK_MESSAGE(!wallet->HaveKey(imported.legacyID),
                        tag << ": failed import left the ECDSA key in memory");
    BOOST_CHECK_MESSAGE(
        wallet->mapHybridAddressBook.count(imported.hybridID) == 0,
        tag << ": failed import left the label in memory");
    BOOST_CHECK_MESSAGE(
        CaptureRecords() == beforeRecords,
        tag << ": failed import wrote records to the wallet ("
            << DescribeRecordDelta(beforeRecords, CaptureRecords()) << ")");
    wallet.reset();

    // Restart from LMDB only: the aborted transaction must have left no trace.
    RestartLMDBWallet(guard.dir);
    std::unique_ptr<CWallet> restarted(LoadWalletOrFail());
    BOOST_CHECK(!restarted->HaveHybridKey(imported.hybridID));
    BOOST_CHECK(!restarted->HaveKey(imported.legacyID));
    BOOST_CHECK(restarted->mapHybridAddressBook.count(imported.hybridID) == 0);
    CheckSnapshotsEqual(before,
                        CaptureWalletSnapshot(*restarted, built.scripts,
                                              built.watchScripts),
                        tag + " after restart");
    BOOST_CHECK_MESSAGE(CaptureRecords() == beforeRecords,
                        tag << ": restart sees records from the failed import ("
                            << DescribeRecordDelta(beforeRecords,
                                                   CaptureRecords())
                            << ")");

    // The injection is one-shot and now disarmed: the retry must persist.
    const std::string address = ImportHybridKeyRPC(
        *restarted, imported.wif, imported.derBase64, "atomic import");
    BOOST_CHECK_EQUAL(address, imported.address);
    CheckHybridKeyInvariants(*restarted, tag + " retry");
    restarted.reset();

    RestartLMDBWallet(guard.dir);
    std::unique_ptr<CWallet> finalWallet(LoadWalletOrFail());
    CheckHybridKeyInvariants(*finalWallet, tag + " retry after restart");
    BOOST_CHECK(finalWallet->HaveHybridKey(imported.hybridID));
    BOOST_CHECK(finalWallet->HaveKey(imported.legacyID));
    BOOST_CHECK(finalWallet->mapHybridAddressBook.count(imported.hybridID) == 1);
}

/**
 * importhybridkey writes the ECDSA key, the hybrid record and the label in one
 * transaction.  A failure at each individual write, and at the commit itself,
 * must leave the wallet byte-for-byte unchanged after a restart.
 */
BOOST_AUTO_TEST_CASE(wallet_atomic_hybrid_import_rollback)
{
    RunHybridImportRollback("keymeta", "keymeta", false);
    RunHybridImportRollback("key", "key", false);
    RunHybridImportRollback("hyb", "hyb", false);
    RunHybridImportRollback("hybaddr", "hybaddr", false);
    RunHybridImportRollback("commit", "", true);
}

/**
 * Exercises every wallet write boundary inside an explicit transaction:
 * a successful prefix (a key record and a label), a deliberately failed
 * write, and a successful suffix.  Aborting must roll all three back, and a
 * restart must see the wallet exactly as it was before the transaction.
 *
 * This format has no HD chain or descriptor records, so the boundaries that
 * exist here are the ones covered below.
 */
BOOST_AUTO_TEST_CASE(wallet_atomic_write_boundaries)
{
    TempDirGuard guard("wallet_write_boundaries");
    CloseLMDBWalletDB();

    BuiltWallet built;
    {
        CWallet wallet("wallet.dat");
        built = BuildRichWallet(wallet);
    }
    MigrateMockWallet(guard.dir);

    // Load once so any top-up triggered by opening the wallet is out of the way.
    {
        std::unique_ptr<CWallet> wallet(LoadWalletOrFail());
    }
    const std::map<CDBKey, CDBValue> baseline = CaptureRecords();

    uint64_t nSerial = 0;

    CHybridKey atomicHybrid;
    GenerateHybridKey(atomicHybrid);
    const CHybridKeyID atomicHybridID = atomicHybrid.GetHybridID();
    const CHybridKeyDisk atomicHybridDisk =
        CHybridKeyDisk::FromMemory(atomicHybrid);

    struct BoundaryWrite
    {
        std::string phase;
        std::string type;
        std::function<bool(CWalletDB &)> write;
    };

    std::vector<BoundaryWrite> boundaries;

    auto writeKey = [&nSerial](CWalletDB &db) {
        CKey key;
        key.MakeNewKey(true);
        return db.WriteKey(key.GetPubKey(), key.GetPrivKey(),
                           CKeyMetadata(GetTime() + (int64)nSerial++));
    };
    auto writeCryptedKey = [&nSerial](CWalletDB &db) {
        CKey key;
        key.MakeNewKey(true);
        const std::vector<unsigned char> crypted(48, 0xA5);
        return db.WriteCryptedKey(key.GetPubKey(), crypted,
                                  CKeyMetadata(GetTime() + (int64)nSerial++));
    };
    auto writeTx = [&nSerial](CWalletDB &db) {
        CWalletTx wtx;
        wtx.nTimeReceived = (unsigned int)GetTime();
        wtx.nOrderPos = (int64)nSerial;
        const uint256 hash = SerializeHash(
            std::string("atomic-write-tx-") + std::to_string(nSerial++));
        return db.WriteTx(hash, wtx);
    };
    auto writeName = [&nSerial](CWalletDB &db) {
        return db.WriteName("atomic-name-" + std::to_string(nSerial++),
                            "atomic");
    };
    auto writeBestBlock = [&nSerial](CWalletDB &db) {
        const uint256 hash = SerializeHash(
            std::string("atomic-best-block-") + std::to_string(nSerial++));
        const CBlockLocator locator(std::vector<uint256>(1, hash));
        return db.WriteBestBlock(locator);
    };
    auto writePool = [&nSerial](CWalletDB &db) {
        CKey key;
        key.MakeNewKey(true);
        return db.WritePool((int64)(1000000 + nSerial++), CKeyPool(key.GetPubKey()));
    };
    auto writeCScript = [&nSerial](CWalletDB &db) {
        CKey key;
        key.MakeNewKey(true);
        CScript script;
        script.SetDestination(key.GetPubKey().GetID());
        return db.WriteCScript(Hash160(script), script);
    };
    auto writeWatchOnly = [&nSerial](CWalletDB &db) {
        CKey key;
        key.MakeNewKey(true);
        CScript script;
        script.SetDestination(key.GetPubKey().GetID());
        return db.WriteWatchOnly(script);
    };
    auto writeDefaultKey = [&nSerial](CWalletDB &db) {
        CKey key;
        key.MakeNewKey(true);
        return db.WriteDefaultKey(key.GetPubKey());
    };
    auto writeOrderPosNext = [&nSerial](CWalletDB &db) {
        return db.WriteOrderPosNext((int64)(900000 + nSerial++));
    };
    auto writeHybridKey = [&atomicHybridID, &atomicHybridDisk](CWalletDB &db) {
        return db.WriteHybridKey(atomicHybridID, atomicHybridDisk);
    };
    auto writeHybridAddress = [&atomicHybridID](CWalletDB &db) {
        return db.WriteHybridAddressEntry(atomicHybridID,
                                          CHybridAddressEntry("atomic label"));
    };
    auto writeHybridUsed = [&atomicHybridID](CWalletDB &db) {
        std::set<CHybridKeyID> used;
        used.insert(atomicHybridID);
        return db.WriteHybridUsedKeys(used);
    };
    auto writeMasterKey = [&nSerial](CWalletDB &db) {
        CMasterKey master;
        master.vchCryptedKey.assign(32, 0x11);
        master.vchSalt.assign(8, 0x22);
        return db.WriteMasterKey((unsigned int)(1000 + nSerial++), master);
    };
    auto writeSetting = [&nSerial](CWalletDB &db) {
        const uint64_t serial = nSerial++;
        return db.WriteSetting("atomic-setting-" + std::to_string(serial),
                               (int64)serial);
    };
    auto writeAccount = [&nSerial](CWalletDB &db) {
        CKey key;
        key.MakeNewKey(true);
        CAccount account;
        account.vchPubKey = key.GetPubKey();
        return db.WriteAccount("atomic-account-" + std::to_string(nSerial++),
                               account);
    };
    auto writeAccountingEntry = [&nSerial](CWalletDB &db) {
        CAccountingEntry entry;
        entry.strAccount = "atomic-account-" + std::to_string(nSerial++);
        entry.nCreditDebit = -1;
        entry.nTime = GetTime();
        entry.nOrderPos = (int64)nSerial;
        entry.nEntryNo = 100000 + nSerial++;
        return db.WriteAccountingEntry(entry);
    };
    auto writeMinVersion = [](CWalletDB &db) {
        return db.WriteMinVersion(CLIENT_VERSION);
    };
    auto writeVersion = [](CWalletDB &db) {
        return db.WriteVersion(CLIENT_VERSION);
    };

    boundaries.push_back({"WriteKey/keymeta", "keymeta", writeKey});
    boundaries.push_back({"WriteKey/key", "key", writeKey});
    boundaries.push_back({"WriteCryptedKey/keymeta", "keymeta", writeCryptedKey});
    boundaries.push_back({"WriteCryptedKey/ckey", "ckey", writeCryptedKey});
    boundaries.push_back({"WriteTx", "tx", writeTx});
    boundaries.push_back({"WriteName", "name", writeName});
    boundaries.push_back({"WriteBestBlock", "bestblock", writeBestBlock});
    boundaries.push_back({"WritePool", "pool", writePool});
    boundaries.push_back({"WriteCScript", "cscript", writeCScript});
    boundaries.push_back({"WriteWatchOnly", "watch", writeWatchOnly});
    boundaries.push_back({"WriteDefaultKey", "defaultkey", writeDefaultKey});
    boundaries.push_back({"WriteOrderPosNext", "orderposnext", writeOrderPosNext});
    boundaries.push_back({"WriteHybridKey", "hyb", writeHybridKey});
    boundaries.push_back({"WriteHybridAddressEntry", "hybaddr", writeHybridAddress});
    boundaries.push_back({"WriteHybridUsedKeys", "hybused", writeHybridUsed});
    boundaries.push_back({"WriteMasterKey", "mkey", writeMasterKey});
    boundaries.push_back({"WriteSetting", "setting", writeSetting});
    boundaries.push_back({"WriteAccount", "acc", writeAccount});
    boundaries.push_back({"WriteAccountingEntry", "acentry", writeAccountingEntry});
    boundaries.push_back({"WriteMinVersion", "minversion", writeMinVersion});
    boundaries.push_back({"WriteVersion", "version", writeVersion});

    for (const BoundaryWrite &boundary : boundaries)
    {
        {
            CWalletDB db("wallet.dat");
            BOOST_REQUIRE_MESSAGE(db.TxnBegin(),
                                  boundary.phase << ": could not begin a "
                                                    "transaction");

            // Prefix writes that must roll back with the target.
            CKey prefixKey;
            prefixKey.MakeNewKey(true);
            BOOST_REQUIRE(db.WriteKey(prefixKey.GetPubKey(),
                                      prefixKey.GetPrivKey(),
                                      CKeyMetadata(GetTime())));
            BOOST_REQUIRE(db.WriteName("atomic-prefix-" + boundary.type,
                                       "prefix"));

            SetTestWalletWriteFailure(boundary.type);
            const bool fWritten = boundary.write(db);
            ClearTestWalletWriteFailures();

            BOOST_CHECK_MESSAGE(!fWritten,
                                boundary.phase << ": injected failure did not "
                                                  "reach the write boundary");

            // A later write in the same transaction must disappear too.
            BOOST_CHECK(db.WriteName("atomic-suffix-" + boundary.type,
                                     "suffix"));

            BOOST_REQUIRE_MESSAGE(db.TxnAbort(),
                                  boundary.phase << ": abort failed");
        }

        BOOST_CHECK_MESSAGE(CaptureRecords() == baseline,
                            boundary.phase << ": aborted transaction changed "
                                              "the live wallet ("
                                           << DescribeRecordDelta(
                                                  baseline, CaptureRecords())
                                           << ")");
        RestartLMDBWallet(guard.dir);
        BOOST_CHECK_MESSAGE(CaptureRecords() == baseline,
                            boundary.phase << ": aborted transaction survived "
                                              "a restart ("
                                           << DescribeRecordDelta(
                                                  baseline, CaptureRecords())
                                           << ")");
    }

    // A normal transaction must still commit and persist: the injection is
    // one-shot and must not leak into later transactions.
    {
        CWalletDB db("wallet.dat");
        BOOST_REQUIRE(db.TxnBegin());
        BOOST_REQUIRE(db.WriteName("atomic-committed", "committed"));
        BOOST_REQUIRE(db.TxnCommit());
    }
    RestartLMDBWallet(guard.dir);
    const std::map<CDBKey, CDBValue> afterCommit = CaptureRecords();
    BOOST_CHECK_EQUAL(CountRecordsOfType(afterCommit, "name"),
                      CountRecordsOfType(baseline, "name") + 1);
}

/**
 * A hybrid keypool top-up writes several ECDSA keys and hybrid records in one
 * transaction.  Failing the first, second or third hybrid write must leave the
 * pool and the database exactly as they were.
 */
BOOST_AUTO_TEST_CASE(wallet_atomic_hybrid_keypool_rollback)
{
    TempDirGuard guard("wallet_hybrid_pool_atomic");
    CloseLMDBWalletDB();

    BuiltWallet built;
    {
        CWallet wallet("wallet.dat");
        built = BuildRichWallet(wallet);
    }
    MigrateMockWallet(guard.dir);

    std::unique_ptr<CWallet> wallet(LoadWalletOrFail());
    const std::map<CDBKey, CDBValue> baseline = CaptureRecords();
    const size_t existing = wallet->mapHybridKeys.size();
    const size_t unusedBefore = wallet->setUnusedHybridKeys.size();
    const size_t target = existing + 3;

    for (int nSkip = 0; nSkip < 3; ++nSkip)
    {
        SetTestWalletWriteFailure("hyb", nSkip);
        BOOST_CHECK_MESSAGE(!wallet->EnsureHybridKeyPool(target),
                            "injected hybrid write " << nSkip
                                                     << " did not fail the "
                                                        "top-up");
        ClearTestWalletWriteFailures();

        BOOST_CHECK_EQUAL(wallet->mapHybridKeys.size(), existing);
        BOOST_CHECK_EQUAL(wallet->setUnusedHybridKeys.size(), unusedBefore);
        BOOST_CHECK_MESSAGE(CaptureRecords() == baseline,
                            "failed hybrid top-up " << nSkip
                                                    << " changed the live "
                                                       "wallet ("
                                                    << DescribeRecordDelta(
                                                           baseline,
                                                           CaptureRecords())
                                                    << ")");
        RestartLMDBWallet(guard.dir);
        BOOST_CHECK_MESSAGE(CaptureRecords() == baseline,
                            "failed hybrid top-up " << nSkip
                                                    << " survived a restart ("
                                                    << DescribeRecordDelta(
                                                           baseline,
                                                           CaptureRecords())
                                                    << ")");
    }

    // The next top-up is no longer injected and must persist atomically.
    BOOST_REQUIRE(wallet->EnsureHybridKeyPool(target));
    BOOST_CHECK_EQUAL(wallet->mapHybridKeys.size(), target);
    BOOST_CHECK_EQUAL(wallet->setUnusedHybridKeys.size(), unusedBefore + 3);
    CheckHybridKeyInvariants(*wallet, "hybrid keypool retry");
    wallet.reset();

    RestartLMDBWallet(guard.dir);
    std::unique_ptr<CWallet> restarted(LoadWalletOrFail());
    BOOST_CHECK_EQUAL(restarted->mapHybridKeys.size(), target);
    CheckHybridKeyInvariants(*restarted, "hybrid keypool retry after restart");
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
    BOOST_CHECK_GT(CountRecordsOfType(plaintextRecords, "hyb"), 0U);

    std::unique_ptr<CWallet> wallet(LoadWalletOrFail());
    BOOST_REQUIRE(!wallet->IsCrypted());
    BOOST_REQUIRE(!wallet->IsLocked());
    CheckHybridKeyInvariants(*wallet, "unencrypted migrated wallet");
    BOOST_REQUIRE(!wallet->mapHybridKeys.empty());
    const CHybridKeyID hybridSigningID = wallet->mapHybridKeys.begin()->first;

    // An unencrypted migrated wallet can sign straight away.
    const CKeyID signingKeyID = built.pubKeys[0].GetID();
    CheckSigningWorks(*wallet, signingKeyID, "unencrypted migrated wallet");
    CheckHybridSigningWorks(*wallet, hybridSigningID,
                            "unencrypted migrated wallet");

    // Remember the plaintext secrets so the on-disk scan below can prove they
    // are gone after encryption and compaction.  Hybrid keys contribute both
    // their legacy ECDSA secret and their ML-DSA private material.
    std::vector<std::vector<unsigned char>> plaintextSecrets;
    {
        std::set<CKeyID> keyIDs;
        wallet->GetKeys(keyIDs);
        for (const CKeyID &keyID : keyIDs) {
            CKey key;
            if (wallet->GetKey(keyID, key)) {
                const CPrivKey secret = key.GetPrivKey();
                plaintextSecrets.emplace_back(secret.begin(), secret.end());
            }
        }

        for (const auto &entry : wallet->mapHybridKeys) {
            CHybridKeyDisk disk = CHybridKeyDisk::FromMemory(entry.second);
            plaintextSecrets.emplace_back(disk.secpPriv.begin(),
                                          disk.secpPriv.end());
            plaintextSecrets.push_back(disk.mldsaPrivKey);
        }
    }
    BOOST_REQUIRE(!plaintextSecrets.empty());

    BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->IsLocked());

    // Encryption locks the wallet, so the decrypted hybrid keys are gone and
    // only encrypted-at-rest records remain.
    BOOST_CHECK(wallet->mapHybridKeys.empty());
    BOOST_REQUIRE(!wallet->mapHybridKeyDisk.empty());
    std::set<CKeyID> hybridLegacyIDs;
    for (const auto &entry : wallet->mapHybridKeyDisk) {
        const CHybridKeyDisk &disk = entry.second;
        BOOST_CHECK(disk.IsEncrypted());
        BOOST_CHECK(disk.secpPriv.empty());
        BOOST_CHECK(disk.mldsaPrivKey.empty());
        BOOST_CHECK(!disk.vchCryptedPrivate.empty());
        BOOST_CHECK(disk.CheckChecksum());
        BOOST_CHECK(disk.secpPub.IsValid());
        hybridLegacyIDs.insert(disk.secpPub.GetID());
    }

    // The encrypted wallet must not retain plaintext key records and must
    // carry encrypted key and master-key records instead.
    const std::map<CDBKey, CDBValue> encryptedRecords = CaptureRecords();
    BOOST_CHECK_EQUAL(CountRecordsOfType(encryptedRecords, "key"), 0U);
    BOOST_CHECK_EQUAL(CountRecordsOfType(encryptedRecords, "wkey"), 0U);
    BOOST_CHECK_GT(CountRecordsOfType(encryptedRecords, "ckey"), 0U);
    BOOST_CHECK_GT(CountRecordsOfType(encryptedRecords, "mkey"), 0U);

    // Every hybrid legacy key is now an encrypted "ckey" record, and every
    // at-rest "hyb" record is the encrypted layout.
    const std::set<CKeyID> ckeyIDs = KeyRecordIDs(encryptedRecords, "ckey");
    for (const CKeyID &keyID : hybridLegacyIDs) {
        BOOST_CHECK_MESSAGE(ckeyIDs.count(keyID) == 1,
                            "encrypted wallet has no legacy ECDSA record for "
                            "hybrid key "
                                << keyID.ToString());
    }

    const std::map<CHybridKeyID, CHybridKeyDisk> encryptedDisks =
        ReadHybridDiskRecords(encryptedRecords);
    BOOST_CHECK_EQUAL(encryptedDisks.size(), wallet->mapHybridKeyDisk.size());
    for (const auto &entry : encryptedDisks) {
        BOOST_CHECK(entry.second.IsEncrypted());
        BOOST_CHECK(entry.second.secpPriv.empty());
        BOOST_CHECK(entry.second.mldsaPrivKey.empty());
        BOOST_CHECK(!entry.second.vchCryptedPrivate.empty());
        BOOST_CHECK(entry.second.CheckChecksum());
    }

    // Locked means the key material is not reachable.
    CKey lockedKey;
    BOOST_CHECK(!wallet->GetKey(signingKeyID, lockedKey));
    wallet.reset();

    // Restart: the migration target must still be an encrypted wallet.
    RestartLMDBWallet(guard.dir);

    std::unique_ptr<CWallet> restarted(LoadWalletOrFail());
    BOOST_CHECK(restarted->IsCrypted());
    BOOST_CHECK(restarted->IsLocked());

    // A locked wallet can only expose hybrid keys through their encrypted
    // disk records; those records must still match the pre-restart ones.
    BOOST_CHECK(restarted->mapHybridKeys.empty());
    BOOST_CHECK_EQUAL(restarted->mapHybridKeyDisk.size(), encryptedDisks.size());
    const std::map<CDBKey, CDBValue> restartedRecords = CaptureRecords();
    const std::map<CHybridKeyID, CHybridKeyDisk> restartedDisks =
        ReadHybridDiskRecords(restartedRecords);
    BOOST_CHECK_EQUAL(restartedDisks.size(), encryptedDisks.size());
    for (const auto &entry : encryptedDisks) {
        const auto disk = restartedDisks.find(entry.first);
        BOOST_REQUIRE(disk != restartedDisks.end());
        BOOST_CHECK(disk->second.IsEncrypted());
        BOOST_CHECK(disk->second.vchCryptedPrivate ==
                    entry.second.vchCryptedPrivate);
        BOOST_CHECK(disk->second.secpPub == entry.second.secpPub);
        BOOST_CHECK(disk->second.CheckChecksum());
    }

    BOOST_CHECK(!restarted->Unlock(wrongPassphrase));
    BOOST_CHECK(restarted->IsLocked());
    BOOST_REQUIRE(restarted->Unlock(passphrase));
    BOOST_CHECK(!restarted->IsLocked());
    CheckSigningWorks(*restarted, signingKeyID, "unlocked after restart");
    CheckHybridKeyInvariants(*restarted, "unlocked after restart");
    CheckHybridSigningWorks(*restarted, hybridSigningID,
                            "unlocked after restart");

    BOOST_REQUIRE(restarted->Lock());
    BOOST_CHECK(restarted->IsLocked());
    restarted.reset();

    // A second restart still loads a locked wallet, and unlocking works again.
    RestartLMDBWallet(guard.dir);

    std::unique_ptr<CWallet> secondRestart(LoadWalletOrFail());
    BOOST_CHECK(secondRestart->IsCrypted());
    BOOST_CHECK(secondRestart->IsLocked());
    BOOST_REQUIRE(secondRestart->Unlock(passphrase));
    CheckSigningWorks(*secondRestart, signingKeyID,
                      "unlocked after second restart");
    CheckHybridKeyInvariants(*secondRestart, "unlocked after second restart");
    CheckHybridSigningWorks(*secondRestart, hybridSigningID,
                            "unlocked after second restart");
    BOOST_REQUIRE(secondRestart->Lock());

    // No plaintext private-key bytes may survive in the compacted environment.
    const std::filesystem::path dataFile = guard.dir / "wallet" / "data.mdb";
    BOOST_REQUIRE(std::filesystem::exists(dataFile));
    for (const std::vector<unsigned char> &secret : plaintextSecrets) {
        BOOST_CHECK_MESSAGE(!FileContainsBytes(dataFile, secret),
                            "plaintext private key material leaked into "
                            "the LMDB wallet");
    }
}

BOOST_AUTO_TEST_SUITE_END()
