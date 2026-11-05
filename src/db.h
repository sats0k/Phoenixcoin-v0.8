// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef DB_H
#define DB_H

#include <filesystem>

#include <db_cxx.h>

#include <cstdint>
#include <memory>
#include <utility>
#include <map>
#include <string>
#include <vector>

#include "db_kv.h"
#include "lmdbdb.h"
#include "sync.h"
#include "serialize.h"
#include "bignum.h"
#include "uint256.h"

class CAddress;
class CAddrMan;
class CBlockLocator;
class CDiskBlockIndex;
class CDiskTxPos;
class CMasterKey;
class COutPoint;
class CTransaction;
class CTxIndex;
class CWallet;

extern unsigned int nWalletDBUpdated;

void ThreadFlushWalletDB(void* parg);
bool BackupWallet(const CWallet& wallet, const std::string& strDest);

/**
 * Flushes the active wallet database to disk.  Returns false when the LMDB
 * sync fails, or when a Berkeley DB flush was skipped because the environment
 * was busy; callers should retry on the next flush interval.  Hides the
 * backend from the wallet loop.
 */
bool FlushWalletDB(const std::string& strFile);

/** Copies the active wallet database to strDest. */
bool BackupWalletDB(const std::string& strFile, const std::string& strDest);

/** Copies the active LMDB wallet to strDest with mdb_env_copy2(). */
bool BackupLMDBWallet(const std::string& strDest);

bool ExportWallet(CWallet *pwallet, const std::string &strDst);
bool ImportWallet(CWallet *pwallet, const std::string &strSrc);

class CDBEnv
{
private:
    bool fDetachDB;
    bool fDbEnvInit;
    bool fMockDb;
    std::filesystem::path pathEnv;
    std::string strPath;

    void EnvShutdown();

public:
    mutable CCriticalSection cs_db;
    DbEnv dbenv;
    std::map<std::string, int> mapFileUseCount;
    std::map<std::string, Db*> mapDb;

    CDBEnv();
    ~CDBEnv();
    void MakeMock();
    bool IsMock() { return fMockDb; };

    /*
     * Verify that database file strFile is OK. If it is not,
     * call the callback to try to recover.
     * This must be called BEFORE strFile is opened.
     * Returns true if strFile is OK.
     */
    enum VerifyResult { VERIFY_OK, RECOVER_OK, RECOVER_FAIL };
    VerifyResult Verify(std::string strFile, bool (*recoverFunc)(CDBEnv& dbenv, std::string strFile));
    /*
     * Salvage data from a file that Verify says is bad.
     * fAggressive sets the DB_AGGRESSIVE flag (see berkeley DB->verify() method documentation).
     * Appends binary key/value pairs to vResult, returns true if successful.
     * NOTE: reads the entire database into memory, so cannot be used
     * for huge databases.
     */
    typedef std::pair<std::vector<unsigned char>, std::vector<unsigned char> > KeyValPair;
    bool Salvage(std::string strFile, bool fAggressive, std::vector<KeyValPair>& vResult);

    bool Open(std::filesystem::path pathEnv_);
    void Close();
    void Flush(bool fShutdown);
    void CheckpointLSN(std::string strFile);
    void SetDetach(bool fDetachDB_) { fDetachDB = fDetachDB_; }
    bool GetDetach() { return fDetachDB; }

    void CloseDb(const std::string& strFile);
    bool RemoveDb(const std::string& strFile);

    DbTxn *TxnBegin(int flags=DB_TXN_WRITE_NOSYNC)
    {
        DbTxn* ptxn = nullptr;
        int ret = dbenv.txn_begin(nullptr, &ptxn, flags);
        if (!ptxn || ret != 0)
            return nullptr;
        return ptxn;
    }
};

extern CDBEnv bitdb;

enum DBBackend
{
    DB_BACKEND_BDB = 0,
    DB_BACKEND_LMDB = 1,
};

/**
 * On-disk state of one LMDB environment directory, inspected without opening
 * it.  fComplete only proves that data.mdb is large enough to hold the two
 * LMDB meta pages; it does not prove the B-tree is readable.  Use
 * VerifyLMDBEnvironment() (the -checklmdb command) for a full check.
 */
struct LMDBOnDiskState
{
    bool fDirectoryExists = false;
    bool fDataFileExists = false;
    bool fLockFileExists = false;
    bool fComplete = false;
    uintmax_t nDataFileBytes = 0;
    std::string strReason;
};

/**
 * Inspects dir as an LMDB environment directory.  A missing, empty or
 * truncated data.mdb is reported as incomplete, which startup treats as a
 * failure rather than as an invitation to create a fresh environment.
 */
LMDBOnDiskState InspectLMDBEnvironmentOnDisk(const std::filesystem::path& dir);

/**
 * Returns true when path is the environment directory currently opened for the
 * chain index or wallet.  Offline verification must not be used on a live
 * environment, and this lets the command refuse that case.
 */
bool IsActiveLMDBEnvironmentPath(const std::filesystem::path& path);

/**
 * Health of one database backend (chain index or wallet) for getdbinfo.
 *
 * The configured value comes from the command line, the active value from the
 * environment that startup actually opened, and the marker values from the
 * on-disk authority markers.  LMDB fields are only meaningful when
 * fLMDBEnabled is true; a BDB backend reports no environment or database
 * statistics.
 */
struct DBBackendDiagnostics
{
    std::string strRole;              // "chain" or "wallet"
    std::string strConfiguredBackend; // "bdb" or "lmdb"
    std::string strActiveBackend;     // "bdb" or "lmdb"
    bool fLMDBEnabled = false;
    bool fOpenedCleanly = false;
    bool fEnvironmentOpen = false;
    bool fDatabaseOpen = false;
    bool fMarkerPresent = false;
    std::string strMarker;
    bool fMarkerMatchesBackend = false;
    std::string strPath;
    std::string strError;
    LMDBOnDiskState disk;
    CLMDBStats env;
    CLMDBDBStats db;
};

/** Snapshot of both database backends for getdbinfo. */
struct DBDiagnostics
{
    DBBackendDiagnostics chain;
    DBBackendDiagnostics wallet;
};

/** Returns true when the LMDB chain index is the active backend. */
bool IsLMDBChainEnabled();

/** Startup action for the LMDB chain index once the environment is open. */
enum ChainIndexStartupAction
{
    CHAIN_INDEX_USE_EXISTING,
    CHAIN_INDEX_MIGRATE_BDB,
    CHAIN_INDEX_FAIL_MISSING,
};

/**
 * Decides what startup should do with the LMDB chain index.  A marker saying
 * LMDB is authoritative forbids migration: an empty index means data loss, not
 * an invitation to resurrect the old blkindex.dat snapshot.
 */
ChainIndexStartupAction GetChainIndexStartupAction(bool fMarkerLMDB, bool fLMDBEmpty);

/** Returns the chain index backend selected by -dbbackend (default: LMDB). */
DBBackend GetConfiguredDBBackend();

/** Maximum supported -lmdbmapsize value in MiB for this build. */
int64 GetLMDBMaxMapSizeMiB();

/** Default -lmdbmapsize / -lmdbwalletsize value in MiB for this build. */
int64 GetLMDBDefaultMapSizeMiB();
int64 GetLMDBDefaultWalletMapSizeMiB();

/**
 * Default automatic growth ceiling in MiB for this build: 1 TiB on 64-bit
 * platforms and 2048 MiB on 32-bit platforms.
 */
int64 GetLMDBDefaultMaxMapSizeMiB();

/**
 * Parses a -lmdbmapsize value in MiB and converts it to a page-aligned byte
 * count.  Fails for non-numeric, non-positive, unrepresentable, unsupported and
 * unaligned values, filling strError with a user-facing reason.
 */
bool ParseLMDBMapSize(const std::string& strValue, size_t& nBytes, std::string& strError);

/**
 * Resolves the initial map size and automatic growth ceiling for one LMDB
 * environment.  Empty option strings select nDefaultInitialMiB and the build's
 * default ceiling.  When fAutoGrow is false the map is fixed at the initial
 * size.  The maximum must be at least as large as the initial size.
 */
bool ResolveLMDBMapSizes(const std::string& strMapSize,
                         const std::string& strMaxMapSize,
                         int64 nDefaultInitialMiB,
                         bool fAutoGrow,
                         size_t& nMapSize,
                         size_t& nMaxMapSize,
                         std::string& strError);

/**
 * Returns the map size to use for a migration from a wallet.dat of
 * nSourceBytes.  The configured value is kept unless the source file needs
 * more room, so an explicit small -lmdbwalletsize cannot make the one-shot
 * copy fail with MDB_MAP_FULL.
 */
size_t GetLMDBWalletMapSizeForMigration(size_t nConfigured, uintmax_t nSourceBytes);

/** Reads the blkindex.backend marker from dir.  Returns false when it is absent. */
bool ReadChainBackendMarker(const std::filesystem::path& dir, std::string& strBackend);

/** Atomically writes the blkindex.backend marker in dir. */
bool WriteChainBackendMarker(const std::filesystem::path& dir, const std::string& strBackend);

/** Returns true when dir contains a non-empty LMDB chain index. */
bool HasLMDBChainIndex(const std::filesystem::path& dir);

/**
 * Checks that the configured backend can use the chain index in dir.  A marker
 * records which backend owns the index, and a legacy LMDB index without a
 * marker is still treated as authoritative.  This prevents a BDB start from
 * silently loading a stale blkindex.dat after an LMDB migration.
 */
bool CheckChainBackendCompatibility(const std::filesystem::path& dir, DBBackend configured);

/**
 * Validates the configured chain index backend against the data directory and,
 * when LMDB is selected, opens it and copies the raw records from an existing
 * blkindex.dat on first use.  The Berkeley DB file is left untouched.
 *
 * A blkindex.backend marker records that the data directory has moved to LMDB
 * so that a later BDB start cannot silently load the stale index.
 */
bool InitLMDBChainDB();
void CloseLMDBChainDB();

/** Begins a transaction on the active chain index backend (LMDB). */
std::unique_ptr<CDBTransaction> BeginChainTransaction(bool fReadOnly);


/** Startup action for the LMDB wallet once its environment is open. */
enum WalletStartupAction
{
    WALLET_USE_EXISTING,
    WALLET_INIT_NEW,
    WALLET_MIGRATE_BDB,
    WALLET_FAIL_MISSING,
};

/** Returns the wallet backend selected by -walletbackend (default: LMDB). */
DBBackend GetConfiguredWalletBackend();

/**
 * Decides what startup should do with the LMDB wallet.  A marker saying LMDB
 * is authoritative forbids silently starting from an empty wallet; that is
 * data loss, not an invitation to create a fresh wallet.  When no marker is
 * present and wallet.dat exists, the wallet is copied into the empty LMDB
 * environment before the marker is written.
 */
WalletStartupAction GetWalletStartupAction(bool fMarkerLMDB, bool fLMDBEmpty,
                                           bool fBDBWalletExists);

/** Reads the wallet.backend marker from dir.  Returns false when it is absent. */
bool ReadWalletBackendMarker(const std::filesystem::path& dir, std::string& strBackend);

/** Atomically writes the wallet.backend marker in dir. */
bool WriteWalletBackendMarker(const std::filesystem::path& dir, const std::string& strBackend);

/** Returns true when dir contains a non-empty LMDB wallet. */
bool HasLMDBWallet(const std::filesystem::path& dir);

/**
 * Checks that the configured wallet backend can use the wallet in dir.  A
 * marker records which backend owns the wallet, and a legacy LMDB wallet
 * without a marker is still treated as authoritative.  This prevents a BDB
 * start from silently creating or loading a stale wallet.dat after an LMDB
 * migration.
 */
bool CheckWalletBackendCompatibility(const std::filesystem::path& dir, DBBackend configured);

/**
 * Validates the configured wallet backend and opens the LMDB wallet when it is
 * selected.  On first use, an existing wallet.dat is copied into the empty
 * LMDB wallet in a single transaction.  The Berkeley DB file is left untouched
 * so a failed or unwanted migration does not destroy the original wallet.
 *
 * A wallet.backend marker records that the data directory has moved to LMDB so
 * that a later BDB start cannot silently open a stale wallet.dat.
 */
bool InitLMDBWalletDB();
void CloseLMDBWalletDB();
bool IsLMDBWalletEnabled();

/** Flushes pending LMDB wallet commits to disk.  No-op for a BDB wallet. */
bool FlushLMDBWallet(bool fForce = true);

/** Begins a transaction on the active wallet backend (LMDB). */
std::unique_ptr<CDBTransaction> BeginWalletTransaction(bool fReadOnly);

/**
 * Collects backend, marker, environment and database statistics for the
 * configured data directory.  The wallet directory follows the open LMDB
 * wallet when there is one, so tests and migration tooling can inspect a
 * temporary environment.
 */
DBDiagnostics GetDBDiagnostics();

/**
 * Collects diagnostics for explicit chain and wallet directories.  Used by
 * tests to inspect temporary environments without touching the configured
 * data directory.
 */
DBDiagnostics GetDBDiagnostics(const std::filesystem::path& chainDir,
                               const std::filesystem::path& walletDir);

/**
 * Test hook: initializes the LMDB wallet rooted at dir, bypassing the mock
 * guard so tests can use a temporary directory instead of the real datadir.
 */
bool InitLMDBWalletDBForTest(const std::filesystem::path& dir);

/**
 * Test-only failure injection for wallet write transactions.
 *
 * SetTestWalletWriteFailure arms the next wallet write whose serialized record
 * type matches strType (for example "key", "tx" or "hyb"); after nSkip matches
 * have succeeded the matching write returns false.  The caller must then abort
 * the surrounding transaction, which is what the atomicity tests exercise.
 *
 * SetTestWalletCommitFailure makes the next wallet transaction commit fail and
 * abort instead; nSkip lets earlier commits succeed when one logical
 * operation uses more than one transaction.  Both hooks are one-shot, apply
 * only to wallet databases and are inert until armed.  They are used by the
 * failure-injection tests only.
 */
void SetTestWalletWriteFailure(const std::string& strType, int nSkip = 0);
void SetTestWalletCommitFailure(int nSkip = 0);
void ClearTestWalletWriteFailures();
bool TestWalletWriteFailureArmed();
bool TestWalletWriteFailureMatches(const std::string& strType);
bool ConsumeTestWalletCommitFailure();

/**
 * Test-only failure injection for chain-index transaction commits.  Arms the
 * next non-wallet LMDB transaction commit to fail and abort, so the import
 * batch can exercise its rollback path.  The hook is one-shot and inert until
 * armed.
 */
void SetTestChainCommitFailure();
void ClearTestChainCommitFailure();
bool ConsumeTestChainCommitFailure();

/**
 * Test-only failure injection for RewriteWalletLMDB().  The named point fails
 * once (after nSkip successful hits), and no other rewrite is affected.  The
 * points are "wallet-rewrite-rename-old", "wallet-rewrite-install",
 * "wallet-rewrite-restore", "wallet-rewrite-reopen-old",
 * "wallet-rewrite-reopen-installed", "wallet-rewrite-reopen-restored" and
 * "wallet-rewrite-remove-old".
 *
 * Fatal rewrite errors normally terminate the process because no safe wallet
 * backend remains.  SetTestWalletRewriteAbort(true) makes them return false
 * instead and records the decision in TestWalletRewriteAborted(), so a unit
 * test can inspect the on-disk state without exiting.  All hooks are inert
 * until armed and apply only to the LMDB wallet.
 */
void SetTestWalletRewriteFailure(const std::string& strPoint, int nSkip = 0);
void ClearTestWalletRewriteFailures();
void SetTestWalletRewriteAbort(bool fAbort);
bool TestWalletRewriteAbortArmed();
bool TestWalletRewriteAborted();

/**
 * Test-only crash injection.  PHOENIX_TEST_CRASH_FILE names a small control
 * file containing "<point> <skip>".  When the named point is reached, skip
 * matching calls are released and the next one kills the process with
 * SIGKILL, leaving the same on-disk state a power loss would.  The file is
 * rewritten after each skip so a test can arm an exact write.  The hook is
 * inert when the variable or file is absent and is never armed by a normal
 * startup path.
 */
void TestWalletCrashPoint(const char* pszPoint);


/** RAII class that provides access to a Berkeley database */
class CDB
{
protected:
    Db* pdb;
    std::string strFile;
    DbTxn *activeTxn;
    bool fReadOnly;

    // When an LMDB backend is active this database delegates to it and pdb
    // stays null.  The chain index and the wallet each have their own LMDB
    // environment, so remember which one this handle belongs to.
    std::unique_ptr<CDBTransaction> kvTxn;
    bool fUseKV;
    bool fUseKVWallet;

    // Record types written through an explicit wallet transaction.  The
    // test-only crash hook emits its per-record "after commit" point only
    // once the whole transaction is durable, but still once per record type
    // so the crash regression can select a record class.
    std::vector<std::string> kvTxnRecordTypes;

    std::unique_ptr<CDBTransaction> BeginKVTransaction(bool fReadOnly)
    {
        return fUseKVWallet ? BeginWalletTransaction(fReadOnly)
                            : BeginChainTransaction(fReadOnly);
    }

    bool ReadKV(const CDBKey& key, CDBValue& value);
    bool WriteKV(const CDBKey& key, const CDBValue& value, bool fOverwrite);
    bool EraseKV(const CDBKey& key);
    bool ExistsKV(const CDBKey& key);

    explicit CDB(const char* pszFile, const char* pszMode="r+");
    ~CDB() { Close(); }
public:
    void Close();
private:
    CDB(const CDB&);
    void operator=(const CDB&);

protected:
    template<typename K, typename T>
    bool Read(const K& key, T& value)
    {
        if (fUseKV)
        {
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            ssKey << key;
            CDBKey kvKey(ssKey.begin(), ssKey.end());
            CDBValue kvValue;
            if (!ReadKV(kvKey, kvValue))
                return false;
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            try {
                if (!kvValue.empty())
                    ssValue.write((const char*)kvValue.data(), kvValue.size());
                ssValue >> value;
                if (!kvValue.empty())
                    OPENSSL_cleanse(kvValue.data(), kvValue.size());
                if (ssValue.size() > 0)
                    OPENSSL_cleanse(&ssValue[0], ssValue.size());
                return true;
            } catch (const std::exception&) {
                if (!kvValue.empty())
                    OPENSSL_cleanse(kvValue.data(), kvValue.size());
                if (ssValue.size() > 0)
                    OPENSSL_cleanse(&ssValue[0], ssValue.size());
                return false;
            }
        }

        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Read
        Dbt datValue;
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pdb->get(activeTxn, &datKey, &datValue, 0);
        OPENSSL_cleanse(datKey.get_data(), datKey.get_size());
        bool success = false;
        if (datValue.get_data() != nullptr) {
            // Unserialize value
            try {
                CDataStream ssValue((char*)datValue.get_data(), (char*)datValue.get_data() + datValue.get_size(), SER_DISK, CLIENT_VERSION);
                ssValue >> value;
                success = true;
            } catch (const std::exception&) {
                // In this case success remains 'false'
            }

            // Clear and free memory
            OPENSSL_cleanse(datValue.get_data(), datValue.get_size());
            free(datValue.get_data());
        }
        return(ret == 0 && success);
    }

    template<typename K, typename T>
    bool Write(const K& key, const T& value, bool fOverwrite=true)
    {
        if (!fUseKV && !pdb)
            return false;
        if (fReadOnly)
            assert(!"Write called on database in read-only mode");

        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;

        // Test-only failure injection: see SetTestWalletWriteFailure.
        if (fUseKV && fUseKVWallet && TestWalletWriteFailureArmed())
        {
            std::string strTestType;
            try {
                CDataStream ssType(ssKey.begin(), ssKey.end(),
                                   SER_DISK, CLIENT_VERSION);
                ssType >> strTestType;
            } catch (...) {
            }
            if (TestWalletWriteFailureMatches(strTestType))
                return false;
        }

        // Value
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.reserve(10000);
        ssValue << value;

        if (fUseKV)
        {
            CDBKey kvKey(ssKey.begin(), ssKey.end());
            CDBValue kvValue(ssValue.begin(), ssValue.end());
            bool fResult = WriteKV(kvKey, kvValue, fOverwrite);
            if (!kvValue.empty())
                OPENSSL_cleanse(kvValue.data(), kvValue.size());
            if (ssValue.size() > 0)
                OPENSSL_cleanse(&ssValue[0], ssValue.size());
            return fResult;
        }

        Dbt datKey(&ssKey[0], ssKey.size());
        Dbt datValue(&ssValue[0], ssValue.size());

        // Write
        int ret = pdb->put(activeTxn, &datKey, &datValue, (fOverwrite ? 0 : DB_NOOVERWRITE));

        // Clear memory in case it was a private key
        OPENSSL_cleanse(datKey.get_data(), datKey.get_size());
        OPENSSL_cleanse(datValue.get_data(), datValue.get_size());
        return (ret == 0);
    }

    template<typename K>
    bool Erase(const K& key)
    {
        if (!fUseKV && !pdb)
            return false;
        if (fReadOnly)
            assert(!"Erase called on database in read-only mode");

        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;

        if (fUseKV)
        {
            const CDBKey kvKey(ssKey.begin(), ssKey.end());
            return EraseKV(kvKey);
        }

        Dbt datKey(&ssKey[0], ssKey.size());

        // Erase
        int ret = pdb->del(activeTxn, &datKey, 0);

        // Clear memory
        OPENSSL_cleanse(datKey.get_data(), datKey.get_size());
        return (ret == 0 || ret == DB_NOTFOUND);
    }

    template<typename K>
    bool Exists(const K& key)
    {
        if (fUseKV)
        {
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            ssKey << key;
            const CDBKey kvKey(ssKey.begin(), ssKey.end());
            return ExistsKV(kvKey);
        }

        if (!pdb)
            return false;

        // Key
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        Dbt datKey(&ssKey[0], ssKey.size());

        // Exists
        int ret = pdb->exists(activeTxn, &datKey, 0);

        // Clear memory
        OPENSSL_cleanse(datKey.get_data(), datKey.get_size());
        return (ret == 0);
    }

    /** Opens a forward/backward scan on either backend. */
    std::unique_ptr<CDBScan> GetScan(const CDBKey& prefix = CDBKey());

    Dbc* GetCursor()
    {
        if (!pdb)
            return nullptr;
        Dbc* pcursor = nullptr;
        int ret = pdb->cursor(nullptr, &pcursor, 0);
        if (ret != 0)
            return nullptr;
        return pcursor;
    }

    int ReadAtCursor(Dbc* pcursor, CDataStream& ssKey, CDataStream& ssValue, unsigned int fFlags=DB_NEXT)
    {
        // Read at cursor
        Dbt datKey;
        if (fFlags == DB_SET || fFlags == DB_SET_RANGE || fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
        {
            datKey.set_data(&ssKey[0]);
            datKey.set_size(ssKey.size());
        }
        Dbt datValue;
        if (fFlags == DB_GET_BOTH || fFlags == DB_GET_BOTH_RANGE)
        {
            datValue.set_data(&ssValue[0]);
            datValue.set_size(ssValue.size());
        }
        datKey.set_flags(DB_DBT_MALLOC);
        datValue.set_flags(DB_DBT_MALLOC);
        int ret = pcursor->get(&datKey, &datValue, fFlags);
        if (ret != 0)
            return ret;
        else if (datKey.get_data() == nullptr || datValue.get_data() == nullptr)
            return 99999;

        // Convert to streams
        ssKey.SetType(SER_DISK);
        ssKey.clear();
        ssKey.write((char*)datKey.get_data(), datKey.get_size());
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char*)datValue.get_data(), datValue.get_size());

        // Clear and free memory
        OPENSSL_cleanse(datKey.get_data(), datKey.get_size());
        OPENSSL_cleanse(datValue.get_data(), datValue.get_size());
        free(datKey.get_data());
        free(datValue.get_data());
        return 0;
    }

public:
    /** True while this handle has an explicit transaction open. */
    bool IsTransactionActive() const
    {
        return fUseKV ? kvTxn.get() != nullptr : activeTxn != nullptr;
    }

    bool TxnBegin()
    {
        if (fUseKV)
        {
            if (kvTxn)
                return false;
            kvTxnRecordTypes.clear();
            kvTxn = BeginKVTransaction(false);
            return kvTxn.get() != nullptr;
        }

        if (!pdb || activeTxn)
            return false;
        DbTxn* ptxn = bitdb.TxnBegin();
        if (!ptxn)
            return false;
        activeTxn = ptxn;
        return true;
    }

    bool TxnCommit()
    {
        if (fUseKV)
        {
            if (!kvTxn)
                return false;
            if (fUseKVWallet)
                TestWalletCrashPoint("wallet-txn-before-commit");
            if (fUseKVWallet && ConsumeTestWalletCommitFailure())
            {
                kvTxn->Abort();
                kvTxn.reset();
                kvTxnRecordTypes.clear();
                return false;
            }
            if (!fUseKVWallet && ConsumeTestChainCommitFailure())
            {
                kvTxn->Abort();
                kvTxn.reset();
                kvTxnRecordTypes.clear();
                return false;
            }
            bool fSuccess = kvTxn->Commit();
            kvTxn.reset();
            if (fUseKVWallet && fSuccess)
            {
                TestWalletCrashPoint("wallet-txn-after-commit");
                // Emit the per-record points after the transaction is
                // durable, so a kill leaves every record applied rather than
                // only the record whose point matched.
                for (const std::string& strType : kvTxnRecordTypes)
                    TestWalletCrashPoint(("wallet-write-after-commit:" +
                                          strType).c_str());
            }
            kvTxnRecordTypes.clear();
            return fSuccess;
        }

        if (!pdb || !activeTxn)
            return false;
        int ret = activeTxn->commit(0);
        activeTxn = nullptr;
        return (ret == 0);
    }

    bool TxnAbort()
    {
        if (fUseKV)
        {
            if (!kvTxn)
                return false;
            kvTxn->Abort();
            kvTxn.reset();
            kvTxnRecordTypes.clear();
            return true;
        }

        if (!pdb || !activeTxn)
            return false;
        int ret = activeTxn->abort();
        activeTxn = nullptr;
        return (ret == 0);
    }

    bool ReadVersion(int& nVersion)
    {
        nVersion = 0;
        return Read(std::string("version"), nVersion);
    }

    bool WriteVersion(int nVersion)
    {
        return Write(std::string("version"), nVersion);
    }

    bool static Rewrite(const std::string& strFile, const char* pszSkip = nullptr);
};







/** Access to the block and transaction index (blkindex.dat or the LMDB chain index) */
class CTxDB : public CDB
{
public:
    CTxDB(const char* pszMode="r+") : CDB("blkindex.dat", pszMode) { }
private:
    CTxDB(const CTxDB&);
    void operator=(const CTxDB&);
public:
    bool ReadTxIndex(uint256 hash, CTxIndex& txindex);
    bool UpdateTxIndex(uint256 hash, const CTxIndex& txindex);
    bool AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight);
    bool EraseTxIndex(const CTransaction& tx);
    bool ContainsTx(uint256 hash);
    bool ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(uint256 hash, CTransaction& tx);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex);
    bool ReadDiskTx(COutPoint outpoint, CTransaction& tx);
    bool WriteBlockIndex(const CDiskBlockIndex& blockindex);
    bool ReadHashBestChain(uint256& hashBestChain);
    bool WriteHashBestChain(uint256 hashBestChain);
    bool ReadBestInvalidWork(CBigNum& bnBestInvalidWork);
    bool WriteBestInvalidWork(CBigNum bnBestInvalidWork);
    bool LoadBlockIndex();

    /** Copies raw blkindex.dat records into an empty LMDB chain index. */
    static bool MigrateToLMDB();

    /* Calls related to sync checkpoints */
    bool ReadSyncCheckpoint(uint256 &hashCheckpoint);
    bool WriteSyncCheckpoint(uint256 hashCheckpoint);
    bool ReadCheckpointPubKey(std::string &strPubKey);
    bool WriteCheckpointPubKey(const std::string &strPubKey);
private:
    bool LoadBlockIndexGuts();
    bool LoadBlockIndexGutsKV();
};




/** Access to the (IP) address database (peers.dat) */
class CAddrDB
{
private:
    std::filesystem::path pathAddr;
public:
    CAddrDB();
    bool Write(const CAddrMan& addr);
    bool Read(CAddrMan& addr);
};

#endif /* DB_H */
