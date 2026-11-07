// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <mutex>

#ifndef WINDOWS
#include "sys/stat.h"
#endif

#include <boost/version.hpp>
#include <filesystem>
#include <fstream>
#include <stdint.h>
#include <openssl/crypto.h>

#include "allocators.h" /* for GetSystemPageSize */
#include "util.h"
#include "main.h"
#include "checkpoints.h" /* for hashSyncCheckpoint */
#include "db.h"
#include "lmdb_kv.h"

#include <cctype>
#include <csignal>

using namespace std;
using namespace boost;


unsigned int nWalletDBUpdated;

// Test-only crash injection (see TestWalletCrashPoint in db.h).  A test arms
// one named point in a control file; skip counts let it pick an exact record
// or transaction boundary.  Nothing here runs unless the environment variable
// is set and the control file names the point being reached.
void TestWalletCrashPoint(const char* pszPoint)
{
    const char* pszFile = std::getenv("PHOENIX_TEST_CRASH_FILE");
    if (pszFile == nullptr || *pszFile == '\0')
        return;

    std::ifstream in(pszFile);
    std::string strPoint;
    int nSkip = 0;
    if (!(in >> strPoint >> nSkip) || strPoint != pszPoint)
        return;

    if (nSkip > 0)
    {
        std::ofstream out(pszFile, std::ios::trunc);
        if (out)
            out << strPoint << " " << (nSkip - 1) << "\n";
        return;
    }

    fflush(nullptr);
#ifndef WIN32
    raise(SIGKILL);
#endif
    // SIGKILL cannot be caught, so this is only reached on platforms without
    // it (or if raise() fails); keep the same observable exit status.
    std::_Exit(137);
}

namespace {

// The first serialized field of every wallet record is its record type
// ("tx", "name", "key", "pool", "hyb", ...).  Crash points include it so a
// test can arm an exact record class instead of counting unrelated writes.
std::string TestWalletRecordType(const CDBKey& key)
{
    try {
        CDataStream ssKey(key, SER_DISK, CLIENT_VERSION);
        std::string strType;
        ssKey >> strType;
        return strType;
    } catch (...) {
        return std::string();
    }
}

// Test-only fault injection for RewriteWalletLMDB().  Nothing is armed by a
// normal startup or by any production code path.
struct TestWalletRewriteState
{
    std::mutex mutex;
    // Armed points, each with the number of matching calls to let pass first.
    std::map<std::string, int> mapSkip;
};

TestWalletRewriteState g_testWalletRewrite;
std::atomic<bool> g_fTestWalletRewriteAbort(false);
std::atomic<bool> g_fTestWalletRewriteAborted(false);

// Returns true when the named rewrite step is armed and its skip count has
// been exhausted.  Different points can be armed at once, so a test can force
// both the first install and the subsequent restore to fail.
bool TestWalletRewriteFailureMatches(const char* pszPoint)
{
    std::lock_guard<std::mutex> lock(g_testWalletRewrite.mutex);
    std::map<std::string, int>::iterator it =
        g_testWalletRewrite.mapSkip.find(pszPoint);
    if (it == g_testWalletRewrite.mapSkip.end())
        return false;
    if (it->second > 0)
    {
        --it->second;
        return false;
    }
    g_testWalletRewrite.mapSkip.erase(it);
    return true;
}

} // namespace



//
// CDB
//

namespace {

CLMDBEnv g_lmdbChainEnv;
CLMDBDatabase g_lmdbChainDb;
bool g_fLMDBChainEnabled = false;

CLMDBEnv g_lmdbWalletEnv;
CLMDBDatabase g_lmdbWalletDb;
bool g_fLMDBWalletEnabled = false;

// Serializes wallet environment lifecycle operations (init, rewrite, backup,
// flush) against each other.  Short-lived CWalletDB handles increment
// g_nWalletKVHandles so a rewrite can wait for them to drain.
std::mutex g_mutexWalletKV;
std::atomic<int> g_nWalletKVHandles(0);
size_t g_nWalletMapSize = 0;
size_t g_nWalletMaxMapSize = 0;
bool g_fWalletAutoGrow = true;
bool g_fWalletNoSync = false;
// Directory that owns the open LMDB wallet.  The production startup path uses
// GetDataDir(), but tests open the wallet in a temporary directory; rewrite
// must follow the environment it is compacting, not the configured datadir.
std::filesystem::path g_pathLMDBWalletDir;

#if defined(__LP64__) || defined(_WIN64)
constexpr int64 LMDB_DEFAULT_MAPSIZE_MIB = 4096;
// A 64-bit map is bounded by the representable size_t range, not by a small
// platform constant.  Keep the MiB limit inside that range.
constexpr int64 LMDB_MAX_MAPSIZE_MIB =
    static_cast<int64>((std::numeric_limits<size_t>::max)() / (1024ULL * 1024ULL));
#else
constexpr int64 LMDB_DEFAULT_MAPSIZE_MIB = 1024;
// 32-bit processes cannot map the full 4 GiB address space.  LMDB documents a
// practical limit in the ~1.1-2 GiB range, so reject larger requests instead
// of letting the size_t conversion wrap.
constexpr int64 LMDB_MAX_MAPSIZE_MIB = 2048;
#endif

constexpr const char* CHAIN_BACKEND_MARKER = "blkindex.backend";
constexpr const char* WALLET_BACKEND_MARKER = "wallet.backend";

#if defined(__LP64__) || defined(_WIN64)
// A wallet map is virtual address space, not a preallocation.  Match the chain
// index default so a large wallet does not need a flag just to start.
constexpr int64 LMDB_DEFAULT_WALLET_MAPSIZE_MIB = 4096;
#else
constexpr int64 LMDB_DEFAULT_WALLET_MAPSIZE_MIB = 256;
#endif

bool ParseInt64Strict(const std::string& strValue, int64& nValue)
{
    if (strValue.empty())
        return false;

    errno = 0;
    char* pszEnd = nullptr;
    const long long nParsed = strtoll(strValue.c_str(), &pszEnd, 10);
    if (errno == ERANGE || pszEnd == strValue.c_str() || *pszEnd != '\0')
        return false;

    nValue = nParsed;
    return true;
}

std::filesystem::path GetChainBackendMarkerPath(const std::filesystem::path& dir)
{
    return dir / CHAIN_BACKEND_MARKER;
}

void LogLMDBMapUsage()
{
    MDB_env* env = g_lmdbChainEnv.GetEnv();
    if (!env)
        return;

    MDB_envinfo info;
    MDB_stat stat;
    if (mdb_env_info(env, &info) != 0 || mdb_env_stat(env, &stat) != 0)
        return;

    const double nUsedMiB =
        static_cast<double>((info.me_last_pgno + 1) * stat.ms_psize) / (1024.0 * 1024.0);
    const double nMapMiB = static_cast<double>(info.me_mapsize) / (1024.0 * 1024.0);
    printf("LMDB chain index: %.1f of %.1f MiB used\n", nUsedMiB, nMapMiB);

    if (info.me_mapsize > 0 && info.me_last_pgno + 1 > 0) {
        const double nRatio = nUsedMiB / nMapMiB;
        if (nRatio >= 0.85)
            printf("Warning: LMDB chain index is %.0f%% full; increase "
                   "-lmdbmapsize before it runs out of space\n", nRatio * 100.0);
    }
}

} // namespace

CDBScan::CDBScan(std::unique_ptr<CDBTransaction> txnIn, std::unique_ptr<CDBIterator> itIn)
    : txn(std::move(txnIn)), it(std::move(itIn))
{
}

CDBScan::~CDBScan()
{
    // Close the cursor before releasing the backend read transaction.  The
    // destructor body runs before members are destroyed, so an explicit reset
    // is required here: a cursor must not outlive its transaction.
    it.reset();
    if (txn)
        txn->Commit();
}

bool ReadChainBackendMarker(const std::filesystem::path& dir, std::string& strBackend)
{
    std::ifstream file(GetChainBackendMarkerPath(dir));
    if (!file)
        return false;

    std::getline(file, strBackend);
    while (!strBackend.empty() &&
           (strBackend.back() == '\r' || strBackend.back() == '\n' ||
            strBackend.back() == ' ' || strBackend.back() == '\t'))
        strBackend.pop_back();
    while (!strBackend.empty() &&
           (strBackend.front() == ' ' || strBackend.front() == '\t'))
        strBackend.erase(strBackend.begin());
    return true;
}

LMDBOnDiskState InspectLMDBEnvironmentOnDisk(const std::filesystem::path& dir)
{
    LMDBOnDiskState state;

    std::error_code ec;
    state.fDirectoryExists = std::filesystem::is_directory(dir, ec) && !ec;
    if (!state.fDirectoryExists) {
        state.strReason = (std::filesystem::exists(dir, ec) && !ec)
            ? "path exists but is not a directory"
            : "directory is missing";
        return state;
    }

    const std::filesystem::path pathData = dir / "data.mdb";
    const std::filesystem::path pathLock = dir / "lock.mdb";
    state.fDataFileExists =
        std::filesystem::is_regular_file(pathData, ec) && !ec;
    if (!state.fDataFileExists) {
        state.strReason = "data.mdb is missing";
        return state;
    }
    state.fLockFileExists =
        std::filesystem::is_regular_file(pathLock, ec) && !ec;

    state.nDataFileBytes = std::filesystem::file_size(pathData, ec);
    if (ec) {
        state.strReason = "cannot read the size of data.mdb";
        return state;
    }

    // Both LMDB meta pages must be present.  LMDB maps whole pages, so a file
    // shorter than two pages cannot be a complete environment even if the
    // first meta page happens to look valid.
    const size_t nSystemPage = GetSystemPageSize();
    const uintmax_t nMinimum =
        2ULL * (nSystemPage > 0 ? nSystemPage : 4096ULL);
    if (state.nDataFileBytes < nMinimum) {
        state.strReason = strprintf(
            "data.mdb is only %llu bytes, too small to contain two LMDB "
            "meta pages",
            static_cast<unsigned long long>(state.nDataFileBytes));
        return state;
    }

    state.fComplete = true;
    return state;
}

bool HasLMDBChainIndex(const std::filesystem::path& dir)
{
    return InspectLMDBEnvironmentOnDisk(dir / "blkindex").fComplete;
}

bool CheckChainBackendCompatibility(const std::filesystem::path& dir)
{
    std::string strMarker;
    if (ReadChainBackendMarker(dir, strMarker)) {
        if (strMarker != "lmdb" && strMarker != "bdb")
            return error("Unknown chain backend marker in %s: '%s'",
                         GetChainBackendMarkerPath(dir).string().c_str(),
                         strMarker.c_str());

        if (strMarker == "bdb")
            return error("This data directory uses the Berkeley DB chain index. "
                         "Berkeley DB support has been removed. Migrate it "
                         "offline with phoenix-db-migrate before starting.");
        return true;
    }

    // Current builds do not write a marker.  An existing LMDB chain index is
    // authoritative so a stale blkindex.dat is never loaded; a marker left by
    // a migration-window build was handled above.
    const LMDBOnDiskState state = InspectLMDBEnvironmentOnDisk(dir / "blkindex");
    if (state.fDirectoryExists && !state.fComplete)
        return error("The LMDB chain index at %s is incomplete: %s. "
                     "Restore it from a verified backup, or remove the "
                     "directory to let the node create a fresh index.",
                     (dir / "blkindex").string().c_str(),
                     state.strReason.c_str());

    return true;
}

namespace {

std::filesystem::path GetWalletBackendMarkerPath(const std::filesystem::path& dir)
{
    return dir / WALLET_BACKEND_MARKER;
}

std::filesystem::path GetWalletLMDBPath(const std::filesystem::path& dir)
{
    return dir / "wallet";
}

} // namespace

bool IsActiveLMDBEnvironmentPath(const std::filesystem::path& path)
{
    std::error_code ec;
    const std::filesystem::path canonical =
        std::filesystem::weakly_canonical(path, ec);
    if (ec)
        return false;

    const auto matches = [&canonical](const CLMDBEnv& env) {
        if (!env.IsOpen() || env.GetPath().empty())
            return false;
        std::error_code envEc;
        const std::filesystem::path envPath =
            std::filesystem::weakly_canonical(env.GetPath(), envEc);
        return !envEc && envPath == canonical;
    };

    return matches(g_lmdbChainEnv) || matches(g_lmdbWalletEnv);
}

bool ReadWalletBackendMarker(const std::filesystem::path& dir, std::string& strBackend)
{
    std::ifstream file(GetWalletBackendMarkerPath(dir));
    if (!file)
        return false;

    std::getline(file, strBackend);
    while (!strBackend.empty() &&
           (strBackend.back() == '\r' || strBackend.back() == '\n' ||
            strBackend.back() == ' ' || strBackend.back() == '\t'))
        strBackend.pop_back();
    while (!strBackend.empty() &&
           (strBackend.front() == ' ' || strBackend.front() == '\t'))
        strBackend.erase(strBackend.begin());
    return true;
}

bool HasLMDBWallet(const std::filesystem::path& dir)
{
    return InspectLMDBEnvironmentOnDisk(GetWalletLMDBPath(dir)).fComplete;
}

bool CheckWalletBackendCompatibility(const std::filesystem::path& dir)
{
    std::string strMarker;
    if (ReadWalletBackendMarker(dir, strMarker)) {
        if (strMarker != "lmdb" && strMarker != "bdb")
            return error("Unknown wallet backend marker in %s: '%s'",
                         GetWalletBackendMarkerPath(dir).string().c_str(),
                         strMarker.c_str());

        // The marker is authoritative in both directions.  In particular, a
        // leftover wallet/ directory must not let an LMDB start adopt a data
        // directory whose marker still says Berkeley DB owns the wallet.
        if (strMarker == "bdb")
            return error("This data directory uses the Berkeley DB wallet. "
                         "Berkeley DB support has been removed. Migrate it "
                         "offline with phoenix-db-migrate before starting.");
        return true;
    }

    // Current builds do not write a marker.  Treat an existing LMDB wallet as
    // authoritative so that a stale wallet.dat is never opened; a marker left
    // by a migration-window build was handled above.
    const LMDBOnDiskState state =
        InspectLMDBEnvironmentOnDisk(GetWalletLMDBPath(dir));
    if (state.fDirectoryExists && !state.fComplete)
        return error("The LMDB wallet at %s is incomplete: %s. "
                     "Restore it from a verified backup, or run "
                     "phoenix-db-migrate to rebuild it from wallet.dat.",
                     GetWalletLMDBPath(dir).string().c_str(),
                     state.strReason.c_str());

    return true;
}

WalletStartupAction GetWalletStartupAction(bool fMarkerLMDB, bool fLMDBEmpty,
                                           bool fBDBWalletExists)
{
    if (!fLMDBEmpty)
        return WALLET_USE_EXISTING;
    if (fMarkerLMDB)
        return WALLET_FAIL_MISSING;
    if (fBDBWalletExists)
        return WALLET_REQUIRES_MIGRATION;
    return WALLET_INIT_NEW;
}

ChainIndexStartupAction GetChainIndexStartupAction(bool fMarkerLMDB,
                                                   bool fLMDBEmpty,
                                                   bool fBDBSourceExists)
{
    if (!fLMDBEmpty)
        return CHAIN_INDEX_USE_EXISTING;
    if (fMarkerLMDB)
        return CHAIN_INDEX_FAIL_MISSING;
    if (fBDBSourceExists)
        return CHAIN_INDEX_REQUIRES_MIGRATION;
    return CHAIN_INDEX_INIT_NEW;
}

int64 GetLMDBMaxMapSizeMiB()
{
    return LMDB_MAX_MAPSIZE_MIB;
}

int64 GetLMDBDefaultMapSizeMiB()
{
    return LMDB_DEFAULT_MAPSIZE_MIB;
}

int64 GetLMDBDefaultWalletMapSizeMiB()
{
    return LMDB_DEFAULT_WALLET_MAPSIZE_MIB;
}

int64 GetLMDBDefaultMaxMapSizeMiB()
{
    // The map is virtual address space, not a preallocation.  A 1 TiB ceiling
    // leaves ample room for chain growth while still bounding a runaway import
    // or a bug; 32-bit builds cannot map more than about 2 GiB.
#if defined(__LP64__) || defined(_WIN64)
    return 1024LL * 1024LL; // 1 TiB
#else
    return 2048; // 2 GiB
#endif
}

bool ParseLMDBMapSize(const std::string& strValue, size_t& nBytes, std::string& strError)
{
    int64 nMiB = 0;
    if (!ParseInt64Strict(strValue, nMiB))
    {
        strError = strprintf("'%s' is not a valid number of MiB", strValue.c_str());
        return false;
    }

    if (nMiB <= 0)
    {
        strError = strprintf("must be a positive number of MiB (got %s)",
                             std::to_string(nMiB).c_str());
        return false;
    }

    if (nMiB > LMDB_MAX_MAPSIZE_MIB)
    {
        strError = strprintf("%s MiB exceeds the maximum supported value of %s MiB "
                             "for this platform",
                             std::to_string(nMiB).c_str(),
                             std::to_string(LMDB_MAX_MAPSIZE_MIB).c_str());
        return false;
    }

    // The multiplication is safe: nMiB is positive and at most
    // SIZE_MAX / MiB (or 2048 on 32-bit builds).
    const size_t nCandidate = static_cast<size_t>(nMiB) * (1024ULL * 1024ULL);

    const size_t nPageSize = GetSystemPageSize();
    if (nPageSize > 0 && nPageSize <= nCandidate && nCandidate % nPageSize != 0)
    {
        strError = strprintf("%s MiB is not a multiple of the system page size "
                             "(%s bytes)",
                             std::to_string(nMiB).c_str(),
                             std::to_string(nPageSize).c_str());
        return false;
    }

    nBytes = nCandidate;
    return true;
}

bool ResolveLMDBMapSizes(const std::string& strMapSize,
                         const std::string& strMaxMapSize,
                         int64 nDefaultInitialMiB,
                         bool fAutoGrow,
                         size_t& nMapSize,
                         size_t& nMaxMapSize,
                         std::string& strError)
{
    const std::string strInitial = strMapSize.empty()
        ? std::to_string(nDefaultInitialMiB) : strMapSize;
    if (!ParseLMDBMapSize(strInitial, nMapSize, strError))
        return false;

    if (!fAutoGrow) {
        // With runtime growth disabled the initial map is the fixed limit.
        nMaxMapSize = nMapSize;
        return true;
    }

    const std::string strMaximum = strMaxMapSize.empty()
        ? std::to_string(GetLMDBDefaultMaxMapSizeMiB()) : strMaxMapSize;
    if (!ParseLMDBMapSize(strMaximum, nMaxMapSize, strError))
        return false;

    if (nMaxMapSize < nMapSize) {
        strError = strprintf(
            "maximum map size (%s MiB) is smaller than the initial map size "
            "(%s MiB)",
            std::to_string(nMaxMapSize / (1024ULL * 1024ULL)).c_str(),
            std::to_string(nMapSize / (1024ULL * 1024ULL)).c_str());
        return false;
    }

    return true;
}

std::unique_ptr<CDBTransaction> BeginChainTransaction(bool fReadOnly)
{
    if (!g_fLMDBChainEnabled)
        return nullptr;

    if (fReadOnly)
        return g_lmdbChainDb.BeginTransaction(true);

    // The environment allows a single writer.  Other writers may be busy for a
    // short time, so wait for the slot rather than failing a block write.
    for (int i = 0; i < 60000; ++i) {
        std::unique_ptr<CDBTransaction> txn = g_lmdbChainDb.BeginTransaction(false);
        if (txn)
            return txn;
        if (fShutdown)
            break;
        Sleep(1);
    }
    return nullptr;
}

static bool IsChainFile(std::string strFile);

CDB::CDB(const char *pszFile, const char* pszMode) :
    fReadOnly(false), fUseKVWallet(false)
{
    if (pszFile == nullptr)
        return;

    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));
    bool fCreate = strchr(pszMode, 'c');

    // The chain index and the wallet are both LMDB.  They have separate
    // environments, so remember which one this handle belongs to.
    if (IsChainFile(pszFile))
    {
        strFile = pszFile;
        if (!IsLMDBChainEnabled())
            throw runtime_error("chain database is not open");
    }
    else if (string(pszFile) == "wallet.dat")
    {
        strFile = pszFile;
        fUseKVWallet = true;
        {
            // Rewrite and backup hold this lock while they wait for open
            // handles to drain, then replace the environment.
            std::lock_guard<std::mutex> lock(g_mutexWalletKV);
            ++g_nWalletKVHandles;
        }
    }
    else
    {
        throw runtime_error(strprintf("CDB() : unsupported database file %s",
                                      pszFile));
    }

    // Match the old constructor: a newly created database records the client
    // version before it is used.
    if (fCreate && !Exists(string("version")))
    {
        bool fTmp = fReadOnly;
        fReadOnly = false;
        WriteVersion(CLIENT_VERSION);
        fReadOnly = fTmp;
    }
}

static bool IsChainFile(std::string strFile)
{
    if (strFile == "blkindex.dat")
        return true;

    return false;
}

void CDB::Close()
{
    if (kvTxn)
    {
        kvTxn->Abort();
        kvTxn.reset();
    }
    kvTxnRecordTypes.clear();
    if (fUseKVWallet)
    {
        fUseKVWallet = false;
        --g_nWalletKVHandles;
    }
}

bool CDB::ReadKV(const CDBKey& key, CDBValue& value)
{
    if (kvTxn)
        return kvTxn->Read(key, value);

    std::unique_ptr<CDBTransaction> txn = BeginKVTransaction(true);
    if (!txn)
        return false;
    bool fFound = txn->Read(key, value);
    txn->Commit();
    return fFound;
}

bool CDB::WriteKV(const CDBKey& key, const CDBValue& value, bool fOverwrite)
{
    if (kvTxn)
    {
        bool fWritten = kvTxn->Write(key, value, fOverwrite);
        if (fUseKVWallet && fWritten)
        {
            const std::string strType = TestWalletRecordType(key);
            // The record is staged but not durable yet.  A kill here must
            // leave the whole transaction rolled back.
            TestWalletCrashPoint(("wallet-write-before-commit:" +
                                  strType).c_str());
            kvTxnRecordTypes.push_back(strType);
        }
        return fWritten;
    }

    // Outside an explicit transaction, commit every write so readers see it.
    std::unique_ptr<CDBTransaction> txn = BeginKVTransaction(false);
    if (!txn)
        return false;
    bool fWritten = txn->Write(key, value, fOverwrite);
    if (fUseKVWallet)
        TestWalletCrashPoint(("wallet-write-before-commit:" +
                              TestWalletRecordType(key)).c_str());
    bool fCommitted = txn->Commit();
    if (fUseKVWallet && fWritten && fCommitted)
        TestWalletCrashPoint(("wallet-write-after-commit:" +
                              TestWalletRecordType(key)).c_str());
    return fWritten && fCommitted;
}

bool CDB::EraseKV(const CDBKey& key)
{
    if (kvTxn)
    {
        bool fErased = kvTxn->Erase(key);
        if (fUseKVWallet && fErased)
        {
            const std::string strType = TestWalletRecordType(key);
            TestWalletCrashPoint(("wallet-write-before-commit:" +
                                  strType).c_str());
            kvTxnRecordTypes.push_back(strType);
        }
        return fErased;
    }

    std::unique_ptr<CDBTransaction> txn = BeginKVTransaction(false);
    if (!txn)
        return false;
    bool fErased = txn->Erase(key);
    if (fUseKVWallet)
        TestWalletCrashPoint(("wallet-write-before-commit:" +
                              TestWalletRecordType(key)).c_str());
    bool fCommitted = txn->Commit();
    if (fUseKVWallet && fCommitted)
        TestWalletCrashPoint(("wallet-write-after-commit:" +
                              TestWalletRecordType(key)).c_str());
    return fErased && fCommitted;
}

bool CDB::ExistsKV(const CDBKey& key)
{
    if (kvTxn)
    {
        CDBValue value;
        return kvTxn->Read(key, value);
    }

    std::unique_ptr<CDBTransaction> txn = BeginKVTransaction(true);
    if (!txn)
        return false;
    CDBValue value;
    bool fFound = txn->Read(key, value);
    txn->Commit();
    return fFound;
}

std::unique_ptr<CDBScan> CDB::GetScan(const CDBKey& prefix)
{
    std::unique_ptr<CDBTransaction> txn = BeginKVTransaction(true);
    if (!txn)
        return nullptr;
    std::unique_ptr<CDBIterator> it = txn->NewIterator(prefix);
    if (!it)
    {
        txn->Abort();
        return nullptr;
    }
    return std::make_unique<CDBScan>(std::move(txn), std::move(it));
}

namespace {

bool IsChainLMDBEmpty(bool& fEmpty)
{
    std::unique_ptr<CDBTransaction> txn = g_lmdbChainDb.BeginTransaction(true);
    if (!txn)
        return false;
    std::unique_ptr<CDBIterator> it = txn->NewIterator();
    it->SeekToFirst();
    fEmpty = !it->Valid();
    it.reset();
    return txn->Commit();
}

bool MissingLMDBChainIndexError(const std::filesystem::path& pathChain)
{
    const LMDBOnDiskState state = InspectLMDBEnvironmentOnDisk(pathChain);
    if (state.fDirectoryExists && !state.fComplete)
        return error("The LMDB chain index at %s is incomplete: %s. "
                     "blkindex.backend marks LMDB as authoritative, so the "
                     "node will not silently fall back to blkindex.dat. Restore "
                     "the chain index from a verified backup (check it with "
                     "-checklmdb), or run phoenix-db-migrate to rebuild it from "
                     "a legacy blkindex.dat.",
                     pathChain.string().c_str(), state.strReason.c_str());

    return error("The LMDB chain index at %s is missing or empty, but "
                 "blkindex.backend marks LMDB as authoritative. Restore the "
                 "chain index from a backup, or run phoenix-db-migrate to "
                 "rebuild it from a legacy blkindex.dat.",
                 pathChain.string().c_str());
}

} // namespace

bool InitLMDBChainDB()
{
    if (!CheckChainBackendCompatibility(GetDataDir()))
        return false;

    const std::filesystem::path pathChain = GetDataDir() / "blkindex";

    std::string strMarker;
    const bool fMarkerLMDB = ReadChainBackendMarker(GetDataDir(), strMarker) &&
                             strMarker == "lmdb";

    // Once the marker says LMDB is authoritative, an empty or missing LMDB
    // index is data loss.  Never silently resurrect a migration-time source
    // file; a deliberate re-import requires running the converter again.
    if (fMarkerLMDB && !HasLMDBChainIndex(GetDataDir()))
        return MissingLMDBChainIndexError(pathChain);

    const std::string strMapSize = mapArgs.count("-lmdbmapsize")
        ? mapArgs["-lmdbmapsize"] : std::string();
    const std::string strMaxMapSize = mapArgs.count("-lmdbmaxmapsize")
        ? mapArgs["-lmdbmaxmapsize"] : std::string();
    const bool fAutoGrow = GetBoolArg("-lmdbruntimegrow", true);
    size_t nMapSize = 0;
    size_t nMaxMapSize = 0;
    std::string strMapSizeError;
    if (!ResolveLMDBMapSizes(strMapSize, strMaxMapSize, LMDB_DEFAULT_MAPSIZE_MIB,
                             fAutoGrow, nMapSize, nMaxMapSize,
                             strMapSizeError))
        return error("InitLMDBChainDB(): invalid LMDB map size: %s",
                     strMapSizeError.c_str());

    // Durability is the safe default.  -lmdbnosync=1 is an explicit opt-in
    // for bulk import or benchmarking; it keeps commits atomic and consistent
    // but skips the per-commit fsync.
    const bool fNoSync = GetBoolArg("-lmdbnosync", false);

    if (!g_lmdbChainEnv.Open(pathChain.string(), true, nMapSize, fNoSync,
                             "-lmdbmapsize", false, nMaxMapSize, fAutoGrow))
        return error("InitLMDBChainDB(): failed to open LMDB environment %s",
                     pathChain.string().c_str());

    if (!g_lmdbChainDb.Open(g_lmdbChainEnv, "main", true))
    {
        g_lmdbChainEnv.Close();
        return error("InitLMDBChainDB(): failed to open chain database");
    }

    bool fLMDBEmpty = false;
    if (!IsChainLMDBEmpty(fLMDBEmpty))
    {
        g_lmdbChainDb.Close();
        g_lmdbChainEnv.Close();
        return error("InitLMDBChainDB(): cannot inspect LMDB chain index");
    }

    const bool fBDBSourceExists =
        std::filesystem::exists(GetDataDir() / "blkindex.dat");

    switch (GetChainIndexStartupAction(fMarkerLMDB, fLMDBEmpty,
                                       fBDBSourceExists))
    {
    case CHAIN_INDEX_FAIL_MISSING:
        g_lmdbChainDb.Close();
        g_lmdbChainEnv.Close();
        return MissingLMDBChainIndexError(pathChain);

    case CHAIN_INDEX_REQUIRES_MIGRATION:
        g_lmdbChainDb.Close();
        g_lmdbChainEnv.Close();
        return error("Found a Berkeley DB chain index at %s, but Berkeley DB "
                     "support has been removed. Migrate it offline with "
                     "phoenix-db-migrate before starting the node.",
                     (GetDataDir() / "blkindex.dat").string().c_str());

    case CHAIN_INDEX_INIT_NEW:
    case CHAIN_INDEX_USE_EXISTING:
        break;
    }

    // No backend marker is written.  A marker created by a migration-window
    // build is still read above; new data directories simply use the LMDB
    // environment as the authority.
    g_fLMDBChainEnabled = true;
    printf("Chain index database: LMDB (%s%s)\n", pathChain.string().c_str(),
           fNoSync ? ", nosync" : "");
    LogLMDBMapUsage();
    return true;
}

void CloseLMDBChainDB()
{
    if (!g_fLMDBChainEnabled)
        return;
    g_fLMDBChainEnabled = false;
    g_lmdbChainDb.Close();
    g_lmdbChainEnv.Close();
}

bool IsLMDBChainEnabled()
{
    return g_fLMDBChainEnabled;
}

namespace {

bool IsWalletLMDBEmpty(bool& fEmpty)
{
    std::unique_ptr<CDBTransaction> txn = g_lmdbWalletDb.BeginTransaction(true);
    if (!txn)
        return false;
    std::unique_ptr<CDBIterator> it = txn->NewIterator();
    if (!it)
    {
        txn->Abort();
        return false;
    }
    it->SeekToFirst();
    fEmpty = !it->Valid();
    const bool fError = it->Error();
    it.reset();
    if (fError || !txn->Commit())
        return false;
    return true;
}

bool MissingLMDBWalletError(const std::filesystem::path& pathWallet)
{
    const LMDBOnDiskState state = InspectLMDBEnvironmentOnDisk(pathWallet);
    if (state.fDirectoryExists && !state.fComplete)
        return error("The LMDB wallet at %s is incomplete: %s. "
                     "wallet.backend marks LMDB as authoritative, so the node "
                     "will not silently fall back to wallet.dat. Restore the "
                     "wallet from a verified backup (check it with "
                     "-checklmdb), or run phoenix-db-migrate to rebuild it from "
                     "a legacy wallet.dat.",
                     pathWallet.string().c_str(), state.strReason.c_str());

    return error("The LMDB wallet at %s is missing or empty, but wallet.backend "
                 "marks LMDB as authoritative. Restore the wallet from a "
                 "backup, or run phoenix-db-migrate to rebuild it from a legacy "
                 "wallet.dat.",
                 pathWallet.string().c_str());
}

// RewriteWalletLMDB() stages the compacted environment in wallet.rewrite,
// moves the active environment to wallet.old and then installs the staged one.
// A crash between those renames leaves no wallet/ directory at all, which the
// startup state machine would otherwise report as data loss.  Finish or undo
// the rewrite before the compatibility and emptiness checks look at the
// directory.
void RecoverInterruptedWalletRewrite(const std::filesystem::path& dir)
{
    const std::filesystem::path pathWallet = dir / "wallet";
    const std::filesystem::path pathNew = dir / "wallet.rewrite";
    const std::filesystem::path pathOld = dir / "wallet.old";
    std::error_code ec;

    // A marker temp file without a marker means a migration-window build died
    // between write() and rename().  Current builds do not write markers, so
    // the staged file is simply stale; the committed wallet is authoritative.
    std::filesystem::remove(dir / "wallet.backend.tmp", ec);

    const bool fWallet = std::filesystem::exists(pathWallet, ec) && !ec;
    const bool fNew = std::filesystem::exists(pathNew, ec) && !ec;
    const bool fOld = std::filesystem::exists(pathOld, ec) && !ec;

    if (!fWallet && (fNew || fOld))
    {
        // Prefer the compacted copy: it is complete by the time the old
        // environment is renamed.  Fall back to the old environment if the
        // copy is missing.
        const std::filesystem::path& pathRestore = fNew ? pathNew : pathOld;
        std::filesystem::rename(pathRestore, pathWallet, ec);
        if (ec)
            error("RecoverInterruptedWalletRewrite(): cannot restore %s: %s",
                  pathRestore.string().c_str(), ec.message().c_str());
        else
            printf("Recovered interrupted LMDB wallet rewrite from %s\n",
                   pathRestore.string().c_str());
    }

    if (std::filesystem::exists(pathWallet, ec) && !ec)
    {
        // Any remaining staging directory is superseded.  wallet.old may
        // still contain the plaintext keys encryption was compacting away, so
        // it must not be left behind.
        std::filesystem::remove_all(pathNew, ec);
        std::filesystem::remove_all(pathOld, ec);
    }
}

bool InitLMDBWalletDBInternal(const std::filesystem::path& dir,
                              size_t nMapSize,
                              size_t nMaxMapSize,
                              bool fAutoGrow,
                              bool fNoSync)
{
    const std::filesystem::path pathWallet = dir / "wallet";

    // Re-check the marker here as well, so the test entry point (and any
    // future caller) cannot bypass the authority rules enforced by
    // InitLMDBWalletDB().
    if (!CheckWalletBackendCompatibility(dir))
        return false;

    RecoverInterruptedWalletRewrite(dir);

    std::string strMarker;
    const bool fMarkerLMDB = ReadWalletBackendMarker(dir, strMarker) &&
                             strMarker == "lmdb";
    const bool fBDBWalletExists = std::filesystem::exists(dir / "wallet.dat");

    // Once the marker says LMDB is authoritative, an empty or missing LMDB
    // wallet is data loss, not an invitation to create a fresh wallet.
    if (fMarkerLMDB && !HasLMDBWallet(dir))
        return MissingLMDBWalletError(pathWallet);

    if (!g_lmdbWalletEnv.Open(pathWallet.string(), true, nMapSize, fNoSync,
                              "-lmdbwalletsize", false, nMaxMapSize, fAutoGrow))
        return error("InitLMDBWalletDB(): failed to open LMDB environment %s",
                     pathWallet.string().c_str());

    if (!g_lmdbWalletDb.Open(g_lmdbWalletEnv, "main", true))
    {
        g_lmdbWalletEnv.Close();
        return error("InitLMDBWalletDB(): failed to open wallet database");
    }

    bool fLMDBEmpty = false;
    if (!IsWalletLMDBEmpty(fLMDBEmpty))
    {
        g_lmdbWalletDb.Close();
        g_lmdbWalletEnv.Close();
        return error("InitLMDBWalletDB(): cannot inspect LMDB wallet");
    }

    switch (GetWalletStartupAction(fMarkerLMDB, fLMDBEmpty, fBDBWalletExists))
    {
    case WALLET_FAIL_MISSING:
        g_lmdbWalletDb.Close();
        g_lmdbWalletEnv.Close();
        return MissingLMDBWalletError(pathWallet);

    case WALLET_REQUIRES_MIGRATION:
        g_lmdbWalletDb.Close();
        g_lmdbWalletEnv.Close();
        return error("Found a Berkeley DB wallet at %s, but Berkeley DB support "
                     "has been removed. Migrate it offline with "
                     "phoenix-db-migrate before starting the node.",
                     (dir / "wallet.dat").string().c_str());

    case WALLET_INIT_NEW:
    case WALLET_USE_EXISTING:
        break;
    }

    // No backend marker is written; a marker left by a migration-window build
    // is still read above.  New data directories use the LMDB environment as
    // the authority.
    g_fLMDBWalletEnabled = true;
    g_nWalletMapSize = nMapSize;
    g_nWalletMaxMapSize = nMaxMapSize;
    g_fWalletAutoGrow = fAutoGrow;
    g_fWalletNoSync = fNoSync;
    g_pathLMDBWalletDir = dir;
    printf("Wallet database: LMDB (%s%s)\n", pathWallet.string().c_str(),
           fNoSync ? ", nosync" : "");
    return true;
}

// Opens the wallet environment after a rewrite step has closed it.
// pszPoint names the operation for test-only failure injection; it is inert
// unless a test has armed that exact point.
bool ReopenLMDBWallet(const std::filesystem::path& pathWallet,
                      const char* pszPoint)
{
    if (TestWalletRewriteFailureMatches(pszPoint))
        return false;

    if (!g_lmdbWalletEnv.Open(pathWallet.string(), true, g_nWalletMapSize,
                              g_fWalletNoSync, "-lmdbwalletsize", false,
                              g_nWalletMaxMapSize, g_fWalletAutoGrow))
        return false;

    if (!g_lmdbWalletDb.Open(g_lmdbWalletEnv, "main", true))
    {
        g_lmdbWalletEnv.Close();
        return false;
    }
    return true;
}

// Renames a rewrite component, honouring the test-only failure injection.
bool RewriteRename(const std::filesystem::path& pathFrom,
                   const std::filesystem::path& pathTo,
                   const char* pszPoint,
                   std::error_code& ec)
{
    if (TestWalletRewriteFailureMatches(pszPoint))
    {
        ec = std::make_error_code(std::errc::io_error);
        return false;
    }
    std::filesystem::rename(pathFrom, pathTo, ec);
    return !ec;
}

// A rewrite failure that leaves no usable LMDB environment cannot fall back
// to Berkeley DB: the LMDB environment remains authoritative (a legacy
// wallet.backend marker, if present, still says lmdb), so any BDB write would
// be invisible after the next restart.  Stop instead of continuing with a
// split wallet.  Tests can arm TestWalletRewriteAbort to
// observe the decision without terminating the test process.
bool FatalWalletRewrite(const char* pszReason)
{
    error("RewriteWalletLMDB(): %s; LMDB remains authoritative, refusing to "
          "fall back to Berkeley DB", pszReason);
    if (g_fTestWalletRewriteAbort.load())
    {
        g_fTestWalletRewriteAborted.store(true);
        return false;
    }
    exit(1);
}

// Compacts the LMDB wallet into a fresh environment.  LMDB is copy-on-write,
// so overwritten pages (including the plaintext keys removed during wallet
// encryption) stay in the file until the environment is copied or compacted.
//
// Once the live environment is closed it must be reopened before the caller
// resumes, even when the rewrite fails: the LMDB environment remains
// authoritative, so a Berkeley DB fallback would accept writes that the next
// LMDB start could not see.  g_fLMDBWalletEnabled and g_pathLMDBWalletDir
// therefore never change here.
bool RewriteWalletLMDB()
{
    if (!g_fLMDBWalletEnabled)
        return true;

    std::lock_guard<std::mutex> lock(g_mutexWalletKV);

    while (g_nWalletKVHandles.load() > 0 && !fShutdown)
        Sleep(100);
    if (fShutdown)
        return false;

    const std::filesystem::path dir = g_pathLMDBWalletDir.empty()
        ? GetDataDir() : g_pathLMDBWalletDir;
    const std::filesystem::path pathWallet = dir / "wallet";
    const std::filesystem::path pathNew = dir / "wallet.rewrite";
    const std::filesystem::path pathOld = dir / "wallet.old";

    std::error_code ec;
    std::filesystem::remove_all(pathNew, ec);
    std::filesystem::remove_all(pathOld, ec);

    MDB_env* env = g_lmdbWalletEnv.GetEnv();
    if (!env)
        return error("RewriteWalletLMDB(): the LMDB environment is not open");

    if (!g_lmdbWalletEnv.Sync(true))
        return false;

    // mdb_env_copy2() requires the destination directory to exist and to be
    // empty; it does not create it.
    if (!std::filesystem::create_directories(pathNew, ec) && ec)
    {
        std::filesystem::remove_all(pathNew, ec);
        return error("RewriteWalletLMDB(): cannot create %s",
                     pathNew.string().c_str());
    }

    int rc = mdb_env_copy2(env, pathNew.string().c_str(), MDB_CP_COMPACT);
    if (rc != 0)
    {
        std::filesystem::remove_all(pathNew, ec);
        return error("RewriteWalletLMDB(): mdb_env_copy2 failed: %s",
                     mdb_strerror(rc));
    }
    TestWalletCrashPoint("wallet-rewrite-after-copy");

    // The copy is complete and synced.  From here on the environment has to
    // be closed for the directory renames; every failure path below either
    // reopens a usable environment or stops the process.
    g_lmdbWalletDb.Close();
    g_lmdbWalletEnv.Close();

    if (!RewriteRename(pathWallet, pathOld, "wallet-rewrite-rename-old", ec))
    {
        // Nothing moved: wallet/ is still the active environment.
        std::filesystem::remove_all(pathNew, ec);
        if (!ReopenLMDBWallet(pathWallet, "wallet-rewrite-reopen-old"))
            return FatalWalletRewrite("cannot move the old wallet aside and "
                                      "cannot reopen it");
        return error("RewriteWalletLMDB(): cannot move the old wallet aside");
    }
    TestWalletCrashPoint("wallet-rewrite-after-old-rename");

    if (!RewriteRename(pathNew, pathWallet, "wallet-rewrite-install", ec))
    {
        // Put the old environment back.  Do not continue writing into
        // wallet.old: startup recovery prefers wallet.rewrite over wallet.old,
        // so those writes could be lost if the process died now.
        std::error_code restoreEc;
        if (RewriteRename(pathOld, pathWallet, "wallet-rewrite-restore",
                          restoreEc))
        {
            if (ReopenLMDBWallet(pathWallet, "wallet-rewrite-reopen-restored"))
            {
                std::filesystem::remove_all(pathNew, restoreEc);
                return error("RewriteWalletLMDB(): cannot install the "
                             "compacted wallet; restored the old wallet");
            }
        }
        return FatalWalletRewrite("cannot install the compacted wallet or "
                                  "restore the old one");
    }
    TestWalletCrashPoint("wallet-rewrite-after-install");

    if (!ReopenLMDBWallet(pathWallet, "wallet-rewrite-reopen-installed"))
    {
        // The compacted copy is installed but unusable.  Park it, restore the
        // old environment and reopen that, so the process keeps using LMDB.
        std::error_code rollbackEc;
        std::filesystem::rename(pathWallet, pathNew, rollbackEc);
        if (!rollbackEc)
            std::filesystem::rename(pathOld, pathWallet, rollbackEc);

        if (!rollbackEc &&
            ReopenLMDBWallet(pathWallet, "wallet-rewrite-reopen-restored"))
        {
            std::filesystem::remove_all(pathNew, rollbackEc);
            return error("RewriteWalletLMDB(): cannot reopen the compacted "
                         "wallet; restored the old wallet");
        }
        return FatalWalletRewrite("cannot reopen the compacted wallet or "
                                  "restore the old one");
    }

    // The new environment is active.  If the plaintext old copy cannot be
    // removed, report failure so callers that require compaction (wallet
    // encryption) can stop; LMDB stays enabled and usable, and startup
    // recovery removes the leftover copy on the next start.
    if (TestWalletRewriteFailureMatches("wallet-rewrite-remove-old"))
        ec = std::make_error_code(std::errc::io_error);
    else
        std::filesystem::remove_all(pathOld, ec);
    if (ec)
        return error("RewriteWalletLMDB(): cannot remove the old wallet %s: %s",
                     pathOld.string().c_str(), ec.message().c_str());

    printf("Rewrote LMDB wallet %s\n", pathWallet.string().c_str());
    return true;
}

} // namespace

namespace {

// Test-only failure injection for wallet write transactions (see db.h).
struct TestWalletFailureState
{
    CCriticalSection cs;
    bool fWriteArmed = false;
    bool fCommitArmed = false;
    std::string strType;
    int nSkip = 0;
    int nCommitSkip = 0;
};

TestWalletFailureState g_testWalletFailure;
std::atomic<bool> g_fTestWalletFailureArmed(false);
std::atomic<bool> g_fTestChainCommitFailureArmed(false);

} // namespace

void SetTestWalletWriteFailure(const std::string& strType, int nSkip)
{
    LOCK(g_testWalletFailure.cs);
    g_testWalletFailure.fWriteArmed = true;
    g_testWalletFailure.fCommitArmed = false;
    g_testWalletFailure.strType = strType;
    g_testWalletFailure.nSkip = std::max(nSkip, 0);
    g_testWalletFailure.nCommitSkip = 0;
    g_fTestWalletFailureArmed.store(true);
}

void SetTestWalletCommitFailure(int nSkip)
{
    LOCK(g_testWalletFailure.cs);
    g_testWalletFailure.fWriteArmed = false;
    g_testWalletFailure.fCommitArmed = true;
    g_testWalletFailure.strType.clear();
    g_testWalletFailure.nSkip = 0;
    g_testWalletFailure.nCommitSkip = std::max(nSkip, 0);
    g_fTestWalletFailureArmed.store(true);
}

void ClearTestWalletWriteFailures()
{
    {
        LOCK(g_testWalletFailure.cs);
        g_testWalletFailure.fWriteArmed = false;
        g_testWalletFailure.fCommitArmed = false;
        g_testWalletFailure.strType.clear();
        g_testWalletFailure.nSkip = 0;
        g_testWalletFailure.nCommitSkip = 0;
    }
    g_fTestWalletFailureArmed.store(false);
}

bool TestWalletWriteFailureArmed()
{
    return g_fTestWalletFailureArmed.load();
}

bool TestWalletWriteFailureMatches(const std::string& strType)
{
    LOCK(g_testWalletFailure.cs);
    if (!g_testWalletFailure.fWriteArmed ||
        strType != g_testWalletFailure.strType)
        return false;
    if (g_testWalletFailure.nSkip > 0)
    {
        --g_testWalletFailure.nSkip;
        return false;
    }
    g_testWalletFailure.fWriteArmed = false;
    g_fTestWalletFailureArmed.store(false);
    return true;
}

bool ConsumeTestWalletCommitFailure()
{
    LOCK(g_testWalletFailure.cs);
    if (!g_testWalletFailure.fCommitArmed)
        return false;
    if (g_testWalletFailure.nCommitSkip > 0)
    {
        --g_testWalletFailure.nCommitSkip;
        return false;
    }
    g_testWalletFailure.fCommitArmed = false;
    g_fTestWalletFailureArmed.store(false);
    return true;
}

void SetTestChainCommitFailure()
{
    g_fTestChainCommitFailureArmed.store(true);
}

void ClearTestChainCommitFailure()
{
    g_fTestChainCommitFailureArmed.store(false);
}

bool ConsumeTestChainCommitFailure()
{
    return g_fTestChainCommitFailureArmed.exchange(false);
}

void SetTestWalletRewriteFailure(const std::string& strPoint, int nSkip)
{
    std::lock_guard<std::mutex> lock(g_testWalletRewrite.mutex);
    g_testWalletRewrite.mapSkip[strPoint] = std::max(nSkip, 0);
}

void ClearTestWalletRewriteFailures()
{
    {
        std::lock_guard<std::mutex> lock(g_testWalletRewrite.mutex);
        g_testWalletRewrite.mapSkip.clear();
    }
    g_fTestWalletRewriteAbort.store(false);
    g_fTestWalletRewriteAborted.store(false);
}

void SetTestWalletRewriteAbort(bool fAbort)
{
    g_fTestWalletRewriteAbort.store(fAbort);
    if (!fAbort)
        g_fTestWalletRewriteAborted.store(false);
}

bool TestWalletRewriteAbortArmed()
{
    return g_fTestWalletRewriteAbort.load();
}

bool TestWalletRewriteAborted()
{
    return g_fTestWalletRewriteAborted.load();
}

bool InitLMDBWalletDB()
{
    printf("Wallet backend: LMDB\n");
    if (!CheckWalletBackendCompatibility(GetDataDir()))
        return false;

    const std::string strMapSize = mapArgs.count("-lmdbwalletsize")
        ? mapArgs["-lmdbwalletsize"] : std::string();
    const std::string strMaxMapSize = mapArgs.count("-lmdbmaxwalletsize")
        ? mapArgs["-lmdbmaxwalletsize"] : std::string();
    const bool fAutoGrow = GetBoolArg("-lmdbruntimegrow", true);
    size_t nMapSize = 0;
    size_t nMaxMapSize = 0;
    std::string strMapSizeError;
    if (!ResolveLMDBMapSizes(strMapSize, strMaxMapSize,
                             LMDB_DEFAULT_WALLET_MAPSIZE_MIB, fAutoGrow,
                             nMapSize, nMaxMapSize, strMapSizeError))
        return error("InitLMDBWalletDB(): invalid LMDB wallet map size: %s",
                     strMapSizeError.c_str());

    return InitLMDBWalletDBInternal(GetDataDir(), nMapSize, nMaxMapSize,
                                    fAutoGrow,
                                    GetBoolArg("-lmdbnosync", false));
}

bool InitLMDBWalletDBForTest(const std::filesystem::path& dir)
{
    if (g_fLMDBWalletEnabled)
        CloseLMDBWalletDB();
    const size_t nMapSize =
        LMDB_DEFAULT_WALLET_MAPSIZE_MIB * 1024ULL * 1024ULL;
    // Tests use the same automatic growth ceiling as production; cases that
    // need a small, exhausted map open CLMDBEnv directly with an explicit
    // maximum.
    return InitLMDBWalletDBInternal(dir, nMapSize,
                                    GetLMDBDefaultMaxMapSizeMiB() * 1024ULL * 1024ULL,
                                    true, true);
}

void CloseLMDBWalletDB()
{
    if (!g_fLMDBWalletEnabled)
        return;
    g_fLMDBWalletEnabled = false;
    g_lmdbWalletDb.Close();
    g_lmdbWalletEnv.Close();
    g_pathLMDBWalletDir.clear();
}

bool IsLMDBWalletEnabled()
{
    return g_fLMDBWalletEnabled;
}

bool FlushLMDBWallet(bool fForce)
{
    if (!g_fLMDBWalletEnabled)
        return true;
    return g_lmdbWalletEnv.Sync(fForce);
}

std::unique_ptr<CDBTransaction> BeginWalletTransaction(bool fReadOnly)
{
    if (!g_fLMDBWalletEnabled)
        return nullptr;

    // A rewrite fatal path leaves the backend enabled but the environment
    // closed.  Fail immediately instead of retrying a writer slot for a
    // minute: any write must be refused, never redirected to Berkeley DB.
    if (!g_lmdbWalletEnv.GetEnv())
        return nullptr;

    if (fReadOnly)
        return g_lmdbWalletDb.BeginTransaction(true);

    // The environment allows a single writer.  Other writers may be busy for a
    // short time, so wait for the slot rather than failing a wallet write.
    for (int i = 0; i < 60000; ++i) {
        std::unique_ptr<CDBTransaction> txn = g_lmdbWalletDb.BeginTransaction(false);
        if (txn)
            return txn;
        if (fShutdown)
            break;
        Sleep(1);
    }
    return nullptr;
}

bool BackupLMDBWallet(const std::string& strDest)
{
    if (!g_fLMDBWalletEnabled)
        return false;

    std::lock_guard<std::mutex> lock(g_mutexWalletKV);

    while (g_nWalletKVHandles.load() > 0 && !fShutdown)
        Sleep(50);
    if (fShutdown)
        return false;

    MDB_env* env = g_lmdbWalletEnv.GetEnv();
    if (!env)
        return false;
    if (!g_lmdbWalletEnv.Sync(true))
        return false;

    // Capture the committed source entry count before the copy.  No wallet
    // handle is open and g_mutexWalletKV is held, so the source cannot change
    // until the copy and its verification are complete.
    CLMDBDBStats sourceDbStats;
    if (!g_lmdbWalletDb.GetStats(sourceDbStats))
        return error("backupwallet: cannot read the live LMDB wallet state");

    std::filesystem::path pathDest(strDest);
    std::error_code ec;
    if (std::filesystem::is_directory(pathDest, ec))
    {
        // Match backupwallet's existing-directory behaviour: copy into it.
        pathDest /= "wallet";
    }
    else if (std::filesystem::exists(pathDest, ec))
    {
        return error("backupwallet: %s exists and is not a directory",
                     pathDest.string().c_str());
    }

    // An LMDB environment is a directory, so the destination is a directory
    // too.  It may not exist yet, or it must be an empty directory.
    const bool fDestExists = std::filesystem::exists(pathDest, ec);
    if (fDestExists)
    {
        if (!std::filesystem::is_directory(pathDest, ec) ||
            !std::filesystem::is_empty(pathDest, ec))
            return error("backupwallet: %s already exists and is not an empty "
                         "directory", pathDest.string().c_str());
    }

    const std::filesystem::path pathParent = pathDest.parent_path();
    if (!pathParent.empty())
    {
        std::filesystem::create_directories(pathParent, ec);
        if (ec)
            return error("backupwallet: cannot create %s: %s",
                         pathParent.string().c_str(), ec.message().c_str());
    }

    // Build the copy beside the destination and install it with a rename only
    // after it has been verified.  A crash or full disk therefore cannot leave
    // a partial directory that looks like a usable backup.
    static std::atomic<unsigned int> nTempCounter(0);
    const std::string strLeaf = pathDest.filename().string();
    const std::string strTmpName =
        (strLeaf.empty() ? std::string("lmdb-backup") : strLeaf) +
        strprintf(".tmp-%" PRI64d, GetTimeMillis()) + "-" +
        std::to_string(nTempCounter.fetch_add(1));
    const std::filesystem::path pathTmp =
        pathDest.parent_path() / strTmpName;

    std::filesystem::remove_all(pathTmp, ec);
    ec.clear();
    std::filesystem::create_directories(pathTmp, ec);
    if (ec)
        return error("backupwallet: cannot create staging directory %s: %s",
                     pathTmp.string().c_str(), ec.message().c_str());

    int rc = mdb_env_copy2(env, pathTmp.string().c_str(), MDB_CP_COMPACT);
    if (rc != 0)
    {
        std::filesystem::remove_all(pathTmp, ec);
        return error("backupwallet: cannot copy LMDB wallet to %s: %s",
                     pathDest.string().c_str(), mdb_strerror(rc));
    }

    // mdb_env_copy2() documents a point-in-time copy.  Verify the result with
    // a full record scan and compare its entry count with the source before
    // the backup is made visible under its final name.  A compact copy has a
    // new transaction ID by design, so the transaction counter is not a
    // comparable property.
    CLMDBVerifyResult verify;
    if (!VerifyLMDBEnvironment(pathTmp.string(), true, verify))
    {
        std::filesystem::remove_all(pathTmp, ec);
        return error("backupwallet: verification of %s failed: %s",
                     pathDest.string().c_str(), verify.strError.c_str());
    }

    if (!verify.fComplete || !verify.fMainDatabase ||
        !verify.fRecordsReadable ||
        verify.nEntries != sourceDbStats.nEntries)
    {
        std::filesystem::remove_all(pathTmp, ec);
        return error("backupwallet: copy of %s is inconsistent "
                     "(source: %llu entries; backup: %llu entries)",
                     pathDest.string().c_str(),
                     static_cast<unsigned long long>(sourceDbStats.nEntries),
                     static_cast<unsigned long long>(verify.nEntries));
    }

    if (fDestExists)
    {
        // The destination was validated as an empty directory above.  Remove
        // only that empty placeholder so the verified copy can take its name.
        if (!std::filesystem::remove(pathDest, ec) || ec)
        {
            std::filesystem::remove_all(pathTmp, ec);
            return error("backupwallet: cannot replace empty directory %s",
                         pathDest.string().c_str());
        }
    }

    std::filesystem::rename(pathTmp, pathDest, ec);
    if (ec)
    {
        std::filesystem::remove_all(pathTmp, ec);
        return error("backupwallet: cannot install verified backup at %s: %s",
                     pathDest.string().c_str(), ec.message().c_str());
    }

    printf("copied and verified LMDB wallet to %s (%" PRIszu " entries)\n",
           pathDest.string().c_str(), verify.nEntries);
    return true;
}

bool FlushWalletDB(const std::string& /*strFile*/)
{
    return FlushLMDBWallet(true);
}

bool BackupWalletDB(const std::string& /*strFile*/, const std::string& strDest)
{
    return BackupLMDBWallet(strDest);
}

bool CDB::Rewrite(const string& strFile, const char* /*pszSkip*/)
{
    if (strFile == "wallet.dat")
        return RewriteWalletLMDB();

    return error("CDB::Rewrite(): unsupported database file %s",
                 strFile.c_str());
}






//
// CTxDB
//

bool CTxDB::ReadTxIndex(uint256 hash, CTxIndex& txindex)
{
    assert(!fClient);
    txindex.SetNull();
    return Read(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex& txindex)
{
    assert(!fClient);
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int /*nHeight*/)
{
    assert(!fClient);

    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction& tx)
{
    assert(!fClient);
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}

bool CTxDB::ContainsTx(uint256 hash)
{
    assert(!fClient);
    return Exists(make_pair(string("tx"), hash));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
    assert(!fClient);
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex))
        return false;
    return (tx.ReadFromDisk(txindex.pos));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

bool CTxDB::ReadHashBestChain(uint256& hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}

bool CTxDB::ReadBestInvalidWork(CBigNum& bnBestInvalidWork)
{
    return Read(string("bnBestInvalidWork"), bnBestInvalidWork);
}

bool CTxDB::WriteBestInvalidWork(CBigNum bnBestInvalidWork)
{
    return Write(string("bnBestInvalidWork"), bnBestInvalidWork);
}

bool CTxDB::ReadSyncCheckpoint(uint256 &hashCheckpoint) {
    return(Read(string("hashSyncCheckpoint"), hashCheckpoint));
}

bool CTxDB::WriteSyncCheckpoint(uint256 hashCheckpoint) {
    return(Write(string("hashSyncCheckpoint"), hashCheckpoint));
}

bool CTxDB::ReadCheckpointPubKey(string &strPubKey) {
    return(Read(string("strCheckpointPubKey"), strPubKey));
}

bool CTxDB::WriteCheckpointPubKey(const string &strPubKey) {
    return(Write(string("strCheckpointPubKey"), strPubKey));
}

CBlockIndex static * InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
        return nullptr;

    // Return existing
    BlockMap::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool CTxDB::LoadBlockIndex()
{
    if (!LoadBlockIndexGuts())
        return false;

    if (fRequestShutdown)
        return true;

    // Calculate bnChainWork
    vector<pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    for (const PAIRTYPE(const uint256, CBlockIndex*)& item : mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for (const PAIRTYPE(int, CBlockIndex*)& item : vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;
        pindex->bnChainWork = (pindex->pprev ? pindex->pprev->bnChainWork : 0) + pindex->GetBlockWork();
    }

    // Load hashBestChain pointer to end of best chain
    if (!ReadHashBestChain(hashBestChain))
    {
        if (pindexGenesisBlock == nullptr)
            return true;
        return error("CTxDB::LoadBlockIndex() : hashBestChain not loaded");
    }
    if (!mapBlockIndex.count(hashBestChain))
        return error("CTxDB::LoadBlockIndex() : hashBestChain not found in the block index");
    pindexBest = mapBlockIndex[hashBestChain];
    nBestHeight = pindexBest->nHeight;
    bnBestChainWork = pindexBest->bnChainWork;
    printf("LoadBlockIndex(): hashBestChain=%s  height=%d  date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), nBestHeight,
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    /* Load sync checkpoint */
    if(!ReadSyncCheckpoint(Checkpoints::hashSyncCheckpoint)) {
        printf("LoadBlockIndex(): advanced checkpoint cannot be read\n");
    } else {
        printf("LoadBlockIndex(): advanced checkpoint is %s\n",
          Checkpoints::hashSyncCheckpoint.ToString().c_str());
    }

    // Load bnBestInvalidWork, OK if it doesn't exist
    ReadBestInvalidWork(bnBestInvalidWork);

    // Verify blocks in the best chain
    int nCheckLevel = GetArg("-checklevel", 1);
    int nCheckDepth = GetArg( "-checkblocks", 2500);
    if (nCheckDepth == 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > nBestHeight)
        nCheckDepth = nBestHeight;
    printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CBlockIndex* pindexFork = nullptr;
    map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
    for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
    {
        if (fRequestShutdown || pindex->nHeight < nBestHeight-nCheckDepth)
            break;
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("LoadBlockIndex() : block.ReadFromDisk failed");
        // check level 1: verify block validity
        if (nCheckLevel>0 && !block.CheckBlock())
        {
            printf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pindex->pprev;
        }
        // check level 2: verify transaction index validity
        if (nCheckLevel>1)
        {
            pair<unsigned int, unsigned int> pos = make_pair(pindex->nFile, pindex->nBlockPos);
            mapBlockPos[pos] = pindex;
            for (const CTransaction &tx : block.vtx)
            {
                uint256 hashTx = tx.GetHash();
                CTxIndex txindex;
                if (ReadTxIndex(hashTx, txindex))
                {
                    // check level 3: checker transaction hashes
                    if (nCheckLevel>2 || pindex->nFile != txindex.pos.nFile || pindex->nBlockPos != txindex.pos.nBlockPos)
                    {
                        // either an error or a duplicate transaction
                        CTransaction txFound;
                        if (!txFound.ReadFromDisk(txindex.pos))
                        {
                            printf("LoadBlockIndex() : *** cannot read mislocated transaction %s\n", hashTx.ToString().c_str());
                            pindexFork = pindex->pprev;
                        }
                        else
                            if (txFound.GetHash() != hashTx) // not a duplicate tx
                            {
                                printf("LoadBlockIndex(): *** invalid tx position for %s\n", hashTx.ToString().c_str());
                                pindexFork = pindex->pprev;
                            }
                    }
                    // check level 4: check whether spent txouts were spent within the main chain
                    unsigned int nOutput = 0;
                    if (nCheckLevel>3)
                    {
                        for (const CDiskTxPos &txpos : txindex.vSpent)
                        {
                            if (!txpos.IsNull())
                            {
                                pair<unsigned int, unsigned int> posFind = make_pair(txpos.nFile, txpos.nBlockPos);
                                if (!mapBlockPos.count(posFind))
                                {
                                    printf("LoadBlockIndex(): *** found bad spend at %d, hashBlock=%s, hashTx=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str(), hashTx.ToString().c_str());
                                    pindexFork = pindex->pprev;
                                }
                                // check level 6: check whether spent txouts were spent by a valid transaction that consume them
                                if (nCheckLevel>5)
                                {
                                    CTransaction txSpend;
                                    if (!txSpend.ReadFromDisk(txpos))
                                    {
                                        printf("LoadBlockIndex(): *** cannot read spending transaction of %s:%i from disk\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    }
                                    else if (!txSpend.CheckTransaction())
                                    {
                                        printf("LoadBlockIndex(): *** spending transaction of %s:%i is invalid\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    }
                                    else
                                    {
                                        bool fFound = false;
                                        for (const CTxIn &txin : txSpend.vin)
                                            if (txin.prevout.hash == hashTx && txin.prevout.n == nOutput)
                                                fFound = true;
                                        if (!fFound)
                                        {
                                            printf("LoadBlockIndex(): *** spending transaction of %s:%i does not spend it\n", hashTx.ToString().c_str(), nOutput);
                                            pindexFork = pindex->pprev;
                                        }
                                    }
                                }
                            }
                            nOutput++;
                        }
                    }
                }
                // check level 5: check whether all prevouts are marked spent
                if (nCheckLevel>4)
                {
                     for (const CTxIn &txin : tx.vin)
                     {
                          CTxIndex txindex;
                          if (ReadTxIndex(txin.prevout.hash, txindex))
                              if (txin.prevout.n >= txindex.vSpent.size() || txindex.vSpent[txin.prevout.n].IsNull())
                              {
                                  printf("LoadBlockIndex(): *** found unspent prevout %s:%i in %s\n", txin.prevout.hash.ToString().c_str(), txin.prevout.n, hashTx.ToString().c_str());
                                  pindexFork = pindex->pprev;
                              }
                     }
                }
            }
        }
    }
    if (pindexFork && !fRequestShutdown)
    {
        // Reorg back to the fork
        printf("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->nHeight);
        CBlock block;
        if (!block.ReadFromDisk(pindexFork))
            return error("LoadBlockIndex() : block.ReadFromDisk failed");
        CTxDB txdb;
        block.SetBestChain(txdb, pindexFork);
    }

    return true;
}



namespace {

enum BlockIndexLoadResult
{
    BLOCK_INDEX_RECORD,
    BLOCK_INDEX_END,
    BLOCK_INDEX_ERROR,
};

BlockIndexLoadResult LoadBlockIndexRecord(CDataStream& ssKey, CDataStream& ssValue)
{
    try {
        // The key layout for every index record is the varint length of the
        // string prefix followed by the type string itself and then the 32-byte
        // block hash, i.e. make_pair(string, uint256).  We compare the prefix
        // bytes directly instead of constructing a std::string each record,
        // and we reuse the hash already present in the key rather than
        // recomputing the SHA256d header hash via CDiskBlockIndex::GetBlockHash().
        uint64 nSize = ReadCompactSize(ssKey);
        if (nSize != 10 || ssKey.size() < 10 + 32)
            return BLOCK_INDEX_END; // finished loading block index
        if (memcmp(&ssKey[0], "blockindex", 10) != 0)
            return BLOCK_INDEX_END;
        ssKey.ignore(10);
        uint256 hashBlock;
        ssKey >> hashBlock;

        if (fRequestShutdown)
            return BLOCK_INDEX_END; // if shutdown was requested while loading

        CDiskBlockIndex diskindex;
        ssValue >> diskindex;

        // Construct block index object
        CBlockIndex* pindexNew = InsertBlockIndex(hashBlock);
        pindexNew->pprev          = InsertBlockIndex(diskindex.hashPrev);
        pindexNew->pnext          = InsertBlockIndex(diskindex.hashNext);
        pindexNew->nFile          = diskindex.nFile;
        pindexNew->nBlockPos      = diskindex.nBlockPos;
        pindexNew->nHeight        = diskindex.nHeight;
        pindexNew->nVersion       = diskindex.nVersion;
        pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
        pindexNew->nTime          = diskindex.nTime;
        pindexNew->nBits          = diskindex.nBits;
        pindexNew->nNonce         = diskindex.nNonce;

        // Watch for genesis block
        if (pindexGenesisBlock == nullptr && hashBlock == hashGenesisBlock)
            pindexGenesisBlock = pindexNew;

        return BLOCK_INDEX_RECORD;
    }
    catch (std::exception&) {
        return BLOCK_INDEX_ERROR;
    }
}

} // namespace

bool CTxDB::LoadBlockIndexGuts()
{
    std::unique_ptr<CDBTransaction> txn = g_lmdbChainDb.BeginTransaction(true);
    if (!txn)
        return false;

    CDataStream ssPrefix(SER_DISK, CLIENT_VERSION);
    ssPrefix << string("blockindex");
    const CDBKey prefix(ssPrefix.begin(), ssPrefix.end());

    std::unique_ptr<CDBIterator> it = txn->NewIterator(prefix);
    if (!it)
    {
        txn->Abort();
        return false;
    }

    for (it->SeekToFirst(); it->Valid(); it->Next())
    {
        const CDBKey key = it->Key();
        const CDBValue value = it->Value();
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (!key.empty())
            ssKey.write((const char*)key.data(), key.size());
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        if (!value.empty())
            ssValue.write((const char*)value.data(), value.size());

        BlockIndexLoadResult result = LoadBlockIndexRecord(ssKey, ssValue);
        if (result == BLOCK_INDEX_END)
            break;
        if (result == BLOCK_INDEX_ERROR)
        {
            it.reset();
            txn->Abort();
            return error("%s() : deserialize error", __PRETTY_FUNCTION__);
        }
    }
    it.reset();

    return txn->Commit();
}





//
// CAddrDB
//


CAddrDB::CAddrDB()
{
    pathAddr = GetDataDir() / "peers.dat";
}

bool CAddrDB::Write(const CAddrMan& addr)
{
    // Generate random temporary filename
    unsigned short randv = 0;
    RAND_bytes((unsigned char *)&randv, sizeof(randv));
    std::string tmpfn = strprintf("peers.dat.%04x", randv);

    // serialize addresses, checksum data up to that point, then append csum
    CDataStream ssPeers(SER_DISK, CLIENT_VERSION);
    ssPeers << FLATDATA(pchMessageStart);
    ssPeers << addr;
    uint256 hash = Hash(ssPeers.begin(), ssPeers.end());
    ssPeers << hash;

    // open temp output file, and associate with CAutoFile
    std::filesystem::path pathTmp = GetDataDir() / tmpfn;
    FILE *file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout = CAutoFile(file, SER_DISK, CLIENT_VERSION);
    if(!fileout)
      return(error("CAddrDB::Write() : fopen(%s) failed", pathTmp.string().c_str()));

    // Write and commit header, data
    try {
        fileout << ssPeers;
    }
    catch (std::exception &e) {
        return(error("CAddrDB::Write() : I/O error"));
    }
    fflush(fileout);
    if(FileCommit(fileout))
      return(error("CAddrDB::Write() : FileCommit() failed"));
    fileout.fclose();

    // replace existing peers.dat, if any, with new peers.dat.XXXX
    if(!RenameOver(pathTmp, pathAddr))
      return(error("CAddrDB::Write() : RenameOver() failed"));

    return(true);
}

bool CAddrDB::Read(CAddrMan& addr)
{
    // open input file, and associate with CAutoFile
    FILE *file = fopen(pathAddr.string().c_str(), "rb");
    CAutoFile filein = CAutoFile(file, SER_DISK, CLIENT_VERSION);
    if (!filein)
        return error("CAddrman::Read() : open failed");

    // use file size to size memory buffer
    int fileSize = GetFilesize(filein);
    int dataSize = fileSize - sizeof(uint256);
    vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (std::exception &e) {
        return error("CAddrman::Read() 2 : I/O error or stream data corrupted");
    }
    filein.fclose();

    CDataStream ssPeers(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssPeers.begin(), ssPeers.end());
    if (hashIn != hashTmp)
        return error("CAddrman::Read() : checksum mismatch; data corrupted");

    unsigned char pchMsgTmp[4];
    try {
        // de-serialize file header (pchMessageStart magic number) and
        ssPeers >> FLATDATA(pchMsgTmp);

        // verify the network matches ours
        if (memcmp(pchMsgTmp, pchMessageStart, sizeof(pchMsgTmp)))
            return error("CAddrman::Read() : invalid network magic number");

        // de-serialize address data into one CAddrMan object
        ssPeers >> addr;
    }
    catch (std::exception &e) {
        return error("CAddrman::Read() : I/O error or stream data corrupted");
    }

    return true;
}

namespace {

DBBackendDiagnostics CollectDBBackendDiagnostics(
    const std::string& strRole, bool fLMDBEnabled,
    const std::filesystem::path& dir, CLMDBEnv& env, CLMDBDatabase& db,
    bool fWallet)
{
    DBBackendDiagnostics diag;
    diag.strRole = strRole;
    diag.strConfiguredBackend = "lmdb";
    diag.strActiveBackend = fLMDBEnabled ? "lmdb" : "none";
    diag.fLMDBEnabled = fLMDBEnabled;
    diag.strPath = (dir / (fWallet ? "wallet" : "blkindex")).string();
    diag.disk = InspectLMDBEnvironmentOnDisk(
        dir / (fWallet ? "wallet" : "blkindex"));

    std::string strMarker;
    diag.fMarkerPresent = fWallet
        ? ReadWalletBackendMarker(dir, strMarker)
        : ReadChainBackendMarker(dir, strMarker);
    diag.strMarker = strMarker;
    // Current builds do not create a marker.  Absence is therefore normal; a
    // marker left by a migration-window build must still say LMDB.
    diag.fMarkerMatchesBackend =
        fLMDBEnabled && (!diag.fMarkerPresent || strMarker == "lmdb");

    diag.fEnvironmentOpen = env.GetStats(diag.env);
    diag.fDatabaseOpen = db.GetStats(diag.db);
    diag.fOpenedCleanly = diag.fEnvironmentOpen && diag.fDatabaseOpen &&
                          diag.disk.fComplete;

    if (!diag.fEnvironmentOpen)
        diag.strError = "LMDB environment is not open";
    else if (!diag.fDatabaseOpen)
        diag.strError = "LMDB database statistics are unavailable";
    else if (!diag.disk.fComplete)
        diag.strError = std::string("LMDB data file is incomplete: ") +
                        diag.disk.strReason;
    else if (diag.fMarkerPresent && !diag.fMarkerMatchesBackend)
        diag.strError = "legacy backend marker does not match the active backend";
    return diag;
}

} // namespace

DBDiagnostics GetDBDiagnostics(const std::filesystem::path& chainDir,
                               const std::filesystem::path& walletDir)
{
    DBDiagnostics diag;
    diag.chain = CollectDBBackendDiagnostics(
        "chain", g_fLMDBChainEnabled, chainDir,
        g_lmdbChainEnv, g_lmdbChainDb, false);
    diag.wallet = CollectDBBackendDiagnostics(
        "wallet", g_fLMDBWalletEnabled, walletDir,
        g_lmdbWalletEnv, g_lmdbWalletDb, true);
    return diag;
}

DBDiagnostics GetDBDiagnostics()
{
    const std::filesystem::path walletDir = g_pathLMDBWalletDir.empty()
        ? GetDataDir() : g_pathLMDBWalletDir;
    return GetDBDiagnostics(GetDataDir(), walletDir);
}

