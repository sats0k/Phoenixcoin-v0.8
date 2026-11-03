// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "lmdbdb.h"
#include "allocators.h"
#include "datatypes.h"
#include "util.h"

#include <cstdio>
#include <filesystem>

namespace {
#if defined(__LP64__) || defined(_WIN64)
constexpr size_t LMDB_DEFAULT_MAPSIZE = 4096ULL * 1024ULL * 1024ULL; // 4GB
// A 1 TiB ceiling leaves room for decades of chain growth while still
// bounding a bug or a runaway import.  The map is virtual address space, not
// a preallocation.
constexpr size_t LMDB_DEFAULT_MAX_MAPSIZE = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
#else
constexpr size_t LMDB_DEFAULT_MAPSIZE = 1024ULL * 1024ULL * 1024ULL; // 1GB
constexpr size_t LMDB_DEFAULT_MAX_MAPSIZE = 2048ULL * 1024ULL * 1024ULL; // 2GB
#endif
constexpr unsigned int LMDB_MAX_DBS = 64;

size_t AlignDown(size_t nValue, size_t nAlignment)
{
    return nAlignment > 0 ? (nValue / nAlignment) * nAlignment : nValue;
}

} // namespace

CLMDBEnv::CLMDBEnv()
    : env(nullptr), strMapSizeFlag("-lmdbmapsize"), fWriterActive(false),
      fNoSync(false), fReadOnly(false), fAutoGrow(true), nMaxMapSize(0),
      nActiveTxns(0), fResizePending(false)
{
}

CLMDBEnv::~CLMDBEnv()
{
    Close();
}

bool CLMDBEnv::Open(const std::string &path, bool fCreate, size_t nMapSize,
                    bool fNoSync, const std::string &strMapSizeFlag,
                    bool fReadOnly, size_t nMaxMapSize, bool fAutoGrow)
{
    std::lock_guard<std::mutex> lock(mutexEnv);
    if (env)
        return strPath == path;

    if (nMapSize == 0)
        nMapSize = LMDB_DEFAULT_MAPSIZE;

    std::error_code ec;
    const bool fPathExists = std::filesystem::exists(path, ec);
    if (!fPathExists) {
        if (!fCreate || fReadOnly)
            return false;
        if (!std::filesystem::create_directories(path, ec))
            return false;
    } else {
        // Never reopen an existing database with a map smaller than the data
        // file.  This happens when a datadir was created with a larger
        // -lmdbmapsize and is later started without that option.
        const std::filesystem::path pathData = std::filesystem::path(path) / "data.mdb";
        const uintmax_t nDataSize = std::filesystem::file_size(pathData, ec);
        if (!ec && nDataSize > 0) {
            const size_t nMinMapSize = static_cast<size_t>(nDataSize) + 16ULL * 1024ULL * 1024ULL;
            if (nMapSize < nMinMapSize) {
                const size_t nOldMapSize = nMapSize;
                nMapSize = nMinMapSize;
                printf("LMDB map size increased from %" PRIszu " to %" PRIszu
                       " bytes to fit the existing database\n",
                       nOldMapSize, nMapSize);
            }
        }
        ec.clear();
    }

    if (fReadOnly)
        fAutoGrow = false;
    if (!fAutoGrow)
        nMaxMapSize = nMapSize;
    else if (nMaxMapSize == 0)
        nMaxMapSize = LMDB_DEFAULT_MAX_MAPSIZE;
    if (nMaxMapSize < nMapSize)
        nMaxMapSize = nMapSize;
    this->nMaxMapSize = nMaxMapSize;
    this->fAutoGrow = fAutoGrow;

    int rc = mdb_env_create(&env);
    if (rc != 0) {
        printf("mdb_env_create failed: %s\n", mdb_strerror(rc));
        env = nullptr;
        return false;
    }

    rc = mdb_env_set_maxdbs(env, LMDB_MAX_DBS);
    if (rc != 0) {
        printf("mdb_env_set_maxdbs failed: %s\n", mdb_strerror(rc));
        mdb_env_close(env);
        env = nullptr;
        return false;
    }

    rc = mdb_env_set_mapsize(env, nMapSize);
    if (rc != 0) {
        printf("mdb_env_set_mapsize failed: %s\n", mdb_strerror(rc));
        mdb_env_close(env);
        env = nullptr;
        return false;
    }

    // MDB_NOTLS detaches read transactions from a thread-local reader slot.
    // The key/value abstraction hands transactions out as moveable objects, so
    // a transaction may be committed or destroyed on a different thread than
    // the one that created it.  With MDB_NOTLS the slot is tied to the
    // transaction instead of the thread; the transaction still must not be
    // used concurrently from several threads.
    //
    // MDB_NOSYNC is opt-in: it matches Berkeley DB's DB_TXN_WRITE_NOSYNC
    // behaviour, keeping commits atomic and consistent while skipping the
    // per-commit fsync.  The default remains LMDB's strongest normal
    // durability mode.
    //
    // MDB_WRITEMAP, MDB_MAPASYNC and MDB_NOMETASYNC are deliberately never
    // enabled.  WRITEMAP removes protection against application memory bugs,
    // and mixing processes with different WRITEMAP settings can defeat
    // durability.
    unsigned int nFlags = MDB_NOTLS;
    if (fNoSync)
        nFlags |= MDB_NOSYNC;
    if (fReadOnly)
        nFlags |= MDB_RDONLY;

    rc = mdb_env_open(env, path.c_str(), nFlags, 0644);
    if (rc != 0) {
        printf("mdb_env_open failed: %s\n", mdb_strerror(rc));
        mdb_env_close(env);
        env = nullptr;
        return false;
    }

    // The requested maximum is a byte count from configuration.  LMDB maps
    // whole pages, so round the ceiling down and keep it at least as large as
    // the initial map.
    MDB_stat stat;
    if (fAutoGrow && mdb_env_stat(env, &stat) == 0) {
        nMaxMapSize = AlignDown(nMaxMapSize, static_cast<size_t>(stat.ms_psize));
        if (nMaxMapSize < nMapSize)
            nMaxMapSize = nMapSize;
        this->nMaxMapSize = nMaxMapSize;
    }

    strPath = path;
    this->fNoSync = fNoSync;
    this->fReadOnly = fReadOnly;
    this->strMapSizeFlag = strMapSizeFlag;
    return true;
}

bool CLMDBEnv::GetStats(CLMDBStats &stats) const
{
    std::lock_guard<std::mutex> lock(mutexEnv);
    stats = CLMDBStats();
    if (!env)
        return false;

    MDB_envinfo info;
    MDB_stat stat;
    if (mdb_env_info(env, &info) != 0 || mdb_env_stat(env, &stat) != 0)
        return false;

    stats.fOpen = true;
    stats.fReadOnly = fReadOnly;
    stats.fNoSync = fNoSync;
    stats.fWriterActive = fWriterActive.load();
    stats.fAutoGrow = fAutoGrow;
    stats.nMapSize = static_cast<size_t>(info.me_mapsize);
    stats.nMaxMapSize = nMaxMapSize;
    stats.nPageSize = static_cast<size_t>(stat.ms_psize);
    stats.nLastPgno = static_cast<size_t>(info.me_last_pgno);
    stats.nLastTxnId = static_cast<size_t>(info.me_last_txnid);
    stats.nUsedBytes = (stats.nLastPgno + 1) * stats.nPageSize;
    stats.nFreeBytes = stats.nMapSize > stats.nUsedBytes
        ? stats.nMapSize - stats.nUsedBytes : 0;
    stats.nUtilization = stats.nMapSize
        ? 100.0 * static_cast<double>(stats.nUsedBytes) /
          static_cast<double>(stats.nMapSize)
        : 0.0;
    stats.nMaxReaders = info.me_maxreaders;
    stats.nReaders = info.me_numreaders;
    return true;
}

bool CLMDBEnv::GetDbStats(MDB_dbi dbi, CLMDBDBStats &stats) const
{
    std::lock_guard<std::mutex> lock(mutexEnv);
    stats = CLMDBDBStats();
    if (!env)
        return false;

    MDB_txn *txn = nullptr;
    if (mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn) != 0)
        return false;

    MDB_stat stat;
    const int rc = mdb_stat(txn, dbi, &stat);
    mdb_txn_abort(txn);
    if (rc != 0)
        return false;

    stats.fOpen = true;
    stats.nEntries = static_cast<size_t>(stat.ms_entries);
    stats.nDepth = static_cast<size_t>(stat.ms_depth);
    stats.nBranchPages = static_cast<size_t>(stat.ms_branch_pages);
    stats.nLeafPages = static_cast<size_t>(stat.ms_leaf_pages);
    stats.nOverflowPages = static_cast<size_t>(stat.ms_overflow_pages);
    stats.nPageSize = static_cast<size_t>(stat.ms_psize);
    return true;
}

bool VerifyLMDBEnvironment(const std::string &path, bool fFullScan,
                           CLMDBVerifyResult &result)
{
    result = CLMDBVerifyResult();
    result.strPath = path;
    result.fFullScan = fFullScan;

    std::error_code ec;
    result.fDirectoryExists = std::filesystem::is_directory(path, ec) && !ec;
    if (!result.fDirectoryExists) {
        result.strError = (std::filesystem::exists(path, ec) && !ec)
            ? "path exists but is not a directory"
            : "directory does not exist";
        return false;
    }

    const std::filesystem::path pathData =
        std::filesystem::path(path) / "data.mdb";
    const std::filesystem::path pathLock =
        std::filesystem::path(path) / "lock.mdb";
    result.fDataFileExists = std::filesystem::is_regular_file(pathData, ec) && !ec;
    if (!result.fDataFileExists) {
        result.strError = "data.mdb is missing";
        return false;
    }
    result.fLockFileExists = std::filesystem::is_regular_file(pathLock, ec) && !ec;

    const uintmax_t nBytes = std::filesystem::file_size(pathData, ec);
    if (ec) {
        result.strError = "cannot read the size of data.mdb";
        return false;
    }
    result.nDataFileBytes = static_cast<size_t>(nBytes);

    // Both LMDB meta pages must exist before mdb_env_open() maps the file.
    // mmap() succeeds beyond EOF, but touching a missing meta page raises
    // SIGBUS instead of returning a clean LMDB error.  LMDB page sizes are at
    // least the system page size, so two system pages are the safe minimum.
    const size_t nSystemPage = GetSystemPageSize();
    const uintmax_t nMinimumMetaBytes =
        2ULL * (nSystemPage > 0 ? nSystemPage : 4096ULL);
    if (nBytes < nMinimumMetaBytes) {
        result.strError = "data.mdb is too small to contain two LMDB meta "
                          "pages (truncated or incomplete copy)";
        return false;
    }
    result.fDataFileSizeSane = true;

    MDB_env *env = nullptr;
    int rc = mdb_env_create(&env);
    if (rc != 0) {
        result.strError = std::string("mdb_env_create failed: ") +
                          mdb_strerror(rc);
        return false;
    }
    mdb_env_set_maxdbs(env, LMDB_MAX_DBS);

    // NOLOCK makes this a true offline check: a backup without lock.mdb can
    // be verified without creating one, and a read-only directory works too.
    rc = mdb_env_open(env, path.c_str(),
                      MDB_RDONLY | MDB_NOLOCK | MDB_NOTLS, 0);
    if (rc != 0) {
        result.strError = std::string("cannot open data.mdb: ") +
                          mdb_strerror(rc);
        mdb_env_close(env);
        return false;
    }
    result.fOpened = true;

    MDB_envinfo info;
    MDB_stat envStat;
    if (mdb_env_info(env, &info) != 0 || mdb_env_stat(env, &envStat) != 0) {
        result.strError = "LMDB cannot report environment statistics";
        mdb_env_close(env);
        return false;
    }
    result.nPageSize = static_cast<size_t>(envStat.ms_psize);
    result.nMapSize = static_cast<size_t>(info.me_mapsize);
    result.nLastPgno = static_cast<size_t>(info.me_last_pgno);
    result.nLastTxnId = static_cast<size_t>(info.me_last_txnid);
    result.nRequiredBytes = result.nPageSize > 0
        ? (result.nLastPgno + 1) * result.nPageSize : 0;
    if (nBytes < result.nRequiredBytes) {
        result.strError = strprintf(
            "data.mdb is truncated: %llu bytes on disk but the meta page "
            "refers to %llu bytes",
            static_cast<unsigned long long>(nBytes),
            static_cast<unsigned long long>(result.nRequiredBytes));
        mdb_env_close(env);
        return false;
    }

    MDB_txn *txn = nullptr;
    rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
    if (rc != 0) {
        result.strError = std::string("cannot begin a read transaction: ") +
                          mdb_strerror(rc);
        mdb_env_close(env);
        return false;
    }

    MDB_dbi dbi = 0;
    rc = mdb_dbi_open(txn, "main", 0, &dbi);
    if (rc != 0) {
        result.strError = std::string("main sub-database is missing or "
                                      "unreadable: ") + mdb_strerror(rc);
        mdb_txn_abort(txn);
        mdb_env_close(env);
        return false;
    }
    result.fMainDatabase = true;

    MDB_stat dbStat;
    rc = mdb_stat(txn, dbi, &dbStat);
    if (rc != 0) {
        result.strError = std::string("cannot read main database statistics: ") +
                          mdb_strerror(rc);
        mdb_txn_abort(txn);
        mdb_env_close(env);
        return false;
    }
    result.nEntries = static_cast<size_t>(dbStat.ms_entries);

    if (fFullScan) {
        MDB_cursor *cursor = nullptr;
        rc = mdb_cursor_open(txn, dbi, &cursor);
        if (rc != 0) {
            result.strError = std::string("cannot open a scan cursor: ") +
                              mdb_strerror(rc);
            mdb_txn_abort(txn);
            mdb_env_close(env);
            return false;
        }

        MDB_val key;
        MDB_val value;
        size_t nRecords = 0;
        for (rc = mdb_cursor_get(cursor, &key, &value, MDB_FIRST);
             rc == 0;
             rc = mdb_cursor_get(cursor, &key, &value, MDB_NEXT))
            ++nRecords;
        mdb_cursor_close(cursor);

        if (rc != MDB_NOTFOUND) {
            result.strError = std::string("cannot read every record: ") +
                              mdb_strerror(rc);
            mdb_txn_abort(txn);
            mdb_env_close(env);
            return false;
        }
        if (nRecords != result.nEntries) {
            result.strError = strprintf(
                "full scan read %llu records but the main database reports "
                "%llu entries",
                static_cast<unsigned long long>(nRecords),
                static_cast<unsigned long long>(result.nEntries));
            mdb_txn_abort(txn);
            mdb_env_close(env);
            return false;
        }
    }

    result.fRecordsReadable = true;
    mdb_txn_abort(txn);
    mdb_env_close(env);
    result.fComplete = true;
    return true;
}

void CLMDBEnv::AcquireTransactionLease()
{
    std::unique_lock<std::mutex> lock(mutexTxns);
    cvTxns.wait(lock, [this] { return !fResizePending; });
    ++nActiveTxns;
}

void CLMDBEnv::ReleaseTransactionLease()
{
    std::lock_guard<std::mutex> lock(mutexTxns);
    if (nActiveTxns > 0)
        --nActiveTxns;
    cvTxns.notify_all();
}

bool CLMDBEnv::GrowMap(std::string &strError)
{
    std::unique_lock<std::mutex> txnsLock(mutexTxns);

    if (!env) {
        strError = "LMDB environment is not open";
        return false;
    }
    if (fReadOnly) {
        strError = "LMDB environment is read-only";
        return false;
    }
    if (!fAutoGrow) {
        strError = "automatic LMDB map growth is disabled";
        return false;
    }

    // mdb_env_set_mapsize() requires that no transaction is active in this
    // process.  New transactions block on fResizePending while we drain the
    // existing ones.
    fResizePending = true;
    cvTxns.wait(txnsLock, [this] { return nActiveTxns == 0; });

    bool fGrown = false;
    do {
        std::lock_guard<std::mutex> envLock(mutexEnv);
        if (!env) {
            strError = "LMDB environment was closed during resize";
            break;
        }

        MDB_envinfo info;
        MDB_stat stat;
        if (mdb_env_info(env, &info) != 0 || mdb_env_stat(env, &stat) != 0) {
            strError = "LMDB could not report the environment size";
            break;
        }

        const size_t nPageSize = static_cast<size_t>(stat.ms_psize);
        const size_t nCurrent = static_cast<size_t>(info.me_mapsize);
        if (nPageSize == 0) {
            strError = "LMDB reported an invalid page size";
            break;
        }

        size_t nMax = AlignDown(nMaxMapSize, nPageSize);
        if (nMax < nCurrent)
            nMax = nCurrent;
        if (nMax <= nCurrent) {
            strError = strprintf(
                "LMDB map is already at its maximum size (%" PRIszu " bytes)",
                nCurrent);
            break;
        }

        // Double the map on each full event.  A transaction that grows past
        // one doubling simply retries and grows again.  Clamp before
        // multiplying so the arithmetic cannot overflow.
        size_t nTarget = nCurrent > nMax / 2 ? nMax : nCurrent * 2;
        nTarget = AlignDown(nTarget, nPageSize);
        if (nTarget <= nCurrent) {
            if (nCurrent > nMax - nPageSize) {
                nTarget = nMax;
            } else {
                nTarget = nCurrent + nPageSize;
            }
        }

        const int rc = mdb_env_set_mapsize(env, nTarget);
        if (rc != 0) {
            strError = strprintf("mdb_env_set_mapsize(%" PRIszu ") failed: %s",
                                 nTarget, mdb_strerror(rc));
            break;
        }

        printf("LMDB map size increased from %" PRIszu " to %" PRIszu
               " bytes to recover from a full map (%s, maximum %" PRIszu
               " bytes)\n",
               nCurrent, nTarget, strMapSizeFlag.c_str(), nMax);
        fGrown = true;
    } while (false);

    fResizePending = false;
    cvTxns.notify_all();
    return fGrown;
}

bool CLMDBEnv::Sync(bool fForce)
{
    std::lock_guard<std::mutex> lock(mutexEnv);
    if (!env)
        return false;

    int rc = mdb_env_sync(env, fForce ? 1 : 0);
    if (rc != 0) {
        printf("mdb_env_sync failed: %s\n", mdb_strerror(rc));
        return false;
    }
    return true;
}

void CLMDBEnv::Close()
{
    std::lock_guard<std::mutex> lock(mutexEnv);

    // Flush the memory map before tearing it down.  This is required for
    // MDB_NOSYNC environments and harmless for synchronous ones.
    if (env && fNoSync) {
        int rc = mdb_env_sync(env, 1);
        if (rc != 0)
            printf("mdb_env_sync failed: %s\n", mdb_strerror(rc));
    }

    // DBI handles are invalidated when the environment is closed.
    mapDbis.clear();
    fWriterActive.store(false);

    if (env) {
        mdb_env_close(env);
        env = nullptr;
    }
    strPath.clear();
    fNoSync = false;
    fReadOnly = false;
    fAutoGrow = true;
    nMaxMapSize = 0;
}

bool CLMDBEnv::OpenDbi(const std::string &name, MDB_dbi &dbi, bool fCreate)
{
    std::lock_guard<std::mutex> lock(mutexEnv);

    if (!env)
        return false;

    std::map<std::string, MDB_dbi>::const_iterator it = mapDbis.find(name);
    if (it != mapDbis.end()) {
        dbi = it->second;
        return true;
    }

    MDB_txn *txn = nullptr;
    const unsigned int nTxnFlags = fReadOnly ? MDB_RDONLY : 0;
    int rc = mdb_txn_begin(env, nullptr, nTxnFlags, &txn);
    if (rc != 0) {
        printf("mdb_txn_begin failed: %s\n", mdb_strerror(rc));
        return false;
    }

    unsigned int flags = (fCreate && !fReadOnly) ? MDB_CREATE : 0;
    rc = mdb_dbi_open(txn, name.c_str(), flags, &dbi);
    if (rc != 0) {
        printf("mdb_dbi_open(%s) failed: %s\n", name.c_str(), mdb_strerror(rc));
        mdb_txn_abort(txn);
        return false;
    }

    // Commit even for a read-only transaction: aborting would discard the DBI
    // handle instead of publishing it to the environment.
    rc = mdb_txn_commit(txn);
    if (rc != 0) {
        printf("mdb_txn_commit failed: %s\n", mdb_strerror(rc));
        return false;
    }

    mapDbis[name] = dbi;
    return true;
}

bool CLMDBEnv::TryAcquireWriter()
{
    bool expected = false;
    return fWriterActive.compare_exchange_strong(expected, true);
}

void CLMDBEnv::ReleaseWriter()
{
    fWriterActive.store(false);
}
