// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef LMDBDB_H
#define LMDBDB_H

#include <atomic>
#include <cstddef>
#include <map>
#include <mutex>
#include <string>

#include <lmdb.h>

/**
 * Point-in-time environment statistics for diagnostics.
 *
 * All byte counts are derived from the map size and the last used page, so
 * nUsedBytes covers the copy-on-write data file rather than the logical size
 * of the live tree.  nFreeBytes is the remaining address space before LMDB
 * returns MDB_MAP_FULL.
 */
struct CLMDBStats
{
    bool fOpen = false;
    bool fReadOnly = false;
    bool fNoSync = false;
    bool fWriterActive = false;
    size_t nMapSize = 0;
    size_t nPageSize = 0;
    size_t nLastPgno = 0;
    size_t nLastTxnId = 0;
    size_t nUsedBytes = 0;
    size_t nFreeBytes = 0;
    double nUtilization = 0.0; // percentage of the map in use
    unsigned int nMaxReaders = 0;
    unsigned int nReaders = 0;
};

/** Point-in-time statistics for one named sub-database. */
struct CLMDBDBStats
{
    bool fOpen = false;
    size_t nEntries = 0;
    size_t nDepth = 0;
    size_t nBranchPages = 0;
    size_t nLeafPages = 0;
    size_t nOverflowPages = 0;
    size_t nPageSize = 0;
};

/**
 * Thin RAII wrapper around an LMDB environment.
 *
 * A CLMDBEnv owns one MDB_env and caches the named sub-databases opened in it.
 * The CDB-style key/value adapters use this class instead of managing MDB_env
 * themselves, so there is only one place that knows about environment setup
 * and shutdown.
 */
class CLMDBEnv
{
public:
    CLMDBEnv();
    ~CLMDBEnv();

    CLMDBEnv(const CLMDBEnv&) = delete;
    CLMDBEnv& operator=(const CLMDBEnv&) = delete;

    /**
     * Opens (and creates when needed) the environment.  With fNoSync the
     * environment is opened with MDB_NOSYNC, so commits do not fsync and a
     * system crash may lose the most recent transactions.  The database stays
     * consistent (MDB_WRITEMAP is not used) and the data is flushed when the
     * environment is closed.
     */
    bool Open(const std::string &path, bool fCreate = true, size_t nMapSize = 0,
              bool fNoSync = false,
              const std::string &strMapSizeFlag = "-lmdbmapsize",
              bool fReadOnly = false);
    void Close();

    /** Flushes the memory map to disk.  Returns false when there is no open environment. */
    bool Sync(bool fForce = true);

    /**
     * Fills stats with the current environment and global database counters.
     * Returns false when the environment is closed or LMDB cannot report the
     * counters.  Safe to call while another thread reads or writes.
     */
    bool GetStats(CLMDBStats &stats) const;

    /**
     * Fills stats with mdb_stat() counters for one database handle.  Returns
     * false when the environment is closed or a read transaction cannot be
     * created.  Safe to call while another thread reads or writes.
     */
    bool GetDbStats(MDB_dbi dbi, CLMDBDBStats &stats) const;

    bool IsOpen() const { return env != nullptr; }
    MDB_env *GetEnv() const { return env; }
    const std::string &GetPath() const { return strPath; }
    bool IsNoSync() const { return fNoSync; }
    bool IsReadOnly() const { return fReadOnly; }
    /** Option that controls this environment's map size, for error messages. */
    const std::string &GetMapSizeFlag() const { return strMapSizeFlag; }

    /**
     * Open (and cache) a named sub-database.  When fCreate is false the
     * sub-database must already exist.
     */
    bool OpenDbi(const std::string &name, MDB_dbi &dbi, bool fCreate = true);

    /**
     * LMDB allows exactly one write transaction per environment.  The
     * environment therefore owns a non-recursive writer lock that a write
     * transaction holds from mdb_txn_begin() until commit/abort.
     *
     * TryAcquireWriter() never blocks: it returns false when another write
     * transaction is already active (including a re-entrant write transaction
     * in the same thread).  Callers must retry rather than assume progress.
     *
     * Note that this lock only serializes writers.  LMDB write transactions
     * and cursors remain thread-affine even with MDB_NOTLS and must be
     * committed or aborted on the thread that created them.
     */
    bool TryAcquireWriter();
    void ReleaseWriter();

private:
    MDB_env *env;
    std::string strPath;
    std::string strMapSizeFlag;
    std::map<std::string, MDB_dbi> mapDbis;
    std::atomic<bool> fWriterActive;
    bool fNoSync;
    bool fReadOnly;
    mutable std::mutex mutexEnv;
};

#endif // LMDBDB_H
