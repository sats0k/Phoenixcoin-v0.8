// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "lmdbdb.h"
#include "datatypes.h"

#include <cstdio>
#include <filesystem>

namespace {
#if defined(__LP64__) || defined(_WIN64)
constexpr size_t LMDB_DEFAULT_MAPSIZE = 4096ULL * 1024ULL * 1024ULL; // 4GB
#else
constexpr size_t LMDB_DEFAULT_MAPSIZE = 1024ULL * 1024ULL * 1024ULL; // 1GB
#endif
constexpr unsigned int LMDB_MAX_DBS = 64;
}

CLMDBEnv::CLMDBEnv() : env(nullptr), fWriterActive(false), fNoSync(false)
{
}

CLMDBEnv::~CLMDBEnv()
{
    Close();
}

bool CLMDBEnv::Open(const std::string &path, bool fCreate, size_t nMapSize, bool fNoSync)
{
    std::lock_guard<std::mutex> lock(mutexEnv);
    if (env)
        return strPath == path;

    if (nMapSize == 0)
        nMapSize = LMDB_DEFAULT_MAPSIZE;

    std::error_code ec;
    const bool fPathExists = std::filesystem::exists(path, ec);
    if (!fPathExists) {
        if (!fCreate)
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
    // MDB_NOSYNC matches Berkeley DB's DB_TXN_WRITE_NOSYNC behaviour: commits
    // stay atomic and consistent, but do not force the OS buffers to disk.
    // This avoids an fsync for every block during initial sync.  The data is
    // flushed explicitly when the environment is closed.
    unsigned int nFlags = MDB_NOTLS;
    if (fNoSync)
        nFlags |= MDB_NOSYNC;

    rc = mdb_env_open(env, path.c_str(), nFlags, 0644);
    if (rc != 0) {
        printf("mdb_env_open failed: %s\n", mdb_strerror(rc));
        mdb_env_close(env);
        env = nullptr;
        return false;
    }

    strPath = path;
    this->fNoSync = fNoSync;
    return true;
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
    int rc = mdb_txn_begin(env, nullptr, 0, &txn);
    if (rc != 0) {
        printf("mdb_txn_begin failed: %s\n", mdb_strerror(rc));
        return false;
    }

    unsigned int flags = fCreate ? MDB_CREATE : 0;
    rc = mdb_dbi_open(txn, name.c_str(), flags, &dbi);
    if (rc != 0) {
        printf("mdb_dbi_open(%s) failed: %s\n", name.c_str(), mdb_strerror(rc));
        mdb_txn_abort(txn);
        return false;
    }

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
