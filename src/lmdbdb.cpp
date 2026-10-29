// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "lmdbdb.h"

#include <cstdio>
#include <filesystem>

namespace {
constexpr size_t LMDB_DEFAULT_MAPSIZE = 1024ULL * 1024ULL * 1024ULL; // 1GB
constexpr unsigned int LMDB_MAX_DBS = 64;
}

CLMDBEnv::CLMDBEnv() : env(nullptr), fWriterActive(false)
{
}

CLMDBEnv::~CLMDBEnv()
{
    Close();
}

bool CLMDBEnv::Open(const std::string &path, bool fCreate)
{
    if (env)
        return strPath == path;

    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        if (!fCreate)
            return false;
        if (!std::filesystem::create_directories(path, ec))
            return false;
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

    rc = mdb_env_set_mapsize(env, LMDB_DEFAULT_MAPSIZE);
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
    rc = mdb_env_open(env, path.c_str(), MDB_NOTLS, 0644);
    if (rc != 0) {
        printf("mdb_env_open failed: %s\n", mdb_strerror(rc));
        mdb_env_close(env);
        env = nullptr;
        return false;
    }

    strPath = path;
    return true;
}

void CLMDBEnv::Close()
{
    // DBI handles are invalidated when the environment is closed.
    mapDbis.clear();
    fWriterActive.store(false);

    if (env) {
        mdb_env_close(env);
        env = nullptr;
    }
    strPath.clear();
}

bool CLMDBEnv::OpenDbi(const std::string &name, MDB_dbi &dbi, bool fCreate)
{
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
