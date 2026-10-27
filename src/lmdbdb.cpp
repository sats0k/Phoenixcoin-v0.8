// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "lmdbdb.h"
#include "util.h"
#include <sys/stat.h>

using namespace std;

CLMDBEnv lmdbenv;

CLMDBEnv::CLMDBEnv() : env(nullptr)
{
}

CLMDBEnv::~CLMDBEnv()
{
    Close();
}

bool CLMDBEnv::Open(const std::string &path)
{
    if (env) return true;

    strPath = path;
    int rc = mdb_env_create(&env);
    if (rc != 0) {
        printf("mdb_env_create failed: %s\n", mdb_strerror(rc));
        return false;
    }

    mdb_env_set_maxdbs(env, 64);
    mdb_env_set_mapsize(env, 1024ULL * 1024ULL * 1024ULL); // 1GB

    rc = mdb_env_open(env, path.c_str(), MDB_CREATE, 0644);
    if (rc != 0) {
        printf("mdb_env_open failed: %s\n", mdb_strerror(rc));
        mdb_env_close(env);
        env = nullptr;
        return false;
    }
    return true;
}

void CLMDBEnv::Close()
{
    if (!env) return;
    for (auto &p : mapDbis) {
        // dbi handles are closed when env closes
    }
    mapDbis.clear();
    mdb_env_close(env);
    env = nullptr;
}

CLMDBTxn::CLMDBTxn(bool readOnly)
{
    txn = nullptr;
    unsigned int flags = readOnly ? MDB_RDONLY : 0;
    int rc = mdb_txn_begin(lmdbenv.env, nullptr, flags, &txn);
    if (rc != 0) {
        printf("mdb_txn_begin failed: %s\n", mdb_strerror(rc));
        txn = nullptr;
    }
}

CLMDBTxn::~CLMDBTxn()
{
    if (txn) {
        mdb_txn_abort(txn);
        txn = nullptr;
    }
}

bool CLMDBTxn::Commit()
{
    if (!txn) return false;
    int rc = mdb_txn_commit(txn);
    txn = nullptr;
    return rc == 0;
}

void CLMDBTxn::Abort()
{
    if (txn) {
        mdb_txn_abort(txn);
        txn = nullptr;
    }
}
