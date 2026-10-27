// Copyright (c) 2026 The Phoenixcoin developers
#include "sync.h"
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef LMDBDB_H
#define LMDBDB_H

#include <string>
#include <map>
#include <vector>
#include <utility>
#include <lmdb.h>

#include "serialize.h"
#include "uint256.h"

class CLMDBEnv
{
public:
    MDB_env *env;
    std::string strPath;
    std::map<std::string, MDB_dbi> mapDbis;
    CCriticalSection cs_db;

    CLMDBEnv();
    ~CLMDBEnv();
    bool Open(const std::string &path);
    void Close();
    bool IsOpen() const { return env != nullptr; }
};

extern CLMDBEnv lmdbenv;

class CLMDBTxn
{
public:
    MDB_txn *txn;
    CLMDBTxn(bool readOnly = false);
    ~CLMDBTxn();
    bool Commit();
    void Abort();
};

#endif // LMDBDB_H
