// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef LMDBDB_H
#define LMDBDB_H

#include <map>
#include <string>

#include <lmdb.h>

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

    bool Open(const std::string &path, bool fCreate = true);
    void Close();

    bool IsOpen() const { return env != nullptr; }
    MDB_env *GetEnv() const { return env; }

    /**
     * Open (and cache) a named sub-database.  When fCreate is false the
     * sub-database must already exist.
     */
    bool OpenDbi(const std::string &name, MDB_dbi &dbi, bool fCreate = true);

private:
    MDB_env *env;
    std::string strPath;
    std::map<std::string, MDB_dbi> mapDbis;
};

#endif // LMDBDB_H
