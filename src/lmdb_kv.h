// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef LMDB_KV_H
#define LMDB_KV_H

#include "db_kv.h"
#include "lmdbdb.h"

#include <lmdb.h>

class CLMDBIterator : public CDBIterator
{
    MDB_cursor *cursor;
    MDB_val key, value;
    CDBKey prefix;
    bool valid;
    bool fError;

    bool MatchesPrefix() const;
public:
    CLMDBIterator(MDB_txn *txn, MDB_dbi dbi, const CDBKey &prefix = CDBKey());
    ~CLMDBIterator();
    bool Valid() const override;
    bool Error() const override { return fError; }
    void SeekToFirst() override;
    void SeekToLast() override;
    void Seek(const CDBKey &key) override;
    void Next() override;
    void Prev() override;
    CDBKey Key() const override;
    CDBValue Value() const override;
};

class CLMDBTransaction : public CDBTransaction
{
    MDB_txn *txn;
    MDB_dbi dbi;
    bool fReadOnly;
    bool fAborted;
    bool fCommitted;
    CLMDBEnv *writerEnv;

    void ReleaseWriter();
public:
    CLMDBTransaction(MDB_txn *tx, MDB_dbi d, bool fReadOnly, CLMDBEnv *env = nullptr);
    ~CLMDBTransaction();
    bool Read(const CDBKey &key, CDBValue &value) override;
    bool Write(const CDBKey &key, const CDBValue &value, bool fOverwrite = true) override;
    bool Erase(const CDBKey &key) override;
    std::unique_ptr<CDBIterator> NewIterator(const CDBKey &prefix = CDBKey()) override;
    bool Commit() override;
    void Abort() override;
};

class CLMDBDatabase : public CKeyValueDB
{
    CLMDBEnv ownedEnv;
    CLMDBEnv *env;
    MDB_dbi dbi;
    std::string strPath;
    std::string strSubDb;
    bool fOwnsEnv;
    bool fInit;

public:
    CLMDBDatabase();
    ~CLMDBDatabase() override;
    bool Open(const std::string &strPath, bool fCreate = true) override;
    /** Open a sub-database in a caller-owned, shared environment. */
    bool Open(CLMDBEnv &sharedEnv, const std::string &strSubDb, bool fCreate = true);
    void Close() override;
    std::unique_ptr<CDBTransaction> BeginTransaction(bool fReadOnly = false) override;

    /** Fills stats with the current counters for this database handle. */
    bool GetStats(CLMDBDBStats &stats) const;
};

#endif // LMDB_KV_H
