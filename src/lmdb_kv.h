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
    bool valid;
public:
    CLMDBIterator(MDB_txn *txn, MDB_dbi dbi);
    ~CLMDBIterator();
    bool Valid() const override;
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
    CLMDBEnv env;
    MDB_dbi dbi;
    std::string strPath;
    bool fInit;

public:
    CLMDBDatabase();
    ~CLMDBDatabase() override;
    bool Open(const std::string &strPath, bool fCreate = true) override;
    void Close() override;
    std::unique_ptr<CDBTransaction> BeginTransaction(bool fReadOnly = false) override;
};

#endif // LMDB_KV_H
