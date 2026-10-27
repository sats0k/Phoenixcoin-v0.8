// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef BDB_KV_H
#define BDB_KV_H

#include "db_kv.h"
#include <db_cxx.h>
#include "sync.h"

class CBDBIterator : public CDBIterator
{
    Db *pdb;
    Dbc *cursor;
    Dbt key, value;
    bool valid;
public:
    CBDBIterator(Db *db);
    ~CBDBIterator();
    bool Valid() const override;
    void SeekToFirst() override;
    void SeekToLast() override;
    void Seek(const CDBKey &key) override;
    void Next() override;
    void Prev() override;
    CDBKey Key() const override;
    CDBValue Value() const override;
};

class CBDBTransaction : public CDBTransaction
{
    DbEnv *dbenv;
    Db *pdb;
    DbTxn *txn;
    bool fReadOnly;
    bool fAborted;
    bool fCommitted;
public:
    CBDBTransaction(DbEnv *env, Db *db, bool fReadOnly);
    ~CBDBTransaction();
    bool Read(const CDBKey &key, CDBValue &value) override;
    bool Write(const CDBKey &key, const CDBValue &value, bool fOverwrite = true) override;
    bool Erase(const CDBKey &key) override;
    std::unique_ptr<CDBIterator> NewIterator(const CDBKey &prefix = CDBKey()) override;
    bool Commit() override;
    void Abort() override;
};

class CBDBDatabase : public CKeyValueDB
{
public:
    DbEnv dbenv;
    Db *pdb;
    std::string strPath;
    bool fInit;
    CCriticalSection cs_db;

    CBDBDatabase();
    ~CBDBDatabase();
    bool Open(const std::string &strPath, bool fCreate = true) override;
    void Close() override;
    std::unique_ptr<CDBTransaction> BeginTransaction(bool fReadOnly = false) override;
};

#endif // BDB_KV_H
