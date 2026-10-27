// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef DB_KV_H
#define DB_KV_H

#include <memory>
#include <string>
#include <vector>

typedef std::vector<unsigned char> CDBKey;
typedef std::vector<unsigned char> CDBValue;

class CDBIterator
{
public:
    virtual ~CDBIterator() {}
    virtual bool Valid() const = 0;
    virtual void SeekToFirst() = 0;
    virtual void SeekToLast() = 0;
    virtual void Seek(const CDBKey &key) = 0;
    virtual void Next() = 0;
    virtual void Prev() = 0;
    virtual CDBKey Key() const = 0;
    virtual CDBValue Value() const = 0;
};

class CDBTransaction
{
public:
    virtual ~CDBTransaction() {}
    virtual bool Read(const CDBKey &key, CDBValue &value) = 0;
    virtual bool Write(const CDBKey &key, const CDBValue &value, bool fOverwrite = true) = 0;
    virtual bool Erase(const CDBKey &key) = 0;
    virtual std::unique_ptr<CDBIterator> NewIterator(const CDBKey &prefix = CDBKey()) = 0;
    virtual bool Commit() = 0;
    virtual void Abort() = 0;
};

class CKeyValueDB
{
public:
    virtual ~CKeyValueDB() {}
    virtual bool Open(const std::string &strPath, bool fCreate = true) = 0;
    virtual void Close() = 0;
    virtual std::unique_ptr<CDBTransaction> BeginTransaction(bool fReadOnly = false) = 0;
};

#endif // DB_KV_H
