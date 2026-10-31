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
    /** True when a cursor operation failed for a reason other than end of data. */
    virtual bool Error() const { return false; }
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

/**
 * Backend-neutral forward scan over a database.
 *
 * A key/value database needs a read transaction for the whole scan; Berkeley
 * DB scans are driven by a cursor instead.  CDBScan owns whichever resources
 * the selected backend needs and exposes the small common interface the
 * wallet loaders use.
 */
class CDBScan
{
    std::unique_ptr<CDBTransaction> txn;
    std::unique_ptr<CDBIterator> it;

public:
    CDBScan(std::unique_ptr<CDBTransaction> txnIn, std::unique_ptr<CDBIterator> itIn);
    ~CDBScan();

    CDBScan(const CDBScan&) = delete;
    CDBScan& operator=(const CDBScan&) = delete;

    bool Valid() const { return it && it->Valid(); }
    /** True when the scan stopped because of a cursor error, not end of data. */
    bool Error() const { return it && it->Error(); }
    void SeekToFirst() { if (it) it->SeekToFirst(); }
    void SeekToLast() { if (it) it->SeekToLast(); }
    void Seek(const CDBKey &key) { if (it) it->Seek(key); }
    void Next() { if (it) it->Next(); }
    void Prev() { if (it) it->Prev(); }
    CDBKey Key() const { return it ? it->Key() : CDBKey(); }
    CDBValue Value() const { return it ? it->Value() : CDBValue(); }
};

#endif // DB_KV_H
