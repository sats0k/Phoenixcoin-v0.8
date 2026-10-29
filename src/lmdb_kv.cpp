// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "lmdb_kv.h"
#include "util.h"

CLMDBIterator::CLMDBIterator(MDB_txn *txn, MDB_dbi d) : cursor(nullptr), valid(false)
{
    if (txn && mdb_cursor_open(txn, d, &cursor) != 0) {
        cursor = nullptr;
    }
}

CLMDBIterator::~CLMDBIterator()
{
    if (cursor) {
        mdb_cursor_close(cursor);
        cursor = nullptr;
    }
}

bool CLMDBIterator::Valid() const
{
    return valid && cursor != nullptr;
}

void CLMDBIterator::SeekToFirst()
{
    if (!cursor) return;
    int ret = mdb_cursor_get(cursor, &key, &value, MDB_FIRST);
    valid = (ret == 0);
}

void CLMDBIterator::SeekToLast()
{
    if (!cursor) return;
    int ret = mdb_cursor_get(cursor, &key, &value, MDB_LAST);
    valid = (ret == 0);
}

void CLMDBIterator::Seek(const CDBKey &seekKey)
{
    if (!cursor) return;
    key.mv_size = seekKey.size();
    key.mv_data = (void*)seekKey.data();
    int ret = mdb_cursor_get(cursor, &key, &value, MDB_SET_RANGE);
    valid = (ret == 0);
}

void CLMDBIterator::Next()
{
    if (!cursor || !valid) return;
    int ret = mdb_cursor_get(cursor, &key, &value, MDB_NEXT);
    valid = (ret == 0);
}

void CLMDBIterator::Prev()
{
    if (!cursor || !valid) return;
    int ret = mdb_cursor_get(cursor, &key, &value, MDB_PREV);
    valid = (ret == 0);
}

CDBKey CLMDBIterator::Key() const
{
    CDBKey k;
    if (!valid || key.mv_size == 0 || !key.mv_data) return k;
    k.assign((unsigned char*)key.mv_data, (unsigned char*)key.mv_data + key.mv_size);
    return k;
}

CDBValue CLMDBIterator::Value() const
{
    CDBValue v;
    if (!valid || value.mv_size == 0 || !value.mv_data) return v;
    v.assign((unsigned char*)value.mv_data, (unsigned char*)value.mv_data + value.mv_size);
    return v;
}

CLMDBTransaction::CLMDBTransaction(MDB_txn *tx, MDB_dbi d, bool readOnly) : txn(tx), dbi(d), fReadOnly(readOnly), fAborted(false), fCommitted(false)
{
}

CLMDBTransaction::~CLMDBTransaction()
{
    if (txn) {
        mdb_txn_abort(txn);
        txn = nullptr;
    }
}

bool CLMDBTransaction::Read(const CDBKey &key, CDBValue &value)
{
    if (!txn) return false;
    MDB_val mkey, mval;
    mkey.mv_size = key.size();
    mkey.mv_data = (void*)key.data();
    int ret = mdb_get(txn, dbi, &mkey, &mval);
    if (ret != 0) return false;
    if (mval.mv_size == 0 || !mval.mv_data) {
        value.clear();
        return true;
    }
    value.assign((unsigned char*)mval.mv_data, (unsigned char*)mval.mv_data + mval.mv_size);
    return true;
}

bool CLMDBTransaction::Write(const CDBKey &key, const CDBValue &value, bool fOverwrite)
{
    if (!txn || fReadOnly) return false;
    static const unsigned char empty = 0;
    MDB_val mkey, mval;
    mkey.mv_size = key.size();
    mkey.mv_data = (void*)key.data();
    mval.mv_size = value.size();
    mval.mv_data = value.empty() ? (void*)&empty : (void*)value.data();
    unsigned int flags = fOverwrite ? 0 : MDB_NOOVERWRITE;
    int ret = mdb_put(txn, dbi, &mkey, &mval, flags);
    return ret == 0;
}

bool CLMDBTransaction::Erase(const CDBKey &key)
{
    if (!txn || fReadOnly) return false;
    MDB_val mkey;
    mkey.mv_size = key.size();
    mkey.mv_data = (void*)key.data();
    int ret = mdb_del(txn, dbi, &mkey, nullptr);
    return ret == 0 || ret == MDB_NOTFOUND;
}

std::unique_ptr<CDBIterator> CLMDBTransaction::NewIterator(const CDBKey &prefix)
{
    (void)prefix;
    return std::unique_ptr<CDBIterator>(new CLMDBIterator(txn, dbi));
}

bool CLMDBTransaction::Commit()
{
    if (!txn) return false;
    // mdb_txn_commit() is valid for read-only transactions too.  It must be
    // called (or Abort()) so the reader slot is released.
    int ret = mdb_txn_commit(txn);
    txn = nullptr;
    fCommitted = (ret == 0);
    return fCommitted;
}

void CLMDBTransaction::Abort()
{
    if (txn) {
        mdb_txn_abort(txn);
        txn = nullptr;
    }
    fAborted = true;
}

CLMDBDatabase::CLMDBDatabase() : dbi(0), fInit(false)
{
}

CLMDBDatabase::~CLMDBDatabase()
{
    Close();
}

bool CLMDBDatabase::Open(const std::string &path, bool fCreate)
{
    if (fInit) return true;
    strPath = path;
    if (!env.Open(path, fCreate)) return false;
    if (!env.OpenDbi("main", dbi, fCreate)) {
        env.Close();
        dbi = 0;
        return false;
    }
    fInit = true;
    return true;
}

void CLMDBDatabase::Close()
{
    if (fInit) {
        env.Close();
        dbi = 0;
        fInit = false;
    }
}

std::unique_ptr<CDBTransaction> CLMDBDatabase::BeginTransaction(bool fReadOnly)
{
    if (!fInit) return nullptr;
    MDB_txn *txn = nullptr;
    unsigned int flags = fReadOnly ? MDB_RDONLY : 0;
    int rc = mdb_txn_begin(env.GetEnv(), nullptr, flags, &txn);
    if (rc != 0) return nullptr;
    return std::unique_ptr<CDBTransaction>(new CLMDBTransaction(txn, dbi, fReadOnly));
}
