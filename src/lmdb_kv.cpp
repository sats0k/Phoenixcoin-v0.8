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
    if (!valid || !key.mv_data) return k;
    k.assign((unsigned char*)key.mv_data, (unsigned char*)key.mv_data + key.mv_size);
    return k;
}

CDBValue CLMDBIterator::Value() const
{
    CDBValue v;
    if (!valid || !value.mv_data) return v;
    v.assign((unsigned char*)value.mv_data, (unsigned char*)value.mv_data + value.mv_size);
    return v;
}

CLMDBTransaction::CLMDBTransaction(MDB_txn *tx, MDB_dbi d, bool readOnly) : txn(tx), dbi(d), fReadOnly(readOnly), fAborted(false), fCommitted(false)
{
}

CLMDBTransaction::~CLMDBTransaction()
{
    if (txn && !fCommitted && !fAborted) {
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
    value.assign((unsigned char*)mval.mv_data, (unsigned char*)mval.mv_data + mval.mv_size);
    return true;
}

bool CLMDBTransaction::Write(const CDBKey &key, const CDBValue &value, bool fOverwrite)
{
    if (!txn || fReadOnly) return false;
    MDB_val mkey, mval;
    mkey.mv_size = key.size();
    mkey.mv_data = (void*)key.data();
    mval.mv_size = value.size();
    mval.mv_data = (void*)value.data();
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
    if (fReadOnly) {
        fCommitted = true;
        return true;
    }
    if (!txn) return false;
    int ret = mdb_txn_commit(txn);
    txn = nullptr;
    fCommitted = (ret == 0);
    return fCommitted;
}

void CLMDBTransaction::Abort()
{
    if (txn && !fCommitted) {
        mdb_txn_abort(txn);
        txn = nullptr;
    }
    fAborted = true;
}

CLMDBDatabase::CLMDBDatabase() : env(nullptr), dbi(0), fInit(false)
{
}

CLMDBDatabase::~CLMDBDatabase()
{
    Close();
}

bool CLMDBDatabase::Open(const std::string &path, bool fCreate)
{
    (void)fCreate;
    if (fInit) return true;
    strPath = path;
    int rc = mdb_env_create(&env);
    if (rc != 0) return false;
    mdb_env_set_maxdbs(env, 64);
    mdb_env_set_mapsize(env, 1024ULL * 1024ULL * 1024ULL);
    rc = mdb_env_open(env, path.c_str(), MDB_CREATE, 0644);
    if (rc != 0) { mdb_env_close(env); env = nullptr; return false; }
    MDB_txn *txn = nullptr;
    rc = mdb_txn_begin(env, nullptr, 0, &txn);
    if (rc != 0) { mdb_env_close(env); env = nullptr; return false; }
    rc = mdb_dbi_open(txn, "main", MDB_CREATE, &dbi);
    if (rc != 0) { mdb_txn_abort(txn); mdb_env_close(env); env = nullptr; return false; }
    mdb_txn_commit(txn);
    fInit = true;
    return true;
}

void CLMDBDatabase::Close()
{
    if (fInit && env) {
        mdb_env_close(env);
        env = nullptr;
        fInit = false;
    }
}

std::unique_ptr<CDBTransaction> CLMDBDatabase::BeginTransaction(bool fReadOnly)
{
    if (!env) return nullptr;
    MDB_txn *txn = nullptr;
    unsigned int flags = fReadOnly ? MDB_RDONLY : 0;
    int rc = mdb_txn_begin(env, nullptr, flags, &txn);
    if (rc != 0) return nullptr;
    return std::unique_ptr<CDBTransaction>(new CLMDBTransaction(txn, dbi, fReadOnly));
}
