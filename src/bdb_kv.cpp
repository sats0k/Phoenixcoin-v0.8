// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "bdb_kv.h"
#include "util.h"
#include <algorithm>

CBDBIterator::CBDBIterator(Db *db) : pdb(db), cursor(nullptr), valid(false)
{
    if (pdb) {
        pdb->cursor(nullptr, &cursor, 0);
    }
    key.set_flags(DB_DBT_USERMEM);
    value.set_flags(DB_DBT_USERMEM);
}

CBDBIterator::~CBDBIterator()
{
    if (cursor) {
        cursor->close();
        cursor = nullptr;
    }
}

bool CBDBIterator::Valid() const
{
    return valid && cursor != nullptr;
}

void CBDBIterator::SeekToFirst()
{
    if (!cursor) return;
    static unsigned char kbuf[1024], vbuf[4096];
    key.set_data(kbuf); key.set_ulen(sizeof(kbuf)); key.set_size(0);
    value.set_data(vbuf); value.set_ulen(sizeof(vbuf)); value.set_size(0);
    int ret = cursor->get(&key, &value, DB_FIRST);
    valid = (ret == 0);
}

void CBDBIterator::SeekToLast()
{
    if (!cursor) return;
    static unsigned char kbuf[1024], vbuf[4096];
    key.set_data(kbuf); key.set_ulen(sizeof(kbuf)); key.set_size(0);
    value.set_data(vbuf); value.set_ulen(sizeof(vbuf)); value.set_size(0);
    int ret = cursor->get(&key, &value, DB_LAST);
    valid = (ret == 0);
}

void CBDBIterator::Seek(const CDBKey &seekKey)
{
    if (!cursor) return;
    static unsigned char kbuf[4096], vbuf[4096];
    memcpy(kbuf, seekKey.data(), seekKey.size());
    key.set_data(kbuf); key.set_ulen(sizeof(kbuf)); key.set_size(seekKey.size());
    value.set_data(vbuf); value.set_ulen(sizeof(vbuf)); value.set_size(0);
    int ret = cursor->get(&key, &value, DB_SET_RANGE);
    valid = (ret == 0);
}

void CBDBIterator::Next()
{
    if (!cursor || !valid) return;
    static unsigned char kbuf[4096], vbuf[4096];
    key.set_data(kbuf); key.set_ulen(sizeof(kbuf)); key.set_size(0);
    value.set_data(vbuf); value.set_ulen(sizeof(vbuf)); value.set_size(0);
    int ret = cursor->get(&key, &value, DB_NEXT);
    valid = (ret == 0);
}

void CBDBIterator::Prev()
{
    if (!cursor || !valid) return;
    static unsigned char kbuf[4096], vbuf[4096];
    key.set_data(kbuf); key.set_ulen(sizeof(kbuf)); key.set_size(0);
    value.set_data(vbuf); value.set_ulen(sizeof(vbuf)); value.set_size(0);
    int ret = cursor->get(&key, &value, DB_PREV);
    valid = (ret == 0);
}

CDBKey CBDBIterator::Key() const
{
    CDBKey k;
    if (!valid || !key.get_data()) return k;
    k.assign((unsigned char*)key.get_data(), (unsigned char*)key.get_data() + key.get_size());
    return k;
}

CDBValue CBDBIterator::Value() const
{
    CDBValue v;
    if (!valid || !value.get_data()) return v;
    v.assign((unsigned char*)value.get_data(), (unsigned char*)value.get_data() + value.get_size());
    return v;
}

CBDBTransaction::CBDBTransaction(DbEnv *env, Db *db, bool readOnly) : dbenv(env), pdb(db), txn(nullptr), fReadOnly(readOnly), fAborted(false), fCommitted(false)
{
    if (!readOnly) {
        int ret = dbenv->txn_begin(nullptr, &txn, DB_TXN_WRITE_NOSYNC);
        if (ret != 0) txn = nullptr;
    }
}

CBDBTransaction::~CBDBTransaction()
{
    if (txn && !fCommitted && !fAborted) {
        txn->abort();
        txn = nullptr;
    }
}

bool CBDBTransaction::Read(const CDBKey &key, CDBValue &value)
{
    if (!pdb) return false;
    Dbt datKey((void*)key.data(), key.size());
    Dbt datValue;
    datValue.set_flags(DB_DBT_MALLOC);
    int ret = pdb->get(txn, &datKey, &datValue, 0);
    if (ret != 0 || !datValue.get_data()) {
        if (datValue.get_data()) free(datValue.get_data());
        return false;
    }
    value.assign((unsigned char*)datValue.get_data(), (unsigned char*)datValue.get_data() + datValue.get_size());
    free(datValue.get_data());
    return true;
}

bool CBDBTransaction::Write(const CDBKey &key, const CDBValue &value, bool fOverwrite)
{
    if (!pdb || fReadOnly) return false;
    Dbt datKey((void*)key.data(), key.size());
    Dbt datValue((void*)value.data(), value.size());
    int ret = pdb->put(txn, &datKey, &datValue, fOverwrite ? 0 : DB_NOOVERWRITE);
    return ret == 0;
}

bool CBDBTransaction::Erase(const CDBKey &key)
{
    if (!pdb || fReadOnly) return false;
    Dbt datKey((void*)key.data(), key.size());
    int ret = pdb->del(txn, &datKey, 0);
    return ret == 0 || ret == DB_NOTFOUND;
}

std::unique_ptr<CDBIterator> CBDBTransaction::NewIterator(const CDBKey &prefix)
{
    (void)prefix;
    return std::unique_ptr<CDBIterator>(new CBDBIterator(pdb));
}

bool CBDBTransaction::Commit()
{
    if (fReadOnly) {
        fCommitted = true;
        return true;
    }
    if (!txn) return false;
    int ret = txn->commit(0);
    txn = nullptr;
    fCommitted = (ret == 0);
    return fCommitted;
}

void CBDBTransaction::Abort()
{
    if (txn && !fCommitted) {
        txn->abort();
        txn = nullptr;
    }
    fAborted = true;
}

CBDBDatabase::CBDBDatabase() : dbenv(DB_CXX_NO_EXCEPTIONS), pdb(nullptr), fInit(false)
{
}

CBDBDatabase::~CBDBDatabase()
{
    Close();
}

bool CBDBDatabase::Open(const std::string &path, bool fCreate)
{
    (void)fCreate;
    if (fInit) return true;
    strPath = path;
    dbenv.set_lg_bsize(1048576);
    dbenv.set_lg_max(10485760);
    dbenv.set_lk_max_locks(10000);
    dbenv.set_flags(DB_AUTO_COMMIT, 1);
    dbenv.set_flags(DB_TXN_WRITE_NOSYNC, 1);
    int ret = dbenv.open(path.c_str(),
                         DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_MPOOL | DB_INIT_TXN | DB_THREAD,
                         0644);
    if (ret != 0) return false;
    pdb = new Db(&dbenv, 0);
    ret = pdb->open(nullptr, "wallet.dat", "main", DB_BTREE, DB_CREATE | DB_THREAD, 0644);
    if (ret != 0) {
        delete pdb; pdb = nullptr;
        return false;
    }
    fInit = true;
    return true;
}

void CBDBDatabase::Close()
{
    if (pdb) { pdb->close(0); delete pdb; pdb = nullptr; }
    if (fInit) { dbenv.close(0); fInit = false; }
}

std::unique_ptr<CDBTransaction> CBDBDatabase::BeginTransaction(bool fReadOnly)
{
    if (!pdb) return nullptr;
    return std::unique_ptr<CDBTransaction>(new CBDBTransaction(&dbenv, pdb, fReadOnly));
}
