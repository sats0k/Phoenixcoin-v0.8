// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "bdb_kv.h"
#include "util.h"
#include <algorithm>
#include <openssl/crypto.h>
#include <cstring>

namespace {

// Computes the smallest key that sorts after every key beginning with prefix.
// Returns false when no such key exists (the prefix is all 0xff).
bool PrefixUpperBound(const CDBKey &prefix, CDBKey &upper)
{
    upper = prefix;
    while (!upper.empty()) {
        if (upper.back() != 0xff) {
            ++upper.back();
            return true;
        }
        upper.pop_back();
    }
    return false;
}

} // namespace

CBDBIterator::CBDBIterator(Db *db, const CDBKey &keyPrefix, DbTxn *txn)
    : pdb(db), cursor(nullptr), prefix(keyPrefix), valid(false), fError(false)
{
    if (pdb) {
        if (pdb->cursor(txn, &cursor, 0) != 0 || !cursor) {
            cursor = nullptr;
            fError = true;
        }
    }
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

bool CBDBIterator::MatchesPrefix() const
{
    return prefix.empty() ||
           (prefix.size() <= currentKey.size() &&
            memcmp(currentKey.data(), prefix.data(), prefix.size()) == 0);
}

bool CBDBIterator::Fetch(int flags, const CDBKey *seekKey)
{
    valid = false;
    currentKey.clear();
    currentValue.clear();
    if (!cursor)
        return false;

    Dbt datKey;
    if (seekKey && !seekKey->empty()) {
        datKey.set_data(const_cast<unsigned char*>(seekKey->data()));
        datKey.set_size(seekKey->size());
    }
    Dbt datValue;

    // Match CDB::ReadAtCursor(): ask Berkeley DB for its own copies so the
    // values do not point into cursor-owned memory that the next operation
    // invalidates.  They are copied out and freed below.
    datKey.set_flags(DB_DBT_MALLOC);
    datValue.set_flags(DB_DBT_MALLOC);

    int ret = cursor->get(&datKey, &datValue, flags);
    if (ret != 0)
    {
        // DB_NOTFOUND is ordinary end of data, including for a seek past the
        // last key.  Anything else is a real cursor error and must not be
        // mistaken for an empty or complete scan by wallet loaders.
        if (ret != DB_NOTFOUND)
            fError = true;
        return false;
    }

    if (datKey.get_data() && datKey.get_size() > 0)
        currentKey.assign((unsigned char*)datKey.get_data(),
                          (unsigned char*)datKey.get_data() + datKey.get_size());
    if (datValue.get_data() && datValue.get_size() > 0)
        currentValue.assign((unsigned char*)datValue.get_data(),
                            (unsigned char*)datValue.get_data() + datValue.get_size());

    if (datKey.get_data()) {
        OPENSSL_cleanse(datKey.get_data(), datKey.get_size());
        free(datKey.get_data());
    }
    if (datValue.get_data()) {
        OPENSSL_cleanse(datValue.get_data(), datValue.get_size());
        free(datValue.get_data());
    }

    valid = true;
    return true;
}

void CBDBIterator::SeekToFirst()
{
    if (prefix.empty())
        Fetch(DB_FIRST);
    else
        Fetch(DB_SET_RANGE, &prefix);
    valid = valid && MatchesPrefix();
}

void CBDBIterator::SeekToLast()
{
    CDBKey upper;
    if (!prefix.empty() && PrefixUpperBound(prefix, upper)) {
        if (Fetch(DB_SET_RANGE, &upper)) {
            Fetch(DB_PREV);
        } else {
            Fetch(DB_LAST);
        }
        valid = valid && MatchesPrefix();
        return;
    }

    Fetch(DB_LAST);
    valid = valid && MatchesPrefix();
}

void CBDBIterator::Seek(const CDBKey &seekKey)
{
    // Clamp a seek below the prefix to the prefix itself so a prefixed
    // iterator starts at the first matching record.
    const CDBKey *effective = &seekKey;
    if (!prefix.empty() &&
        std::lexicographical_compare(seekKey.begin(), seekKey.end(), prefix.begin(), prefix.end())) {
        effective = &prefix;
    }

    if (effective->empty())
        Fetch(DB_FIRST);
    else
        Fetch(DB_SET_RANGE, effective);
    valid = valid && MatchesPrefix();
}

void CBDBIterator::Next()
{
    if (!cursor || !valid) return;
    Fetch(DB_NEXT);
    valid = valid && MatchesPrefix();
}

void CBDBIterator::Prev()
{
    if (!cursor || !valid) return;
    Fetch(DB_PREV);
    valid = valid && MatchesPrefix();
}

CDBKey CBDBIterator::Key() const
{
    return valid ? currentKey : CDBKey();
}

CDBValue CBDBIterator::Value() const
{
    return valid ? currentValue : CDBValue();
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
    return std::unique_ptr<CDBIterator>(new CBDBIterator(pdb, prefix));
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
