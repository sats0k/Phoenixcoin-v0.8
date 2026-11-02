// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "lmdb_kv.h"
#include "util.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>

namespace {

void LogMapFullOnce(const std::string &strMapSizeFlag)
{
    // The chain index and the wallet have separate options.  Warn once per
    // option so a failure names the map that actually needs to grow.
    static std::atomic<bool> fWarnedChain(false);
    static std::atomic<bool> fWarnedWallet(false);
    std::atomic<bool> &fWarned =
        strMapSizeFlag == "-lmdbwalletsize" ? fWarnedWallet : fWarnedChain;
    bool expected = false;
    if (fWarned.compare_exchange_strong(expected, true))
        printf("LMDB map is full; increase %s and restart\n",
               strMapSizeFlag.c_str());
}

bool KeyHasPrefix(const MDB_val &key, const CDBKey &prefix)
{
    return prefix.size() <= key.mv_size &&
           memcmp(key.mv_data, prefix.data(), prefix.size()) == 0;
}

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

CLMDBIterator::CLMDBIterator(MDB_txn *txn, MDB_dbi d, const CDBKey &keyPrefix)
    : cursor(nullptr), prefix(keyPrefix), valid(false), fError(false)
{
    if (!txn || mdb_cursor_open(txn, d, &cursor) != 0) {
        cursor = nullptr;
        fError = true;
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

bool CLMDBIterator::MatchesPrefix() const
{
    return prefix.empty() || KeyHasPrefix(key, prefix);
}

void CLMDBIterator::SeekToFirst()
{
    if (!cursor) return;

    if (prefix.empty()) {
        int ret = mdb_cursor_get(cursor, &key, &value, MDB_FIRST);
        if (ret != 0 && ret != MDB_NOTFOUND)
            fError = true;
        valid = (ret == 0);
        return;
    }

    key.mv_size = prefix.size();
    key.mv_data = (void*)prefix.data();
    int ret = mdb_cursor_get(cursor, &key, &value, MDB_SET_RANGE);
    if (ret != 0 && ret != MDB_NOTFOUND)
        fError = true;
    valid = (ret == 0) && MatchesPrefix();
}

void CLMDBIterator::SeekToLast()
{
    if (!cursor) return;

    CDBKey upper;
    if (!prefix.empty() && PrefixUpperBound(prefix, upper)) {
        key.mv_size = upper.size();
        key.mv_data = (void*)upper.data();
        int ret = mdb_cursor_get(cursor, &key, &value, MDB_SET_RANGE);
        if (ret == 0)
            ret = mdb_cursor_get(cursor, &key, &value, MDB_PREV);
        else if (ret == MDB_NOTFOUND)
            ret = mdb_cursor_get(cursor, &key, &value, MDB_LAST);
        if (ret != 0 && ret != MDB_NOTFOUND)
            fError = true;
        valid = (ret == 0) && MatchesPrefix();
        return;
    }

    int ret = mdb_cursor_get(cursor, &key, &value, MDB_LAST);
    if (ret != 0 && ret != MDB_NOTFOUND)
        fError = true;
    valid = (ret == 0) && MatchesPrefix();
}

void CLMDBIterator::Seek(const CDBKey &seekKey)
{
    if (!cursor) return;

    // Clamp a seek below the prefix to the prefix itself so a prefixed
    // iterator starts at the first matching record.
    const CDBKey *effective = &seekKey;
    if (!prefix.empty() &&
        std::lexicographical_compare(seekKey.begin(), seekKey.end(), prefix.begin(), prefix.end())) {
        effective = &prefix;
    }

    key.mv_size = effective->size();
    key.mv_data = (void*)effective->data();
    int ret = mdb_cursor_get(cursor, &key, &value, MDB_SET_RANGE);
    if (ret != 0 && ret != MDB_NOTFOUND)
        fError = true;
    valid = (ret == 0) && MatchesPrefix();
}

void CLMDBIterator::Next()
{
    if (!cursor || !valid) return;
    int ret = mdb_cursor_get(cursor, &key, &value, MDB_NEXT);
    if (ret != 0 && ret != MDB_NOTFOUND)
        fError = true;
    valid = (ret == 0) && MatchesPrefix();
}

void CLMDBIterator::Prev()
{
    if (!cursor || !valid) return;
    int ret = mdb_cursor_get(cursor, &key, &value, MDB_PREV);
    if (ret != 0 && ret != MDB_NOTFOUND)
        fError = true;
    valid = (ret == 0) && MatchesPrefix();
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

CLMDBTransaction::CLMDBTransaction(MDB_txn *tx, MDB_dbi d, bool readOnly, CLMDBEnv *env)
    : txn(tx), dbi(d), fReadOnly(readOnly), fAborted(false), fCommitted(false), writerEnv(env)
{
}

void CLMDBTransaction::ReleaseWriter()
{
    if (writerEnv) {
        writerEnv->ReleaseWriter();
        writerEnv = nullptr;
    }
}

CLMDBTransaction::~CLMDBTransaction()
{
    if (txn) {
        mdb_txn_abort(txn);
        txn = nullptr;
    }
    ReleaseWriter();
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
    if (ret == MDB_MAP_FULL)
        LogMapFullOnce(writerEnv ? writerEnv->GetMapSizeFlag() : "-lmdbmapsize");
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
    return std::unique_ptr<CDBIterator>(new CLMDBIterator(txn, dbi, prefix));
}

bool CLMDBTransaction::Commit()
{
    if (!txn) return false;
    // mdb_txn_commit() is valid for read-only transactions too.  It must be
    // called (or Abort()) so the reader slot is released.
    int ret = mdb_txn_commit(txn);
    txn = nullptr;
    fCommitted = (ret == 0);
    if (ret == MDB_MAP_FULL)
        LogMapFullOnce(writerEnv ? writerEnv->GetMapSizeFlag() : "-lmdbmapsize");
    else if (ret != 0)
        printf("mdb_txn_commit failed: %s\n", mdb_strerror(ret));
    ReleaseWriter();
    return fCommitted;
}

void CLMDBTransaction::Abort()
{
    if (txn) {
        mdb_txn_abort(txn);
        txn = nullptr;
    }
    fAborted = true;
    ReleaseWriter();
}

CLMDBDatabase::CLMDBDatabase() : env(nullptr), dbi(0), fOwnsEnv(false), fInit(false)
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
    strSubDb = "main";
    env = &ownedEnv;
    fOwnsEnv = true;
    if (!env->Open(path, fCreate)) {
        env = nullptr;
        fOwnsEnv = false;
        return false;
    }
    if (!env->OpenDbi(strSubDb, dbi, fCreate)) {
        env->Close();
        dbi = 0;
        env = nullptr;
        fOwnsEnv = false;
        return false;
    }
    fInit = true;
    return true;
}

bool CLMDBDatabase::Open(CLMDBEnv &sharedEnv, const std::string &subDb, bool fCreate)
{
    if (fInit) return true;
    if (!sharedEnv.IsOpen())
        return false;
    strPath = sharedEnv.GetPath();
    strSubDb = subDb;
    env = &sharedEnv;
    fOwnsEnv = false;
    if (!env->OpenDbi(strSubDb, dbi, fCreate)) {
        dbi = 0;
        env = nullptr;
        return false;
    }
    fInit = true;
    return true;
}

void CLMDBDatabase::Close()
{
    if (!fInit) return;

    // Shared environments outlive individual database handles; only the
    // owning adapter is allowed to shut the environment down.
    if (fOwnsEnv && env)
        env->Close();

    dbi = 0;
    env = nullptr;
    fOwnsEnv = false;
    fInit = false;
}

std::unique_ptr<CDBTransaction> CLMDBDatabase::BeginTransaction(bool fReadOnly)
{
    if (!fInit || !env) return nullptr;

    CLMDBEnv *writerEnv = nullptr;
    if (!fReadOnly) {
        // LMDB has a single writer per environment.  Fail fast instead of
        // blocking; the caller is expected to retry.
        if (!env->TryAcquireWriter())
            return nullptr;
        writerEnv = env;
    }

    MDB_txn *txn = nullptr;
    unsigned int flags = fReadOnly ? MDB_RDONLY : 0;
    int rc = mdb_txn_begin(env->GetEnv(), nullptr, flags, &txn);
    if (rc != 0) {
        if (writerEnv)
            writerEnv->ReleaseWriter();
        return nullptr;
    }
    return std::unique_ptr<CDBTransaction>(new CLMDBTransaction(txn, dbi, fReadOnly, writerEnv));
}
