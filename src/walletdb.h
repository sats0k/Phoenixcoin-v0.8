// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef WALLETDB_H
#define WALLETDB_H

#pragma once

#include <utility>
#include <string>
#include <list>
#include <vector>
#include <set>

#include "db.h"
#include "key.h"
#include "script.h"
#include "serialize.h"
#include "hs/walletdb_hybrid.h"
#include "hs/wallethybrid.h"

class CAccount;
class CAccountingEntry;
class CKeyPool;
class CWalletTx;
class CHybridKeyDisk;

/** Error statuses for the wallet database */
enum DBErrors
{
    DB_LOAD_OK,
    DB_CORRUPT,
    DB_NONCRITICAL_ERROR,
    DB_TOO_NEW,
    DB_LOAD_FAIL,
    DB_NEED_REWRITE
};

/**
 * Result of the backend-specific wallet database check performed once during
 * startup.  LMDB validates its environment when it is opened, so it always
 * reports Ok.  Berkeley DB may need the legacy salvage/verify pass.
 */
enum class WalletStartupCheckResult
{
    Ok,
    Recovered,
    SalvageFailed,
    VerifyFailed,
};

/** Runs the backend-specific wallet database startup check. */
WalletStartupCheckResult CheckWalletDatabaseAtStartup();

class CKeyMetadata {

public:
    static const int CURRENT_VERSION = 1;
    int nVersion;
    int64 nCreateTime; /* 0 means unknown */

    CKeyMetadata() {
        SetNull();
    }

    CKeyMetadata(int64 nCreateTime_) {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = nCreateTime_;
    }

    IMPLEMENT_SERIALIZE(
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(nCreateTime);
    )

    void SetNull() {
        nVersion = CKeyMetadata::CURRENT_VERSION;
        nCreateTime = 0;
    }
};

/** Access to the wallet database (wallet.dat) */
class CWalletDB : public CDB
{
public:
    CWalletDB(std::string strFilename, const char* pszMode="r+") : CDB(strFilename.c_str(), pszMode)
    {
    }
private:
    CWalletDB(const CWalletDB&);
    void operator=(const CWalletDB&);
public:
    // vMalformed, when non-null, receives the IDs of "hyb" records whose
    // payload could not be parsed.  They are still present in the database but
    // are not returned in vKeys, so callers that diagnose the wallet can
    // report them instead of silently treating them as absent.
    bool LoadAllHybridKeys(std::vector<std::pair<CHybridKeyID, CHybridKeyDisk> > &vKeys,
                           std::vector<std::string>* vMalformed = nullptr);

    bool WriteHybridKey(const CHybridKeyID &keyID, const CHybridKeyDisk &disk);

    // ---- Hybrid Address Book Functions ----

    bool WriteHybridAddressEntry(const CHybridKeyID& keyID, const CHybridAddressEntry& entry);

    bool LoadAllHybridAddresses(std::map<CHybridKeyID, CHybridAddressEntry>& mapAddresses);

    bool WriteHybridUsedKeys(const std::set<CHybridKeyID>& setUsed);

    bool LoadHybridUsedKeys(std::set<CHybridKeyID>& setUsed);

    bool WriteName(const std::string& strAddress, const std::string& strName);

    bool EraseName(const std::string& strAddress);

    bool WriteTx(uint256 hash, const CWalletTx& wtx)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("tx"), hash), wtx);
    }

    bool EraseTx(uint256 hash)
    {
        nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("tx"), hash));
    }

    bool WriteKey(const CPubKey &vchPubKey, const CPrivKey &vchPrivKey, const CKeyMetadata &keyMeta) {
        nWalletDBUpdated++;

        // Keep the metadata and the key in one transaction so a crash cannot
        // leave a key without its creation time (or the reverse).  When the
        // caller already holds a transaction this joins it instead.
        const bool fOwnTxn = !IsTransactionActive();
        if (fOwnTxn && !TxnBegin())
            return false;

        if(!Write(std::make_pair(std::string("keymeta"), vchPubKey), keyMeta) ||
           !Write(std::make_pair(std::string("key"), vchPubKey.Raw()), vchPrivKey, false)) {
            if (fOwnTxn)
                TxnAbort();
            return(false);
        }

        return(!fOwnTxn || TxnCommit());
    }

    bool WriteCryptedKey(const CPubKey &vchPubKey, const std::vector<uchar> &vchCryptedSecret,
      const CKeyMetadata &keyMeta) {
        nWalletDBUpdated++;

        // Metadata, the encrypted secret and the removal of any plaintext
        // copies form one logical update.
        const bool fOwnTxn = !IsTransactionActive();
        if (fOwnTxn && !TxnBegin())
            return false;

        if(!Write(std::make_pair(std::string("keymeta"), vchPubKey), keyMeta) ||
           !Write(std::make_pair(std::string("ckey"), vchPubKey.Raw()), vchCryptedSecret, false) ||
           !Erase(std::make_pair(std::string("key"), vchPubKey.Raw())) ||
           !Erase(std::make_pair(std::string("wkey"), vchPubKey.Raw()))) {
            if (fOwnTxn)
                TxnAbort();
            return(false);
        }

        return(!fOwnTxn || TxnCommit());
    }

    bool WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
    }

    bool WriteCScript(const uint160& hash, const CScript& redeemScript)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("cscript"), hash), redeemScript, false);
    }

    bool WriteWatchOnly(const CScript &dest) {
        nWalletDBUpdated++;
        return(Write(std::make_pair(std::string("watch"), dest), '1'));
    }

    bool EraseWatchOnly(const CScript &dest) {
        nWalletDBUpdated++;
        return(Erase(std::make_pair(std::string("watch"), dest)));
    }

    bool WriteBestBlock(const CBlockLocator& locator)
    {
        nWalletDBUpdated++;
        return Write(std::string("bestblock"), locator);
    }

    bool ReadBestBlock(CBlockLocator& locator)
    {
        return Read(std::string("bestblock"), locator);
    }

    bool WriteOrderPosNext(int64 nOrderPosNext)
    {
        nWalletDBUpdated++;
        return Write(std::string("orderposnext"), nOrderPosNext);
    }

    bool WriteDefaultKey(const CPubKey& vchPubKey)
    {
        nWalletDBUpdated++;
        return Write(std::string("defaultkey"), vchPubKey.Raw());
    }

    bool ReadPool(int64 nPool, CKeyPool& keypool)
    {
        return Read(std::make_pair(std::string("pool"), nPool), keypool);
    }

    bool WritePool(int64 nPool, const CKeyPool& keypool)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("pool"), nPool), keypool);
    }

    bool ErasePool(int64 nPool)
    {
        nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("pool"), nPool));
    }

    // Settings are no longer stored in wallet.dat; these are
    // used only for backwards compatibility:
    template<typename T>
    bool ReadSetting(const std::string& strKey, T& value)
    {
        return Read(std::make_pair(std::string("setting"), strKey), value);
    }
    template<typename T>
    bool WriteSetting(const std::string& strKey, const T& value)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("setting"), strKey), value);
    }
    bool EraseSetting(const std::string& strKey)
    {
        nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("setting"), strKey));
    }

    bool WriteMinVersion(int nVersion)
    {
        return Write(std::string("minversion"), nVersion);
    }

    bool ReadAccount(const std::string& strAccount, CAccount& account);
    bool WriteAccount(const std::string& strAccount, const CAccount& account);
private:
    bool WriteAccountingEntry(const uint64 nAccEntryNum, const CAccountingEntry& acentry);
public:
    bool WriteAccountingEntry(const CAccountingEntry& acentry);
    int64 GetAccountCreditDebit(const std::string& strAccount);
    void ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& acentries);

    DBErrors ReorderTransactions(CWallet*);
    DBErrors LoadWallet(CWallet* pwallet);
    static bool Recover(CDBEnv& dbenv, std::string filename, bool fOnlyKeys);
    static bool Recover(CDBEnv& dbenv, std::string filename);
};

#endif /* WALLETDB_H */
