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

#include "db.h"
#include "key.h"
#include "script.h"
#include "serialize.h"
#include "hs/wallethybrid.h"

class CAccount;
class CAccountingEntry;
class CKeyPool;
class CWalletTx;
class CHybridKeyDisk;
class CHybridKeyMetadata;

struct CHybridKeyMetadata
{
    int32_t nCreateTime;
    int nVersion;

    CHybridKeyMetadata() : nCreateTime(0), nVersion(1) {}

    IMPLEMENT_SERIALIZE(
        READWRITE(nVersion);
        READWRITE(nCreateTime);
    )
};

// ============================================================================
// HYBRID ADDRESS BOOK METADATA
// ============================================================================

/**
 * Hybrid Address Entry
 * Stores metadata about hybrid keys in address book
 */
struct CHybridAddressEntry
{
    int nVersion;                           // Entry version
    int64 nCreateTime;                      // When address was created
    std::string strLabel;                   // User label/name
    std::string strPurpose;                 // "send", "receive", "change"

    CHybridAddressEntry() : nVersion(1), nCreateTime(0) {}

    CHybridAddressEntry(const std::string& label, const std::string& purpose = "receive")
        : nVersion(1), nCreateTime(GetTime()), strLabel(label), strPurpose(purpose) {}

    IMPLEMENT_SERIALIZE(
        READWRITE(nVersion);
        READWRITE(nCreateTime);
        READWRITE(strLabel);
        READWRITE(strPurpose);
    )
};

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
    bool LoadAllHybridKeys(std::vector<std::pair<CHybridKeyID, CHybridKeyDisk> > &vKeys);

    bool WriteHybridKey(const CHybridKeyID &keyID, const CHybridKeyDisk &disk);

    bool WriteHybridKeyMetadata(const CHybridKeyID& keyid, const CHybridKeyMetadata& meta);

    // ---- Hybrid Address Book Functions ----

    bool WriteHybridAddressEntry(const CHybridKeyID& keyID, const CHybridAddressEntry& entry)
    {
        nWalletDBUpdated++;
        return Write(std::make_pair(std::string("hybaddr"), keyID), entry);
    }

    bool EraseHybridAddressEntry(const CHybridKeyID& keyID)
    {
        nWalletDBUpdated++;
        return Erase(std::make_pair(std::string("hybaddr"), keyID));
    }

    bool ReadHybridAddressEntry(const CHybridKeyID& keyID, CHybridAddressEntry& entry)
    {
        return Read(std::make_pair(std::string("hybaddr"), keyID), entry);
    }

    bool LoadAllHybridAddresses(std::map<CHybridKeyID, CHybridAddressEntry>& mapAddresses)
    {
        mapAddresses.clear();
        Dbc* pcursor = GetCursor();
        if (!pcursor) return false;

        while (true) {
            CDataStream ssKey(SER_DISK, CLIENT_VERSION), ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND) break;
            if (ret != 0) {
                pcursor->close();
                return false;
            }

            std::string strType;
            ssKey >> strType;
            if (strType != "hybaddr") continue;

            CHybridKeyID keyID;
            ssKey >> keyID;

            CHybridAddressEntry entry;
            ssValue >> entry;

            mapAddresses[keyID] = entry;
        }

        pcursor->close();
        return true;
    }

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

        if(!Write(std::make_pair(std::string("keymeta"), vchPubKey), keyMeta))
          return(false);

        return(Write(std::make_pair(std::string("key"), vchPubKey.Raw()), vchPrivKey, false));
    }

    bool WriteCryptedKey(const CPubKey &vchPubKey, const std::vector<uchar> &vchCryptedSecret,
      const CKeyMetadata &keyMeta) {
        nWalletDBUpdated++;

        if(!Write(std::make_pair(std::string("keymeta"), vchPubKey), keyMeta))
          return(false);

        if(!Write(std::make_pair(std::string("ckey"), vchPubKey.Raw()), vchCryptedSecret, false))
          return(false);

        /* Erase unencrypted keys */
        Erase(std::make_pair(std::string("key"), vchPubKey.Raw()));
        Erase(std::make_pair(std::string("wkey"), vchPubKey.Raw()));

        return(true);
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
