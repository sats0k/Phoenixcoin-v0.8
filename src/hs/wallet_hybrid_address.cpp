// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "../wallet.h"
#include "../walletdb.h"
#include "../util.h"
#include "wallethybrid.h"

// ============================================================================
// HYBRID ADDRESS BOOK IMPLEMENTATION
// ============================================================================

bool CWallet::SetHybridAddressBookName(const CHybridKeyID& keyID, const std::string& strName, const std::string& strPurpose)
{
    LOCK(cs_wallet);
    
    // Check if key exists in hybrid keys
    if (mapHybridKeys.find(keyID) == mapHybridKeys.end()) {
        printf("ERROR: SetHybridAddressBookName: Hybrid key %s not found\n", keyID.ToString().c_str());
        return false;
    }
    
    // Create address entry
    CHybridAddressEntry entry(strName, strPurpose);
    entry.nCreateTime = GetTime();
    
    // Update in-memory map
    mapHybridAddressBook[keyID] = entry;
    
    // Persist to database if wallet is backed
    if (fFileBacked) {
        CWalletDB walletdb(strWalletFile);
        if (!walletdb.WriteHybridAddressEntry(keyID, entry)) {
            printf("ERROR: SetHybridAddressBookName: Failed to write to database\n");
            return false;
        }
    }
    
    printf("Hybrid address %s labeled as '%s'\n", keyID.ToString().c_str(), strName.c_str());
    return true;
}

void CWallet::LoadHybridAddressBook()
{
    if (!fFileBacked) return;
    
    LOCK(cs_wallet);
    
    CWalletDB walletdb(strWalletFile);
    if (!walletdb.LoadAllHybridAddresses(mapHybridAddressBook)) {
        printf("WARNING: Failed to load hybrid address book from database\n");
        return;
    }
    
    printf("Loaded %zu hybrid addresses from address book\n", mapHybridAddressBook.size());
}
