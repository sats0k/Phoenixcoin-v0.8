// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "db.h"
#include "wallet.h"
#include "walletdb.h"
#include "hs/walletdb_hybrid.h"
#include "hs/wallethybrid.h"

using namespace std;

namespace {

CDataStream StreamFromBytes(const std::vector<unsigned char>& data)
{
    CDataStream stream(SER_DISK, CLIENT_VERSION);
    if (!data.empty())
        stream.write((const char*)&data[0], data.size());
    return stream;
}

} // namespace

bool CWalletDB::LoadAllHybridKeys(vector<pair<CHybridKeyID, CHybridKeyDisk> > &vKeys)
{
    vKeys.clear();
    std::unique_ptr<CDBScan> scan = GetScan();
    if (!scan) return false;

    scan->SeekToFirst();
    while (scan->Valid()) {
        CDBKey key = scan->Key();
        CDBValue value = scan->Value();
        CDataStream ssKey = StreamFromBytes(key);
        CDataStream ssValue = StreamFromBytes(value);
        scan->Next();

        std::string strType;
        ssKey >> strType;
        if (strType != "hyb") continue; // must match write prefix

        CHybridKeyID hybridID;
        ssKey >> hybridID;

        CHybridKeyDisk disk;
        bool fParsed = false;
        try {
            // Newest layout: the first field is the record's own nVersion.
            CDataStream ssCopy = StreamFromBytes(value);
            ssCopy >> disk;
            if (disk.nVersion == HYBRIDKEY_DISK_VERSION ||
                disk.nVersion == HYBRIDKEY_DISK_VERSION_ENCRYPTED)
                fParsed = true;
        } catch (const std::exception&) {}

        if (!fParsed) {
            // Fall back to the original layout (whose first field is the
            // stream serialization version, i.e. CLIENT_VERSION).
            if (!CHybridKeyDisk::FromLegacyDiskFormat(ssValue, disk)) {
                printf("WARNING: skipping undecipherable hybrid key record\n");
                continue;
            }
        }

        vKeys.push_back(make_pair(hybridID, disk));
    }

    if (scan->Error())
        return false;

    return true;
}

bool CWalletDB::WriteHybridKey(const CHybridKeyID &keyID, const CHybridKeyDisk &disk)
{
    // Test-only failure injection (see regression_atomic_importhybridkey.sh):
    // when PHOENIX_TEST_FAIL_HYBRID_WRITE is set to this key's hex id, the
    // first matching write returns false, driving callers down their
    // TxnAbort() rollback path (importhybridkey commits the ECDSA record,
    // hybrid key and label in one transaction). One-shot per id so an
    // immediate retry in the same daemon succeeds.
    {
        const char* psFail = std::getenv("PHOENIX_TEST_FAIL_HYBRID_WRITE");
        const std::string sFail = (psFail && *psFail) ? std::string(psFail)
                                                      : std::string();
        if (!sFail.empty() && keyID.GetHex() == sFail) {
            // Guarded because WriteHybridKey may run concurrently (e.g. keypool
            // top-ups while an RPC import is in progress).
            static CCriticalSection csFailedIds;
            static std::set<std::string> sFailedIds;
            LOCK(csFailedIds);
            if (sFailedIds.insert(sFail).second)
                return false;
        }
    }
    nWalletDBUpdated++;
    return Write(make_pair(std::string("hyb"), keyID), disk);
}

// ---- Hybrid Address Book Functions ----

bool CWalletDB::WriteHybridAddressEntry(const CHybridKeyID& keyID, const CHybridAddressEntry& entry)
{
    nWalletDBUpdated++;
    return Write(make_pair(std::string("hybaddr"), keyID), entry);
}

// ---- Hybrid Used-Key Set Functions ----

bool CWalletDB::WriteHybridUsedKeys(const std::set<CHybridKeyID>& setUsed)
{
    nWalletDBUpdated++;
    return Write(std::string("hybused"), setUsed);
}

bool CWalletDB::LoadHybridUsedKeys(std::set<CHybridKeyID>& setUsed)
{
    setUsed.clear();
    return Read(std::string("hybused"), setUsed);
}

bool CWalletDB::LoadAllHybridAddresses(map<CHybridKeyID, CHybridAddressEntry>& mapAddresses)
{
    mapAddresses.clear();
    std::unique_ptr<CDBScan> scan = GetScan();
    if (!scan) return false;

    scan->SeekToFirst();
    while (scan->Valid()) {
        CDBKey key = scan->Key();
        CDBValue value = scan->Value();
        CDataStream ssKey = StreamFromBytes(key);
        CDataStream ssValue = StreamFromBytes(value);
        scan->Next();

        std::string strType;
        ssKey >> strType;
        if (strType != "hybaddr") continue;

        CHybridKeyID keyID;
        ssKey >> keyID;

        CHybridAddressEntry entry;
        ssValue >> entry;

        mapAddresses[keyID] = entry;
    }

    if (scan->Error())
        return false;

    return true;
}
