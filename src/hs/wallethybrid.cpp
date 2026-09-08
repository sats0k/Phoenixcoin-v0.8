// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "util.h"
#include "wallet.h"
#include "walletdb.h"
#include "init.h"
#include "serialize.h"
#include "hs/hybrid_signer.h"
#include "hs/wallethybrid.h"

#include <memory>
#include <vector>
#include <stdexcept>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

// -----------------------------
// CHybridKeyDisk
// -----------------------------

// Serializes the CHybridKeyDisk payload exactly as IMPLEMENT_SERIALIZE does
// (everything except hashChecksum). This keeps the checksum in sync with the
// on-disk layout for both the legacy plaintext (v1/v2) and encrypted (v3)
// formats.
static CDataStream SerializeHybridDiskPayload(const CHybridKeyDisk& d)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << d.nVersion << d.nCreateTime;

    if (d.IsEncrypted()) {
        ss << d.secpPub << d.mldsaAlg;
        ::WriteCompactSize(ss, d.vchCryptedPrivate.size());
        if (!d.vchCryptedPrivate.empty())
            ss.write((const char*)&d.vchCryptedPrivate[0], d.vchCryptedPrivate.size());
    } else {
        ss << d.secpPriv << d.secpPub;
        if (d.nVersion >= 2)
            ss << d.mldsaAlg;
        ::WriteCompactSize(ss, d.mldsaPrivKey.size());
        if (!d.mldsaPrivKey.empty())
            ss.write((const char*)&d.mldsaPrivKey[0], d.mldsaPrivKey.size());
    }
    return ss;
}

// Attempts to parse a record written with the original on-disk layout, where
// the first 4 bytes are the stream serialization version (CLIENT_VERSION)
// rather than the data member nVersion. This is what wallets created before
// the encrypted (v3) format look like on disk.
bool CHybridKeyDisk::FromLegacyDiskFormat(CDataStream& ss, CHybridKeyDisk& out)
{
    try {
        int32_t nStreamVersion = 0;
        ss >> nStreamVersion;

        CHybridKeyDisk disk;
        disk.nVersion = HYBRIDKEY_DISK_VERSION;
        ss >> disk.nCreateTime;
        ss >> disk.secpPriv;
        ss >> disk.secpPub;
        if (nStreamVersion >= 2) {
            ss >> disk.mldsaAlg;
            ss >> disk.mldsaPrivKey;
        }
        ss >> disk.hashChecksum;
        if (!ss.empty())
            return false;
        disk.fLegacyDisk = true;
        out = std::move(disk);
        return true;
    } catch (const std::exception& e) {
        printf("FromLegacyDiskFormat() : %s\n", e.what());
        return false;
    }
}

void CHybridKeyDisk::ComputeChecksum()
{
    CDataStream ss = SerializeHybridDiskPayload(*this);
    hashChecksum = Hash(ss.begin(), ss.end());
}

bool CHybridKeyDisk::CheckChecksum() const
{
    CDataStream ss = SerializeHybridDiskPayload(*this);
    return hashChecksum == Hash(ss.begin(), ss.end());
}

// Serializes the MLDSA private key to DER. Returns false on failure.
static bool SerializeMldsaPrivateKey(EVP_PKEY* pkey,
                                     std::vector<unsigned char>& mldsaPrivOut)
{
    if (!pkey)
        return false;

    unsigned char* buf = nullptr;
    int len = i2d_PrivateKey(pkey, &buf);
    if (len <= 0 || !buf)
        return false;

    mldsaPrivOut.assign(buf, buf + len);
    OPENSSL_free(buf);
    return true;
}

CHybridKeyDisk CHybridKeyDisk::FromMemory(const CHybridKey& hk)
{
    CHybridKeyDisk disk;
    disk.nVersion    = HYBRIDKEY_DISK_VERSION;
    disk.nCreateTime = hk.nCreateTime;
    disk.secpPriv    = hk.secpPriv;
    disk.secpPub     = hk.secpPub;
    disk.mldsaAlg    = hk.mldsaAlg;

    // Serialize MLDSA private key
    if (!SerializeMldsaPrivateKey(hk.mldsaSigner->GetKey(), disk.mldsaPrivKey))
        throw std::runtime_error("Failed to serialize MLDSA private key");

    disk.ComputeChecksum();
    return disk;
}

CHybridKeyDisk CHybridKeyDisk::FromMemoryEncrypted(const CHybridKey& hk,
                                                   const CKeyingMaterial& vMasterKey)
{
    CHybridKeyDisk disk;
    disk.nVersion    = HYBRIDKEY_DISK_VERSION_ENCRYPTED;
    disk.nCreateTime = hk.nCreateTime;
    disk.secpPub     = hk.secpPub;
    disk.mldsaAlg    = hk.mldsaAlg;

    if (vMasterKey.size() != WALLET_CRYPTO_KEY_SIZE)
        throw std::runtime_error("wallet is not unlocked");

    std::vector<unsigned char> mldsaPriv;
    if (!SerializeMldsaPrivateKey(hk.mldsaSigner->GetKey(), mldsaPriv))
        throw std::runtime_error("Failed to serialize MLDSA private key");

    // Encrypt the private components with the wallet master key.
    // Public data (secpPub, mldsaAlg) is stored in the clear, matching how
    // legacy wallet keys are stored (pubkey in the clear, secret encrypted).
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << hk.secpPriv << mldsaPriv;

    CSecret vchPlaintext((const unsigned char*)&ss[0],
                         (const unsigned char*)&ss[0] + ss.size());

    if (!EncryptSecret(const_cast<CKeyingMaterial&>(vMasterKey),
                       vchPlaintext, hk.secpPub.GetHash(),
                       disk.vchCryptedPrivate)) {
        throw std::runtime_error("Failed to encrypt hybrid key");
    }

    disk.ComputeChecksum();
    return disk;
}

bool CHybridKeyDisk::DecryptPrivate(const CKeyingMaterial& vMasterKey,
                                    CPrivKey& secpPrivOut,
                                    std::vector<unsigned char>& mldsaPrivOut) const
{
    if (!IsEncrypted()) {
        secpPrivOut  = secpPriv;
        mldsaPrivOut = mldsaPrivKey;
        return true;
    }
    if (vMasterKey.size() != WALLET_CRYPTO_KEY_SIZE)
        return false;

    CSecret vchPlaintext;
    if (!DecryptSecret(const_cast<CKeyingMaterial&>(vMasterKey),
                       vchCryptedPrivate, secpPub.GetHash(), vchPlaintext))
        return false;

    std::vector<unsigned char> plain(vchPlaintext.begin(), vchPlaintext.end());
    try {
        CDataStream ss(plain, SER_DISK, CLIENT_VERSION);
        ss >> secpPrivOut;
        ss >> mldsaPrivOut;
    } catch (const std::exception& e) {
        printf("CHybridKeyDisk::DecryptPrivate() : %s\n", e.what());
        return false;
    }
    return true;
}

// -----------------------------
// Hybrid Key Queries
// -----------------------------
bool CWallet::HaveHybridKey(const CHybridKeyID &address) const
{
    LOCK(cs_wallet);
    return mapHybridKeys.count(address) > 0 ||
           mapHybridKeyDisk.count(address) > 0;
}

bool CWallet::HaveHybridKeyByHash(const uint160& keyHash) const
{
    LOCK(cs_wallet);
    CHybridKeyID hybridID(keyHash);
    return mapHybridKeys.find(hybridID) != mapHybridKeys.end() ||
           mapHybridKeyDisk.find(hybridID) != mapHybridKeyDisk.end();
}

bool CWallet::HaveHybridKeyByLegacyID(const CKeyID& keyID) const
{
    LOCK(cs_wallet);

    for (std::map<CHybridKeyID, CHybridKey>::const_iterator it =
             mapHybridKeys.begin();
         it != mapHybridKeys.end(); ++it)
    {
        if (it->second.GetKeyID() == keyID)
            return true;
    }

    return false;
}

bool CWallet::GetHybridKey(const CHybridKeyID& hybridID,
                           CHybridKey& keyOut) const
{
    LOCK(cs_wallet);

    std::map<CHybridKeyID, CHybridKey>::const_iterator it =
        mapHybridKeys.find(hybridID);

    if (it == mapHybridKeys.end())
        return false;

    keyOut.secpPriv = it->second.secpPriv;
    keyOut.secpPub = it->second.secpPub;
    keyOut.mldsaAlg = it->second.mldsaAlg;
    keyOut.nCreateTime = it->second.nCreateTime;
    keyOut.mldsaSigner = GetSignerFromKey(it->second);

    return keyOut.mldsaSigner != NULL;
}

bool CWallet::GetHybridKeyByHash(const uint160& keyHash,
                                 CHybridKey& keyOut) const
{
    LOCK(cs_wallet);

    CHybridKeyID hybridID(keyHash);

    std::map<CHybridKeyID, CHybridKey>::const_iterator it =
        mapHybridKeys.find(hybridID);

    if (it == mapHybridKeys.end())
        return false;

    keyOut.secpPriv     = it->second.secpPriv;
    keyOut.secpPub      = it->second.secpPub;
    keyOut.mldsaAlg     = it->second.mldsaAlg;
    keyOut.nCreateTime  = it->second.nCreateTime;
    keyOut.mldsaSigner  = GetSignerFromKey(it->second);

    return keyOut.mldsaSigner != NULL;
}

// -----------------------------
// Hybrid key helpers
// -----------------------------
void GenerateHybridKey(CHybridKey& hk)
{
    CKey key;
    key.MakeNewKey(true);
    hk.secpPriv = key.GetPrivKey();
    hk.secpPub  = key.GetPubKey();

    hk.mldsaSigner = MLDSASigner::GenerateNew();
    if (!hk.mldsaSigner)
        throw std::runtime_error("Failed to generate MLDSA key");

    hk.nCreateTime = GetTime();
    hk.mldsaAlg    = "p384_mldsa65";
}

std::unique_ptr<MLDSASigner> GetSignerFromKey(const CHybridKey& hk)
{
    if (!hk.mldsaSigner)
        return nullptr;

    EVP_PKEY* pkey = hk.mldsaSigner->GetKey();
    if (!pkey)
        return nullptr;

    try {
        return std::make_unique<MLDSASigner>(pkey);
    } catch (const std::exception&) {
        return nullptr;
    }
}

// -----------------------------
// Wallet integration
// -----------------------------
CHybridKeyDisk CWallet::MakeHybridKeyDisk(const CHybridKey& hk)
{
    if (IsCrypted()) {
        if (IsLocked())
            throw std::runtime_error("wallet is locked, cannot encrypt hybrid key");
        return CHybridKeyDisk::FromMemoryEncrypted(hk, GetMasterKey());
    }
    return CHybridKeyDisk::FromMemory(hk);
}

bool LoadHybridKey(CWallet* wallet, const CHybridKeyDisk& disk,
                   const CKeyingMaterial& vMasterKey)
{
    CHybridKey mem;
    std::unique_ptr<MLDSASigner> signer;

    // ---- Validate disk ----
    if (disk.nVersion != HYBRIDKEY_DISK_VERSION &&
        disk.nVersion != HYBRIDKEY_DISK_VERSION_ENCRYPTED) {
        printf("FAIL: unsupported hybrid key disk version %u\n", disk.nVersion);
        return false;
    }
    if (disk.IsEncrypted() && !wallet->IsCrypted()) {
        printf("FAIL: encrypted hybrid key in unencrypted wallet\n");
        return false;
    }
    if (!disk.CheckChecksum()) {
        printf("FAIL: checksum mismatch\n");
        return false;
    }
    if (disk.IsEncrypted() && disk.vchCryptedPrivate.empty()) {
        printf("FAIL: empty encrypted hybrid key blob\n");
        return false;
    }
    if (!disk.IsEncrypted() && disk.mldsaPrivKey.empty()) {
        printf("FAIL: empty MLDSA private key\n");
        return false;
    }

    CPrivKey secpPriv;
    std::vector<unsigned char> mldsaPriv;
    if (!disk.DecryptPrivate(vMasterKey, secpPriv, mldsaPriv)) {
        printf("FAIL: could not decrypt hybrid key (wallet locked?)\n");
        return false;
    }

    try {
        // Deserialize secp key
        mem.nCreateTime = disk.nCreateTime;
        mem.secpPriv    = secpPriv;
        mem.secpPub     = disk.secpPub;
        mem.mldsaAlg    = disk.mldsaAlg;

        CKey key;
        if (!key.SetPrivKey(mem.secpPriv) || !key.IsValid())
            throw std::runtime_error("invalid secp private key");
        key.SetPubKey(mem.secpPub);

        // Deserialize MLDSA key
        const unsigned char* p = mldsaPriv.data();
        EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, mldsaPriv.size());
        if (!pkey)
            throw std::runtime_error("MLDSA private key decode failed");

        // Guard the reference returned by d2i_AutoPrivateKey(); the ctor
        // up_refs for each signer, the guard releases the d2i ref (also on
        // exception unwind).
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(
            pkey, &EVP_PKEY_free);

        // Construct MLDSASigner
        mem.mldsaSigner = std::make_unique<MLDSASigner>(pkey_guard.get());
        signer = std::make_unique<MLDSASigner>(pkey_guard.get());

        if (!ValidateHybridKey(mem))
            throw std::runtime_error("Hybrid key validation failed");

    } catch (const std::exception& e) {
        printf("LoadHybridKey failed: %s\n", e.what());
        return false;
    }

    // ---- Commit atomically ----
    CHybridKeyID hybridID = mem.GetHybridID();

    LOCK(wallet->cs_wallet);

    if (wallet->mapHybridKeys.count(hybridID)) {
        printf("WARNING: hybrid key %s already loaded\n", hybridID.ToString().c_str());
        return true;
    }

    wallet->mapHybridKeys.emplace(hybridID, std::move(mem));
    wallet->mapHybridSigners.emplace(hybridID, std::move(signer));

    printf("Hybrid key %s loaded successfully\n", hybridID.ToString().c_str());
    return true;
}

bool CWallet::EnsureHybridKey(const CKeyID& keyID)
{
    CHybridKeyID existingID;
    if (GetHybridKeyIDByLegacyKeyID(keyID, existingID))
        return true;

    CKey key;
    if (!GetKey(keyID, key)) return false;

    // ---- Stage 1: Build locally ----
    CHybridKey hk;
    std::unique_ptr<MLDSASigner> signer;

    try {
        hk.secpPriv = key.GetPrivKey();
        hk.secpPub  = key.GetPubKey();
        hk.nCreateTime = GetTime();
        hk.mldsaAlg = "p384_mldsa65";

        hk.mldsaSigner = MLDSASigner::GenerateNew();
        if (!hk.mldsaSigner) return false;

        if (!ValidateHybridKey(hk))
            return false;

        EVP_PKEY* pkey = hk.mldsaSigner->GetKey();
        if (!pkey) return false;

        signer = std::make_unique<MLDSASigner>(pkey);

    } catch (const std::exception& e) {
        printf("EnsureHybridKey(%s) failed: %s\n", keyID.ToString().c_str(), e.what());
        return false;
    }

    // Compute once
    CHybridKeyID hybridID = hk.GetHybridID();

    // ---- Stage 2: Persist to disk ----
    // Keys are only persisted here while we still have the plaintext copy in
    // memory (i.e. the wallet is either unencrypted or currently unlocked);
    // an encrypted-but-locked wallet cannot not encrypt new private material.
    CHybridKeyDisk disk;
    bool fDiskPersisted = false;
    if (fFileBacked && (!IsCrypted() || !IsLocked())) {
        try {
            disk = MakeHybridKeyDisk(hk);
            CWalletDB walletdb(strWalletFile);

            if (!walletdb.WriteHybridKey(hybridID, disk)) {
                printf("EnsureHybridKey(%s) DB write failed\n", keyID.ToString().c_str());
                return false;
            }
            fDiskPersisted = true;
        } catch (const std::exception& e) {
            printf("EnsureHybridKey(%s) DB exception: %s\n", keyID.ToString().c_str(), e.what());
            return false;
        }
    }

    // ---- Stage 3: Commit to memory ----
    LOCK(cs_wallet);

    mapHybridKeys.emplace(hybridID, std::move(hk));
    mapHybridSigners.emplace(hybridID, std::move(signer));

    if (fDiskPersisted && IsCrypted())
        mapHybridKeyDisk[hybridID] = disk;

    return true;
}

void NewHybridKeyPool(CWallet* wallet, int nSize)
{
    if (!wallet)
        return;

    // Private material can only be encrypted/persisted while the wallet is
    // unencrypted or unlocked.
    if (wallet->IsCrypted() && wallet->IsLocked())
        return;

    std::vector<std::pair<CHybridKeyID, CHybridKey>> stagedKeys;
    std::vector<std::pair<CHybridKeyID, CHybridKeyDisk>> stagedDisks;

    // Phase 1: Build locally
    try {
        for (int i = 0; i < nSize; ++i) {
            CHybridKey hk;
            GenerateHybridKey(hk);

            CHybridKeyID hybridID = hk.GetHybridID();
            stagedKeys.emplace_back(hk.GetHybridID(), std::move(hk));
            // MakeHybridKeyDisk encrypts at-rest records for encrypted wallets.
            stagedDisks.emplace_back(hybridID,
                                     wallet->MakeHybridKeyDisk(stagedKeys.back().second));
        }
    } catch (const std::exception& e) {
        printf("ERROR: failed to generate hybrid key pool: %s\n", e.what());
        return;
    }

    // Phase 2: Persist to DB
    {
        CWalletDB walletdb(wallet->strWalletFile);
        walletdb.TxnBegin();
        bool success = true;
        for (const auto& entry : stagedDisks) {
            if (!walletdb.WriteHybridKey(entry.first, entry.second)) {
                printf("ERROR: failed to write hybrid key to DB\n");
                success = false;
                break;
            }
        }
        if (!success) {
            walletdb.TxnAbort();
            return;
        }
        walletdb.TxnCommit();
    }

    // Phase 3: Commit to memory
    {
        LOCK(wallet->cs_wallet);
        for (auto& entry : stagedKeys) {
            wallet->mapHybridKeys.emplace(entry.first, std::move(entry.second));
        }
        if (wallet->IsCrypted()) {
            for (const auto& entry : stagedDisks) {
                wallet->mapHybridKeyDisk[entry.first] = entry.second;
            }
        }
    }
    printf("Hybrid key pool of size %d created successfully\n", nSize);
}

void CWallet::LoadHybridKeys()
{
    if (!fFileBacked) return;

    LOCK(cs_wallet);
    CWalletDB walletdb(strWalletFile);
    std::vector<std::pair<CHybridKeyID, CHybridKeyDisk>> keyDisks;

    if (!walletdb.LoadAllHybridKeys(keyDisks)) {
        printf("WARNING: failed to load hybrid keys from DB\n");
        return;
    }

    if (IsCrypted())
    {
        // Encrypted wallet: keys cannot be decrypted yet (the wallet is still
        // locked at startup). Cache the at-rest records; they are decrypted on
        // first unlock. Legacy (v2) plaintext records are also cached and are
        // migrated to the encrypted format on first unlock.
        for (const auto& entry : keyDisks)
        {
            const CHybridKeyID& hybridID = entry.first;
            const CHybridKeyDisk& disk = entry.second;

            if (!disk.CheckChecksum()) {
                printf("WARNING: skipping hybrid key %s (checksum mismatch)\n",
                       hybridID.ToString().c_str());
                continue;
            }
            mapHybridKeyDisk[hybridID] = disk;
        }
        printf("Loaded %u encrypted hybrid key(s) into key store\n",
               (unsigned)mapHybridKeyDisk.size());
        return;
    }

    for (const auto& entry : keyDisks)
    {
        if (!LoadHybridKey(this, entry.second, GetMasterKey())) {
            printf("WARNING: failed to load hybrid key %s\n",
                   entry.second.secpPub.GetID().ToString().c_str());
            continue;
        }

        // Records that arrived via the legacy on-disk layout (whose first
        // field is the stream serialization version) are rewritten using the
        // member-version layout so future startups parse them directly.
        if (entry.second.fLegacyDisk) {
            try {
                CWalletDB wdb(strWalletFile);
                if (!wdb.WriteHybridKey(entry.first, entry.second))
                    printf("WARNING: failed to migrate hybrid key %s\n",
                           entry.second.secpPub.GetID().ToString().c_str());
            } catch (const std::exception& e) {
                printf("WARNING: failed to migrate hybrid key %s: %s\n",
                       entry.second.secpPub.GetID().ToString().c_str(), e.what());
            }
        }
    }
}

bool CWallet::DecryptHybridKeys(const CKeyingMaterial& vMasterKey)
{
    LOCK(cs_wallet);

    if (!IsCrypted())
    {
        // Unencrypted wallet: all keys are already resident in memory.
        mapHybridKeyDisk.clear();
        return true;
    }
    if (IsLocked())
        return false;

    bool fOk = true;
    for (std::map<CHybridKeyID, CHybridKeyDisk>::iterator it = mapHybridKeyDisk.begin();
         it != mapHybridKeyDisk.end(); ++it)
    {
        const CHybridKeyID& hybridID = it->first;
        const CHybridKeyDisk& disk = it->second;

        if (mapHybridKeys.count(hybridID))
            continue; // already decrypted on a previous unlock

        if (!disk.CheckChecksum()) {
            printf("WARNING: hybrid key %s checksum mismatch, skipping\n",
                   hybridID.ToString().c_str());
            fOk = false;
            continue;
        }

        CHybridKey mem;
        std::unique_ptr<MLDSASigner> signer;

        try {
            CPrivKey secpPriv;
            std::vector<unsigned char> mldsaPriv;
            if (!disk.DecryptPrivate(vMasterKey, secpPriv, mldsaPriv))
                throw std::runtime_error("decrypt failed");

            mem.nCreateTime = disk.nCreateTime;
            mem.secpPriv    = secpPriv;
            mem.secpPub     = disk.secpPub;
            mem.mldsaAlg    = disk.mldsaAlg;

            CKey key;
            if (!key.SetPrivKey(mem.secpPriv) || !key.IsValid())
                throw std::runtime_error("invalid secp private key");
            key.SetPubKey(mem.secpPub);

            const unsigned char* p = mldsaPriv.data();
            EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, mldsaPriv.size());
            if (!pkey)
                throw std::runtime_error("MLDSA private key decode failed");

            mem.mldsaSigner = std::make_unique<MLDSASigner>(pkey);
            signer = std::make_unique<MLDSASigner>(pkey);
            EVP_PKEY_free(pkey);
            pkey = nullptr;

            if (!ValidateHybridKey(mem))
                throw std::runtime_error("hybrid key validation failed");
        } catch (const std::exception& e) {
            printf("WARNING: failed to decrypt hybrid key %s: %s\n",
                   hybridID.ToString().c_str(), e.what());
            fOk = false;
            continue;
        }

        // Confirm the record actually matches its declared identifier.
        if (mem.GetHybridID() != hybridID) {
            printf("WARNING: hybrid key %s does not match its record, skipping\n",
                   hybridID.ToString().c_str());
            fOk = false;
            continue;
        }

        mapHybridKeys.emplace(hybridID, std::move(mem));
        mapHybridSigners.emplace(hybridID, std::move(signer));
        setUnusedHybridKeys.insert(hybridID);

        // Migrate legacy plaintext records to the encrypted format so that
        // future unlocks (or a cold wallet.dat) no longer expose the private
        // material in the clear.
        if (!disk.IsEncrypted()) {
            try {
                CWalletDB walletdb(strWalletFile);
                CHybridKeyDisk enc = CHybridKeyDisk::FromMemoryEncrypted(
                    mapHybridKeys[hybridID], vMasterKey);
                if (!walletdb.WriteHybridKey(hybridID, enc)) {
                    printf("WARNING: failed to re-encrypt hybrid key %s\n",
                           hybridID.ToString().c_str());
                    fOk = false;
                } else {
                    mapHybridKeyDisk[hybridID] = enc;
                }
            } catch (const std::exception& e) {
                printf("WARNING: failed to re-encrypt hybrid key %s: %s\n",
                       hybridID.ToString().c_str(), e.what());
                fOk = false;
            }
        }
    }

    printf("Decrypted %u hybrid key(s) into memory\n",
           (unsigned)mapHybridKeys.size());
    return fOk;
}

// ============================================================================
// HYBRID KEY VALIDATION
// ============================================================================

bool ValidateHybridKey(const CHybridKey& hk)
{
    // ECDSA private/public key must exist
    if (hk.secpPriv.empty())
        return false;

    if (!hk.secpPub.IsValid())
        return false;

    // Phoenixcoin uses compressed public keys only
    if (hk.secpPub.Raw().size() != 33)
        return false;

    // Algorithm string
    if (hk.mldsaAlg != "p384_mldsa65")
        return false;

    // ML-DSA signer
    if (!hk.mldsaSigner)
        return false;

    EVP_PKEY* pkey = hk.mldsaSigner->GetKey();
    if (!pkey)
        return false;

    // Verify ECDSA key pair
    try
    {
        CKey key = hk.GetCKey();

        if (!key.IsValid())
            return false;

        if (key.GetPubKey() != hk.secpPub)
            return false;
    }
    catch (...)
    {
        return false;
    }

    // Creation time
    if (hk.nCreateTime <= 0)
        return false;

    return true;
}

// ============================================================================
// Hybrid Key Pool
// ============================================================================
bool CWallet::EnsureHybridKeyPool(unsigned int nTarget)
{
    LOCK(cs_wallet);

    if (IsLocked())
        return false;

    if (mapHybridKeys.size() >= nTarget)
        return true;

    CWalletDB walletdb(strWalletFile);

    while (mapHybridKeys.size() < nTarget)
    {
        CHybridKey hybridKey;

        try
        {
            GenerateHybridKey(hybridKey);

            if (!ValidateHybridKey(hybridKey))
                throw std::runtime_error("invalid hybrid key");
        }
        catch (const std::exception& e)
        {
            printf("EnsureHybridKeyPool(): %s\n", e.what());
            return false;
        }

        // Store legacy ECDSA key
        if (!AddKey(hybridKey.GetCKey()))
            return false;

        CHybridKeyID hybridID = hybridKey.GetHybridID();

        mapHybridKeys.emplace(hybridID, std::move(hybridKey));

        auto it = mapHybridKeys.find(hybridID);

        std::unique_ptr<MLDSASigner> signer =
            GetSignerFromKey(it->second);

        if (!signer)
            return false;

        mapHybridSigners.emplace(hybridID, std::move(signer));

        try {
            CHybridKeyDisk disk = MakeHybridKeyDisk(it->second);

            if (!walletdb.WriteHybridKey(hybridID, disk))
                return false;
        } catch (const std::exception& e) {
            printf("EnsureHybridKeyPool(): %s\n", e.what());
            return false;
        }

        setUnusedHybridKeys.insert(hybridID);
    }

    return true;
}

bool CWallet::RebuildUnusedHybridKeySet()
{
    LOCK(cs_wallet);

    setUnusedHybridKeys.clear();

    for (const auto& it : mapHybridKeys)
    {
        setUnusedHybridKeys.insert(it.first);
    }

    // Encrypted wallets keep at-rest records in mapHybridKeyDisk while locked;
    // include those so addresses remain allocatable (their private material is
    // decrypted on unlock).
    for (const auto& it : mapHybridKeyDisk)
    {
        setUnusedHybridKeys.insert(it.first);
    }

    return true;

    // TODO:
    // RebuildUnusedHybridKeySet() currently assumes every stored hybrid key
    // is unused after wallet restart. This may cause previously issued receive
    // addresses to be reused. Funds remain safe, but address reuse reduces
    // privacy. A persistent "used" flag should be added in a future revision.
}

bool CWallet::GetUnusedHybridKey(CHybridKeyID& hybridID)
{
    LOCK(cs_wallet);

    // Top up when running low.
    if (setUnusedHybridKeys.size() < 5)
    {
        if (!EnsureHybridKeyPool(mapHybridKeys.size() + 20))
            return false;
    }

    if (setUnusedHybridKeys.empty())
        return false;

    // Allocate the oldest unused key.
    hybridID = *setUnusedHybridKeys.begin();
    setUnusedHybridKeys.erase(setUnusedHybridKeys.begin());

    return true;
}

bool CWallet::GetHybridKeyIDByLegacyKeyID(const CKeyID& keyID,
                                          CHybridKeyID& hybridID) const
{
    LOCK(cs_wallet);

    for (std::map<CHybridKeyID, CHybridKey>::const_iterator it =
             mapHybridKeys.begin();
         it != mapHybridKeys.end(); ++it)
    {
        if (it->second.GetKeyID() == keyID)
        {
            hybridID = it->first;
            return true;
        }
    }

    return false;
}

bool CWallet::GetHybridKeyByLegacyID(const CKeyID& keyID,
                                     CHybridKey& keyOut) const
{
    CHybridKeyID hybridID;

    if (!GetHybridKeyIDByLegacyKeyID(keyID, hybridID))
        return false;

    return GetHybridKey(hybridID, keyOut);
}
