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
#include <set>
#include <string>
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
        // CDataStream::read() zero-fills on short reads instead of
        // throwing, so every scalar and variable-length field must be
        // explicitly guarded against truncation below; otherwise a
        // truncated or empty record would parse as zero-filled fields.
        int32_t nStreamVersion = 0;
        if (ss.size() < (size_t)sizeof(nStreamVersion))
            return false;
        ss >> nStreamVersion;

        CHybridKeyDisk disk;
        disk.nVersion = HYBRIDKEY_DISK_VERSION;
        if (ss.size() < (size_t)sizeof(disk.nCreateTime))
            return false;
        ss >> disk.nCreateTime;
        if (ss.size() < 1)
            return false;
        ss >> disk.secpPriv;
        if (ss.size() < 1)
            return false;
        ss >> disk.secpPub;
        if (nStreamVersion >= 2) {
            if (ss.size() < 1)
                return false;
            ss >> disk.mldsaAlg;
            if (ss.size() < 1)
                return false;
            ss >> disk.mldsaPrivKey;
        }
        if (ss.size() < (size_t)sizeof(disk.hashChecksum))
            return false;
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

// Decodes an at-rest hybrid record into a live CHybridKey without touching the
// wallet's maps. Used by the diagnostic check to prove that a record still
// derives the identifier it is stored under. Returns false and fills strError
// when the record is malformed or cannot be decrypted.
static bool MaterializeHybridKeyForCheck(const CHybridKeyDisk& disk,
                                         const CKeyingMaterial& vMasterKey,
                                         CHybridKey& out,
                                         std::string& strError)
{
    if (disk.nVersion != HYBRIDKEY_DISK_VERSION &&
        disk.nVersion != HYBRIDKEY_DISK_VERSION_ENCRYPTED) {
        strError = "unsupported hybrid key disk version";
        return false;
    }
    if (!disk.CheckChecksum()) {
        strError = "checksum mismatch";
        return false;
    }
    if (!disk.secpPub.IsValid()) {
        strError = "invalid secp256k1 public key";
        return false;
    }
    if (disk.IsEncrypted()) {
        if (disk.vchCryptedPrivate.empty()) {
            strError = "empty encrypted private blob";
            return false;
        }
    } else {
        if (disk.secpPriv.empty()) {
            strError = "missing plaintext secp256k1 private key";
            return false;
        }
        if (disk.mldsaPrivKey.empty()) {
            strError = "missing plaintext ML-DSA private key";
            return false;
        }
    }

    CPrivKey secpPriv;
    std::vector<unsigned char> mldsaPriv;
    if (!disk.DecryptPrivate(vMasterKey, secpPriv, mldsaPriv)) {
        strError = "cannot decrypt private material";
        return false;
    }

    try {
        out.nCreateTime = disk.nCreateTime;
        out.secpPriv    = secpPriv;
        out.secpPub     = disk.secpPub;
        out.mldsaAlg    = disk.mldsaAlg;

        CKey key;
        if (!key.SetPrivKey(out.secpPriv) || !key.IsValid())
            throw std::runtime_error("invalid secp256k1 private key");
        if (key.GetPubKey() != out.secpPub)
            throw std::runtime_error("secp256k1 private key does not match public key");

        const unsigned char* p = mldsaPriv.data();
        EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, mldsaPriv.size());
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(
            pkey, &EVP_PKEY_free);
        if (!pkey || p != mldsaPriv.data() + mldsaPriv.size())
            throw std::runtime_error("ML-DSA private key decode failed");

        out.mldsaSigner = std::make_unique<MLDSASigner>(pkey_guard.get());

        if (!ValidateHybridKey(out))
            throw std::runtime_error("hybrid key validation failed");
    } catch (const std::exception& e) {
        strError = e.what();
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
    // Only decrypted in-memory keys are usable. mapHybridKeyDisk holds
    // encrypted-at-rest records that are NOT spendable while the wallet is
    // locked, so they must not count as "have" for ownership queries.
    return mapHybridKeys.count(address) > 0;
}

bool CWallet::HaveHybridKeyByHash(const uint160& keyHash) const
{
    LOCK(cs_wallet);
    CHybridKeyID hybridID(keyHash);
    return mapHybridKeys.find(hybridID) != mapHybridKeys.end() ||
           mapHybridKeyDisk.find(hybridID) != mapHybridKeyDisk.end();
}

bool CWallet::FindHybridKeyByLegacyID(const CKeyID& keyID,
                                      CHybridKeyID& hybridIDOut) const
{
    LOCK(cs_wallet);

    // Correctness argument for the rebuild trigger below. The index is keyed by
    // CHybridKey::GetKeyID() (== secpPub.GetID()); the at-rest records expose
    // the same secpPub. For a key already resident in mapHybridKeys, secpPub is
    // written only while a new CHybridKey is being constructed prior to
    // insertion (hs/rpchybrid.cpp:299, hs/wallethybrid.cpp:443/513/575/728/851);
    // no code path rewrites it in place, and the one operator[] site
    // (hs/wallethybrid.cpp:740) only binds a CHybridKey to
    // FromMemoryEncrypted(const CHybridKey&, ...), which cannot mutate it. So an
    // entry's indexed value is immutable once inserted, and the index can only
    // go stale if the SET of entries changes.
    //
    // Every set change in the current code is covered: insertions go through
    // emplace() or operator[], which grow size(); the single clear()
    // (src/wallet.cpp:190) sets fHybridLegacyIndexDirty explicitly because
    // dropping to an empty map is otherwise indistinguishable from a stale
    // build. Both maps are tracked, because mapHybridKeyDisk is populated and
    // cleared independently of mapHybridKeys (load, DecryptHybridKeys, Lock).
    // Comparing sizes is therefore sufficient.
    //
    // A future change that removes a key, or replaces one key with another in a
    // single 1:1 swap, would leave size() unchanged and silently desync the
    // index. There is currently no erase() on either map. If one is added,
    // either preserve the same size by setting fHybridLegacyIndexDirty or stop
    // relying on the size comparison.
    if (fHybridLegacyIndexDirty ||
        nHybridLegacyIndexSize != mapHybridKeys.size() ||
        nHybridLegacyIndexDiskSize != mapHybridKeyDisk.size())
    {
        mapHybridKeyByLegacyID.clear();

        // Loaded keys first so a materialised, spendable record wins a tie,
        // mirroring the original scan over mapHybridKeys.
        for (std::map<CHybridKeyID, CHybridKey>::const_iterator it =
                 mapHybridKeys.begin();
             it != mapHybridKeys.end(); ++it)
        {
            // Keep the first match, mirroring the original linear scan, which
            // returned on the lowest CHybridKeyID that produced this key ID.
            mapHybridKeyByLegacyID.insert(
                std::make_pair(it->second.GetKeyID(), it->first));
        }

        // At-rest (encrypted) records carry secpPub in the clear, so they can
        // be indexed while the wallet is locked. insert() does not overwrite,
        // so a loaded entry for the same key keeps its place.
        for (std::map<CHybridKeyID, CHybridKeyDisk>::const_iterator it =
                 mapHybridKeyDisk.begin();
             it != mapHybridKeyDisk.end(); ++it)
        {
            mapHybridKeyByLegacyID.insert(
                std::make_pair(it->second.secpPub.GetID(), it->first));
        }

        nHybridLegacyIndexSize = mapHybridKeys.size();
        nHybridLegacyIndexDiskSize = mapHybridKeyDisk.size();
        fHybridLegacyIndexDirty = false;
    }

    std::map<CKeyID, CHybridKeyID>::const_iterator it =
        mapHybridKeyByLegacyID.find(keyID);
    if (it == mapHybridKeyByLegacyID.end())
        return false;

    hybridIDOut = it->second;
    return true;
}

bool CWallet::HaveHybridKeyByLegacyID(const CKeyID& keyID) const
{
    // Ownership, not spendability: true when the key is loaded OR only present
    // as an encrypted at-rest record. This mirrors HaveHybridKeyByHash() and is
    // what lets IsMine() mark a locked hybrid pubkey/multisig output
    // watch-only. Use CanSignHybridKeyByLegacyID() for the spendability gate.
    CHybridKeyID unusedHybridID;
    return FindHybridKeyByLegacyID(keyID, unusedHybridID);
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

    return keyOut.mldsaSigner != nullptr;
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

    return keyOut.mldsaSigner != nullptr;
}

// Spendability gate used by IsMine(). Mirrors exactly what GetHybridKeyByHash()
// and SignHybridTx() require, without paying for the MLDSASigner reconstruction:
// the key must live in the loaded mapHybridKeys (not only in mapHybridKeyDisk),
// and its stored signer plus underlying EVP_PKEY must be present. Kept in sync
// with GetSignerFromKey(), which additionally has to survive constructing an
// MLDSASigner from the key; that is checked in SignSignature(), which runs once
// per selected input rather than once per candidate output.
bool CWallet::CanSignHybridKeyByHash(const uint160& keyHash) const
{
    LOCK(cs_wallet);

    std::map<CHybridKeyID, CHybridKey>::const_iterator it =
        mapHybridKeys.find(CHybridKeyID(keyHash));

    if (it == mapHybridKeys.end())
        return false;

    return it->second.mldsaSigner && it->second.mldsaSigner->GetKey();
}

bool CWallet::CanSignHybridKeyByLegacyID(const CKeyID& keyID) const
{
    LOCK(cs_wallet);

    CHybridKeyID hybridID;
    if (!FindHybridKeyByLegacyID(keyID, hybridID))
        return false;

    std::map<CHybridKeyID, CHybridKey>::const_iterator it =
        mapHybridKeys.find(hybridID);

    if (it == mapHybridKeys.end())
        return false;

    return it->second.mldsaSigner && it->second.mldsaSigner->GetKey();
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

bool CWallet::StageHybridKey(CWalletDB& db, const CHybridKey& hk,
                             const CKey& ecdsa, const CHybridKeyDisk& disk,
                             const CKeyMetadata& meta,
                             const std::vector<unsigned char>& vchCryptedSecret,
                             bool fPersistLegacyKey)
{
    try {
        // The two representations must describe the same secp256k1 key. If a
        // caller ever passes mismatched halves, refuse before writing either
        // record instead of committing an inconsistent pair.
        if (!ecdsa.IsValid() || ecdsa.GetPubKey() != hk.secpPub)
            return false;
        if (ecdsa.GetPrivKey() != hk.secpPriv)
            return false;
        if (disk.secpPub != hk.secpPub)
            return false;
        if (disk.IsEncrypted() != IsCrypted())
            return false;

        if (fPersistLegacyKey &&
            !StageKeyRecord(db, ecdsa, meta, vchCryptedSecret))
            return false;

        return db.WriteHybridKey(hk.GetHybridID(), disk);
    } catch (const std::exception& e) {
        printf("StageHybridKey() : %s\n", e.what());
        return false;
    }
}

bool LoadHybridKey(CWallet* wallet, const CHybridKeyDisk& disk,
                   const CKeyingMaterial& vMasterKey)
{
    CHybridKey mem;

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

        // Guard the reference returned by d2i_AutoPrivateKey() before the
        // validity checks so a malformed or trailing-byte DER blob cannot
        // leak the handle; the ctor up_refs for each signer, the guard
        // releases the d2i ref (also on exception unwind).
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(
            pkey, &EVP_PKEY_free);

        if (!pkey || p != mldsaPriv.data() + mldsaPriv.size())
            throw std::runtime_error("MLDSA private key decode failed");

        // Construct MLDSASigner
        mem.mldsaSigner = std::make_unique<MLDSASigner>(pkey_guard.get());

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

    try {
        hk.secpPriv = key.GetPrivKey();
        hk.secpPub  = key.GetPubKey();
        hk.nCreateTime = GetTime();
        hk.mldsaAlg = "p384_mldsa65";

        hk.mldsaSigner = MLDSASigner::GenerateNew();
        if (!hk.mldsaSigner) return false;

        if (!ValidateHybridKey(hk))
            return false;

    } catch (const std::exception& e) {
        printf("EnsureHybridKey(%s) failed: %s\n", keyID.ToString().c_str(), e.what());
        return false;
    }

    // Compute once
    CHybridKeyID hybridID = hk.GetHybridID();

    // ---- Stage 2: Persist to disk ----
    // Keys are only persisted here while we still have the plaintext copy in
    // memory (i.e. the wallet is either unencrypted or currently unlocked);
    // an encrypted-but-locked wallet cannot encrypt new private material.
    //
    // Both representations are written in one transaction.  The legacy ECDSA
    // record is rewritten even when this key came from the keypool: a caller
    // may be recovering from a partial import, and reasserting the pair here
    // is what makes the invariant hold for every created hybrid key.
    CHybridKeyDisk disk;
    bool fDiskPersisted = false;
    if (fFileBacked && (!IsCrypted() || !IsLocked())) {
        try {
            disk = MakeHybridKeyDisk(hk);

            CKeyMetadata meta(hk.nCreateTime);
            {
                LOCK(cs_wallet);
                const std::map<CKeyID, CKeyMetadata>::const_iterator it =
                    mapKeyMetadata.find(keyID);
                if (it != mapKeyMetadata.end())
                    meta = it->second;
            }

            std::vector<unsigned char> vchCryptedSecret;
            if (IsCrypted() && !EncryptKeySecret(key, vchCryptedSecret))
                return false;

            CWalletDB walletdb(strWalletFile);
            if (!walletdb.TxnBegin())
                return false;

            try {
                if (!StageHybridKey(walletdb, hk, key, disk, meta,
                                    vchCryptedSecret, true))
                    throw std::runtime_error("failed to write hybrid key pair");

                if (!walletdb.TxnCommit())
                    throw std::runtime_error("failed to commit hybrid key pair");
            } catch (...) {
                walletdb.TxnAbort();
                throw;
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

    struct StagedHybridKey
    {
        CHybridKeyID hybridID;
        CHybridKey key;
        CHybridKeyDisk disk;
        CKey ecdsa;
        CKeyMetadata metadata;
        std::vector<unsigned char> cryptedSecret;
    };

    std::vector<StagedHybridKey> staged;

    // Phase 1: Build locally, including the legacy ECDSA half.
    try {
        for (int i = 0; i < nSize; ++i) {
            StagedHybridKey entry;
            GenerateHybridKey(entry.key);
            if (!ValidateHybridKey(entry.key))
                throw std::runtime_error("invalid hybrid key");

            entry.hybridID = entry.key.GetHybridID();
            entry.ecdsa = entry.key.GetCKey();
            entry.metadata = CKeyMetadata(entry.key.nCreateTime);
            if (wallet->IsCrypted() &&
                !wallet->EncryptKeySecret(entry.ecdsa, entry.cryptedSecret))
                throw std::runtime_error("failed to encrypt ECDSA key");

            // MakeHybridKeyDisk encrypts at-rest records for encrypted wallets.
            entry.disk = wallet->MakeHybridKeyDisk(entry.key);
            staged.push_back(std::move(entry));
        }
    } catch (const std::exception& e) {
        printf("ERROR: failed to generate hybrid key pool: %s\n", e.what());
        return;
    }

    // Phase 2: Persist both representations in one transaction.
    if (wallet->fFileBacked) {
        CWalletDB walletdb(wallet->strWalletFile);
        if (!walletdb.TxnBegin())
            return;

        try {
            for (const StagedHybridKey& entry : staged) {
                if (!wallet->StageHybridKey(walletdb, entry.key, entry.ecdsa,
                                            entry.disk, entry.metadata,
                                            entry.cryptedSecret, true))
                    throw std::runtime_error("failed to write hybrid key pair");
            }

            if (!walletdb.TxnCommit())
                throw std::runtime_error("failed to commit hybrid key pool");
        } catch (const std::exception& e) {
            walletdb.TxnAbort();
            printf("ERROR: failed to write hybrid key pool: %s\n", e.what());
            return;
        }
    }

    // Phase 3: Commit to memory only after the transaction commits.
    {
        LOCK(wallet->cs_wallet);
        for (StagedHybridKey& entry : staged) {
            if (wallet->IsCrypted())
                wallet->LoadCryptedKey(entry.ecdsa.GetPubKey(),
                                       entry.cryptedSecret);
            else
                wallet->LoadKey(entry.ecdsa);
            wallet->mapKeyMetadata[entry.ecdsa.GetPubKey().GetID()] =
                entry.metadata;

            wallet->mapHybridKeys.emplace(entry.hybridID,
                                          std::move(entry.key));
            if (wallet->fFileBacked && wallet->IsCrypted())
                wallet->mapHybridKeyDisk[entry.hybridID] = entry.disk;
        }
    }
    printf("Hybrid key pool of size %d created successfully\n", nSize);
}

void CWallet::LoadHybridKeys()
{
    if (!fFileBacked) return;

    LOCK(cs_wallet);
    CWalletDB walletdb(strWalletFile);

    if (!walletdb.LoadHybridUsedKeys(setUsedHybridKeys))
        printf("No recorded used-hybrid-key set; scanning wallet "
               "transactions for historically used keys\n");

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
            std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(
                pkey, &EVP_PKEY_free);
            if (!pkey || p != mldsaPriv.data() + mldsaPriv.size())
                throw std::runtime_error("MLDSA private key decode failed");

            mem.mldsaSigner = std::make_unique<MLDSASigner>(pkey);

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
        if (!setUsedHybridKeys.count(hybridID))
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

    // Build every key and encrypt the private material that has to be stored
    // before opening a database transaction.  The whole top-up then commits as
    // one unit: a failure at any write leaves neither the hybrid records nor
    // their legacy ECDSA keys behind.
    struct StagedHybridKey
    {
        CHybridKeyID hybridID;
        CHybridKey key;
        CHybridKeyDisk disk;
        CKey ecdsa;
        CKeyMetadata metadata;
        std::vector<unsigned char> cryptedSecret;
        bool fPersistKey = false;
    };

    std::vector<StagedHybridKey> staged;
    try
    {
        while (mapHybridKeys.size() + staged.size() < nTarget)
        {
            StagedHybridKey entry;
            GenerateHybridKey(entry.key);

            if (!ValidateHybridKey(entry.key))
                throw std::runtime_error("invalid hybrid key");

            entry.hybridID = entry.key.GetHybridID();
            entry.ecdsa = entry.key.GetCKey();
            entry.metadata = CKeyMetadata(entry.key.nCreateTime);

            // Recover from a partially imported key by reusing an ECDSA half
            // that is already present instead of failing the whole top-up.
            const CKeyID keyID = entry.ecdsa.GetPubKey().GetID();
            entry.fPersistKey = !HaveKey(keyID);
            if (entry.fPersistKey && IsCrypted() &&
                !EncryptKeySecret(entry.ecdsa, entry.cryptedSecret))
                throw std::runtime_error("failed to encrypt ECDSA key");

            entry.disk = MakeHybridKeyDisk(entry.key);
            staged.push_back(std::move(entry));
        }
    }
    catch (const std::exception& e)
    {
        printf("EnsureHybridKeyPool(): %s\n", e.what());
        return false;
    }

    // Persist in one database transaction when the wallet is file-backed.
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        if (!walletdb.TxnBegin())
            return false;

        try
        {
            for (const StagedHybridKey& entry : staged)
            {
                if (!StageHybridKey(walletdb, entry.key, entry.ecdsa,
                                    entry.disk, entry.metadata,
                                    entry.cryptedSecret, entry.fPersistKey))
                    throw std::runtime_error("failed to write hybrid key pair");
            }

            if (!walletdb.TxnCommit())
                throw std::runtime_error("failed to commit hybrid key pool");
        }
        catch (const std::exception& e)
        {
            walletdb.TxnAbort();
            printf("EnsureHybridKeyPool(): %s\n", e.what());
            return false;
        }
    }

    // Register in memory only after the transaction commits.
    for (StagedHybridKey& entry : staged)
    {
        if (entry.fPersistKey)
        {
            if (IsCrypted())
                LoadCryptedKey(entry.ecdsa.GetPubKey(), entry.cryptedSecret);
            else
                LoadKey(entry.ecdsa);
            mapKeyMetadata[entry.ecdsa.GetPubKey().GetID()] = entry.metadata;
        }

        const CHybridKeyID hybridID = entry.hybridID;
        mapHybridKeys.emplace(hybridID, std::move(entry.key));
        if (fFileBacked && IsCrypted())
            mapHybridKeyDisk[hybridID] = entry.disk;
        setUnusedHybridKeys.insert(hybridID);
    }

    return true;
}

bool CWallet::CheckHybridKeys(CHybridKeyCheckResult& result, bool fDeep) const
{
    LOCK(cs_wallet);

    result = CHybridKeyCheckResult();
    result.fCrypted = IsCrypted();
    result.fLocked = IsLocked();
    result.fDeepVerified = fDeep;
    result.nHybridKeys = (unsigned int)mapHybridKeys.size();
    result.nHybridDiskRecords = (unsigned int)mapHybridKeyDisk.size();

    {
        std::set<CKeyID> legacyKeys;
        GetKeys(legacyKeys);
        result.nLegacyKeys = (unsigned int)legacyKeys.size();
    }

    // The same underlying problem can be reached from the loaded key, the
    // at-rest cache and the database scan. Keep the report readable.
    std::set<std::string> seenIssues;
    const auto addIssue = [&result, &seenIssues](
        const CHybridKeyID& hybridID, const CKeyID& legacyID,
        const std::string& problem)
    {
        CHybridKeyCheckIssue issue;
        if (hybridID != CHybridKeyID())
            issue.strHybridID = hybridID.ToString();
        if (legacyID != CKeyID())
            issue.strLegacyID = legacyID.ToString();
        issue.strProblem = problem;

        const std::string key = issue.strHybridID + "|" + issue.strLegacyID +
                                "|" + issue.strProblem;
        if (seenIssues.insert(key).second)
            result.vIssues.push_back(issue);
    };

    // Confirms that the legacy keystore has the ECDSA half and that its
    // public key is exactly the one embedded in the hybrid key.  This is the
    // check that would have caught the importhybridkey regression.
    const auto checkLegacyRecord = [this, &addIssue](
        const CHybridKeyID& hybridID, const CPubKey& secpPub,
        const std::string& context) -> CKeyID
    {
        if (!secpPub.IsValid()) {
            addIssue(hybridID, CKeyID(),
                     context + ": invalid secp256k1 public key");
            return CKeyID();
        }

        const CKeyID legacyID = secpPub.GetID();
        if (!HaveKey(legacyID)) {
            addIssue(hybridID, legacyID,
                     context + ": legacy ECDSA key record is missing");
            return legacyID;
        }

        CPubKey storedPub;
        if (!GetPubKey(legacyID, storedPub))
            addIssue(hybridID, legacyID,
                     context + ": cannot read the legacy ECDSA public key");
        else if (storedPub != secpPub)
            addIssue(hybridID, legacyID,
                     context + ": legacy ECDSA public key does not match "
                               "the hybrid key");

        return legacyID;
    };

    // Loaded hybrid keys (unencrypted wallets, or encrypted wallets after
    // unlock): both halves must be live and carry the same private material.
    for (const auto& entry : mapHybridKeys)
    {
        const CHybridKeyID& hybridID = entry.first;
        const CHybridKey& hk = entry.second;

        const CKeyID legacyID =
            checkLegacyRecord(hybridID, hk.secpPub, "loaded hybrid key");

        if (!hk.mldsaSigner || !hk.mldsaSigner->GetKey())
            addIssue(hybridID, legacyID,
                     "loaded hybrid key has no ML-DSA signer");

        if (hk.secpPriv.empty()) {
            addIssue(hybridID, legacyID,
                     "loaded hybrid key has no secp256k1 private key");
        } else {
            try {
                CKey derived = hk.GetCKey();
                if (derived.GetPubKey() != hk.secpPub)
                    addIssue(hybridID, legacyID,
                             "loaded hybrid key contains mismatched "
                             "secp256k1 halves");
            } catch (const std::exception&) {
                addIssue(hybridID, legacyID,
                         "loaded hybrid key contains an invalid "
                         "secp256k1 key pair");
            }
        }

        if (!result.fLocked)
        {
            CKey ecdsa;
            if (!GetKey(legacyID, ecdsa)) {
                addIssue(hybridID, legacyID,
                         "legacy ECDSA private key is not available");
            } else {
                if (ecdsa.GetPubKey() != hk.secpPub)
                    addIssue(hybridID, legacyID,
                             "legacy ECDSA public key does not match the "
                             "loaded hybrid key");
                if (ecdsa.GetPrivKey() != hk.secpPriv)
                    addIssue(hybridID, legacyID,
                             "legacy ECDSA private key does not match the "
                             "loaded hybrid key");
            }
        }

        try {
            if (hk.GetHybridID() != hybridID)
                addIssue(hybridID, legacyID,
                         "loaded hybrid key does not derive its record ID");
        } catch (const std::exception&) {
            addIssue(hybridID, legacyID,
                     "cannot derive the loaded hybrid key ID");
        }
    }

    const auto checkDiskRecord = [this, &result, &addIssue, fDeep,
                                  &checkLegacyRecord](
        const CHybridKeyID& hybridID, const CHybridKeyDisk& disk,
        const std::string& context, bool fFromDatabase)
    {
        const CKeyID legacyID = disk.secpPub.IsValid()
                                    ? disk.secpPub.GetID()
                                    : CKeyID();

        if (!disk.CheckChecksum())
            addIssue(hybridID, legacyID, context + ": checksum mismatch");
        if (!disk.secpPub.IsValid())
            addIssue(hybridID, legacyID,
                     context + ": invalid secp256k1 public key");
        else
            checkLegacyRecord(hybridID, disk.secpPub, context);

        if (disk.IsEncrypted())
        {
            if (!result.fCrypted)
                addIssue(hybridID, legacyID,
                         context + ": encrypted hybrid record in an "
                                   "unencrypted wallet");
            if (disk.vchCryptedPrivate.empty())
                addIssue(hybridID, legacyID,
                         context + ": empty encrypted private key blob");
            if (!disk.secpPriv.empty())
                addIssue(hybridID, legacyID,
                         context + ": encrypted hybrid record contains a "
                                   "plaintext secp256k1 private key");
            if (!disk.mldsaPrivKey.empty())
                addIssue(hybridID, legacyID,
                         context + ": encrypted hybrid record contains a "
                                   "plaintext ML-DSA private key");
        }
        else
        {
            if (result.fCrypted)
                addIssue(hybridID, legacyID,
                         context + ": plaintext hybrid record in an "
                                   "encrypted wallet");
            if (disk.secpPriv.empty())
                addIssue(hybridID, legacyID,
                         context + ": plaintext hybrid record has no "
                                   "secp256k1 private key");
            if (disk.mldsaPrivKey.empty())
                addIssue(hybridID, legacyID,
                         context + ": plaintext hybrid record has no "
                                   "ML-DSA private key");
        }

        const auto loaded = mapHybridKeys.find(hybridID);
        if (loaded != mapHybridKeys.end())
        {
            if (loaded->second.secpPub != disk.secpPub)
                addIssue(hybridID, legacyID,
                         context + ": secp256k1 public key differs from the "
                                   "loaded hybrid key");
            if (!disk.IsEncrypted() &&
                loaded->second.secpPriv != disk.secpPriv)
                addIssue(hybridID, legacyID,
                         context + ": secp256k1 private key differs from the "
                                   "loaded hybrid key");
            if (loaded->second.nCreateTime != disk.nCreateTime)
                addIssue(hybridID, legacyID,
                         context + ": creation time differs from the loaded "
                                   "hybrid key");
        }

        const auto cached = mapHybridKeyDisk.find(hybridID);
        if (fFromDatabase && cached != mapHybridKeyDisk.end())
        {
            if (cached->second.secpPub != disk.secpPub)
                addIssue(hybridID, legacyID,
                         context + ": secp256k1 public key differs from the "
                                   "cached at-rest record");
            if (cached->second.nVersion != disk.nVersion)
                addIssue(hybridID, legacyID,
                         context + ": disk version differs from the cached "
                                   "at-rest record");
            if (cached->second.hashChecksum != disk.hashChecksum)
                addIssue(hybridID, legacyID,
                         context + ": checksum differs from the cached "
                                   "at-rest record");
        }

        const bool fCanVerifyMaterial =
            !disk.IsEncrypted() || (result.fCrypted && !result.fLocked);
        if (fDeep && fCanVerifyMaterial)
        {
            CHybridKey materialized;
            std::string error;
            if (!MaterializeHybridKeyForCheck(disk, GetMasterKey(),
                                              materialized, error))
            {
                addIssue(hybridID, legacyID,
                         context + ": cannot materialize: " + error);
            }
            else
            {
                if (materialized.GetKeyID() != legacyID)
                    addIssue(hybridID, legacyID,
                             context + ": materialized legacy ECDSA key ID "
                                       "does not match the record");

                try {
                    if (materialized.GetHybridID() != hybridID)
                        addIssue(hybridID, legacyID,
                                 context + ": record ID does not match the "
                                           "materialized hybrid key");
                } catch (const std::exception&) {
                    addIssue(hybridID, legacyID,
                             "cannot derive the materialized hybrid key ID");
                }

                if (loaded != mapHybridKeys.end())
                {
                    if (materialized.secpPub != loaded->second.secpPub)
                        addIssue(hybridID, legacyID,
                                 context + ": materialized public key differs "
                                           "from the loaded hybrid key");
                    if (materialized.secpPriv != loaded->second.secpPriv)
                        addIssue(hybridID, legacyID,
                                 context + ": materialized private key differs "
                                           "from the loaded hybrid key");
                }
            }
        }
        else if (fDeep && disk.IsEncrypted() && result.fLocked)
        {
            result.fDeepVerified = false;
        }
    };

    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        std::vector<std::pair<CHybridKeyID, CHybridKeyDisk> > records;
        std::vector<std::string> malformed;

        if (!walletdb.LoadAllHybridKeys(records, &malformed))
        {
            addIssue(CHybridKeyID(), CKeyID(),
                     "cannot read hybrid key records from the wallet database");
        }
        else
        {
            result.nHybridRecordsInDatabase =
                (unsigned int)(records.size() + malformed.size());

            for (const std::string& id : malformed)
                addIssue(CHybridKeyID(), CKeyID(),
                         "unreadable hybrid key record " + id);

            std::set<CHybridKeyID> dbIDs;
            for (const auto& entry : records)
            {
                dbIDs.insert(entry.first);
                checkDiskRecord(entry.first, entry.second,
                                "database hybrid record", true);

                if (!mapHybridKeys.count(entry.first) &&
                    !mapHybridKeyDisk.count(entry.first))
                    addIssue(entry.first, entry.second.secpPub.GetID(),
                             "database hybrid record was not loaded into "
                             "memory");
            }

            for (const auto& entry : mapHybridKeys)
                if (!dbIDs.count(entry.first))
                    addIssue(entry.first, entry.second.GetKeyID(),
                             "loaded hybrid key has no database record");

            for (const auto& entry : mapHybridKeyDisk)
                if (!dbIDs.count(entry.first))
                    addIssue(entry.first, entry.second.secpPub.GetID(),
                             "cached at-rest hybrid key has no database record");
        }
    }
    else
    {
        for (const auto& entry : mapHybridKeyDisk)
            checkDiskRecord(entry.first, entry.second,
                            "at-rest hybrid record", false);
    }

    if (!result.fCrypted && !mapHybridKeyDisk.empty())
        addIssue(CHybridKeyID(), CKeyID(),
                 "unencrypted wallet holds at-rest hybrid key records");
    if (result.fCrypted && result.fLocked && !mapHybridKeys.empty())
        addIssue(CHybridKeyID(), CKeyID(),
                 "locked wallet has decrypted hybrid keys in memory");

    result.fOK = result.vIssues.empty();
    return result.fOK;
}

bool CWallet::RebuildUnusedHybridKeySet()
{
    LOCK(cs_wallet);

    setUnusedHybridKeys.clear();

    // Keys that were allocated as receive/change addresses in the past are
    // excluded so that previously issued addresses are never reused after a
    // wallet restart.
    for (const auto& it : mapHybridKeys)
    {
        if (!setUsedHybridKeys.count(it.first))
            setUnusedHybridKeys.insert(it.first);
    }

    // Encrypted wallets keep at-rest records in mapHybridKeyDisk while locked;
    // include those so addresses remain allocatable (their private material is
    // decrypted on unlock).
    for (const auto& it : mapHybridKeyDisk)
    {
        if (!setUsedHybridKeys.count(it.first))
            setUnusedHybridKeys.insert(it.first);
    }

    return true;
}

// Scans the wallet's own transactions and address book for hybrid keys that
// have been used as receive/change addresses in the past and records them in
// setUsedHybridKeys so they are never issued again after a restart.
void CWallet::BackfillHybridUsedKeys()
{
    LOCK(cs_wallet);

    bool fChanged = false;

    // One-time CKeyID -> CHybridKeyID index. The scan below visits every output
    // of every wallet transaction; probing each legacy-address output against
    // the key maps with a linear scan (and a Hash160 per candidate) is quadratic
    // and dominates wallet load once the pool holds thousands of keys. The
    // at-rest (encrypted) records carry secpPub in the clear, so they can be
    // indexed even while the wallet is locked. mapHybridKeys entries are
    // inserted first so they win on a tie, mirroring the original scan order.
    std::map<CKeyID, CHybridKeyID> mapLegacyToHybrid;
    for (std::map<CHybridKeyID, CHybridKey>::const_iterator hk =
             mapHybridKeys.begin();
         hk != mapHybridKeys.end(); ++hk)
    {
        mapLegacyToHybrid.insert(std::make_pair(hk->second.GetKeyID(), hk->first));
    }
    for (std::map<CHybridKeyID, CHybridKeyDisk>::const_iterator dk =
             mapHybridKeyDisk.begin();
         dk != mapHybridKeyDisk.end(); ++dk)
    {
        mapLegacyToHybrid.insert(std::make_pair(dk->second.secpPub.GetID(), dk->first));
    }

    for (std::map<CHybridKeyID, CHybridAddressEntry>::const_iterator it =
             mapHybridAddressBook.begin();
         it != mapHybridAddressBook.end(); ++it)
    {
        if (setUsedHybridKeys.insert(it->first).second)
            fChanged = true;
    }

    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin();
         it != mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = it->second;
        for (unsigned int i = 0; i < wtx.vout.size(); ++i)
        {
            CTxDestination dest;
            if (!ExtractDestination(wtx.vout[i].scriptPubKey, dest))
                continue;

            CHybridKeyID hybridID;
            bool fFound = false;

            if (const CHybridKeyID* pHybridID = std::get_if<CHybridKeyID>(&dest))
            {
                hybridID = *pHybridID;
                fFound = true;
            }
            else if (const CKeyID* pKeyID = std::get_if<CKeyID>(&dest))
            {
                // A payment made to the legacy (secp) address of a hybrid key.
                // Match by the embedded public key via the index built above.
                std::map<CKeyID, CHybridKeyID>::const_iterator lt =
                    mapLegacyToHybrid.find(*pKeyID);
                if (lt != mapLegacyToHybrid.end())
                {
                    hybridID = lt->second;
                    fFound = true;
                }
            }

            if (fFound && (mapHybridKeys.count(hybridID) ||
                           mapHybridKeyDisk.count(hybridID)))
            {
                if (setUsedHybridKeys.insert(hybridID).second)
                    fChanged = true;
            }
        }
    }

    if (fChanged && fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        if (!walletdb.WriteHybridUsedKeys(setUsedHybridKeys))
            printf("WARNING: failed to persist backfilled used-hybrid-key set\n");
    }
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

    // Persist usage so the address is never issued again after a restart.
    const bool fWasUsed = setUsedHybridKeys.count(hybridID) != 0;
    setUsedHybridKeys.insert(hybridID);

    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        if (!walletdb.WriteHybridUsedKeys(setUsedHybridKeys))
        {
            printf("WARNING: failed to persist used-hybrid-key set\n");

            // Roll back the in-memory allocation because persistence failed.
            if (!fWasUsed)
                setUsedHybridKeys.erase(hybridID);

            setUnusedHybridKeys.insert(hybridID);
            return false;
        }
    }

    return true;
}

bool CWallet::GetHybridKeyIDByLegacyKeyID(const CKeyID& keyID,
                                          CHybridKeyID& hybridID) const
{
    // FindHybridKeyByLegacyID() now also covers the at-rest mapHybridKeyDisk
    // records, but this entry point keeps its original loaded-only contract:
    // callers use the returned ID to build a hybrid script or decide the key is
    // already usable, which requires the CHybridKey to be materialised. Only
    // return an ID whose key is resident in mapHybridKeys.
    if (!FindHybridKeyByLegacyID(keyID, hybridID))
        return false;

    LOCK(cs_wallet);
    return mapHybridKeys.count(hybridID) > 0;
}

bool CWallet::GetHybridKeyByLegacyID(const CKeyID& keyID,
                                     CHybridKey& keyOut) const
{
    CHybridKeyID hybridID;

    if (!GetHybridKeyIDByLegacyKeyID(keyID, hybridID))
        return false;

    return GetHybridKey(hybridID, keyOut);
}
