// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef WALLETHYBRID_H
#define WALLETHYBRID_H

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <stdexcept>

#include "key.h"
#include "serialize.h"
#include "uint256.h"
#include "sync.h"
#include "crypter.h"
#include "hs/hybrid_signer.h"

class CWallet;
class CKeyID;

// -----------------------------
// Hybrid key versions
// -----------------------------
enum HybridKeyVersion : uint8_t {
    HYBRIDKEY_V1 = 1,  // legacy (seed-based MLDSA)
};

// CHybridKeyDisk nVersion values:
//   2 = legacy plaintext format (secpPriv + mldsaPrivKey in the clear).
//   3 = encrypted format: private material is AES-CBC encrypted with the
//       wallet master key and stored in CHybridKeyDisk::vchCryptedPrivate.
static constexpr uint8_t HYBRIDKEY_DISK_VERSION_ENCRYPTED = 3;

// -----------------------------
// In-memory representation
// -----------------------------
struct CHybridKey
{
    CPrivKey secpPriv;
    CPubKey  secpPub;

    std::string mldsaAlg;
    std::unique_ptr<MLDSASigner> mldsaSigner;

    int64_t nCreateTime = 0;

    CHybridKey() = default;

    // Legacy ECDSA identifier
    CKeyID GetKeyID() const
    {
        return secpPub.GetID();
    }

    // Native Hybrid identifier
    CHybridKeyID GetHybridID() const
    {
        if (!mldsaSigner)
            throw std::runtime_error("Hybrid key has no MLDSA signer");

        std::vector<unsigned char> blob;

        std::vector<unsigned char> secp = secpPub.Raw();
        std::vector<unsigned char> ml   = mldsaSigner->GetPublicKey();

        blob.insert(blob.end(), secp.begin(), secp.end());
        blob.insert(blob.end(), ml.begin(), ml.end());

        return CHybridKeyID(Hash160(blob));
    }

    CKey GetCKey() const
    {
        CKey key;
        if (!key.SetPrivKey(secpPriv))
            throw std::runtime_error("Invalid secp key");
        key.SetPubKey(secpPub);
        return key;
    }
};

// -----------------------------
// On-disk representation
// -----------------------------
class CHybridKeyDisk
{
public:
    uint8_t  nVersion = 2;      // wallet serialization version
    int32_t  nCreateTime = 0;

    // secp256k1
    CPrivKey secpPriv;                       // plaintext form (v1/v2 only)
    CPubKey  secpPub;

    // MLDSA
    std::string mldsaAlg;
    std::vector<unsigned char> mldsaPrivKey; // DER-encoded EVP_PKEY (v2 plaintext)

    // v3 (encrypted wallets) only: AES-256-CBC (generic IV = Hash256(secpPub),
    // key = wallet master key) of a serialized (secpPriv, mldsaPrivKey) tuple.
    std::vector<unsigned char> vchCryptedPrivate;

    uint256 hashChecksum;

    bool fLegacyDisk = false;   // non-serialized: parsed from the old
                                // (pre-v3-format) on-disk layout

    bool IsEncrypted() const
    {
        return nVersion >= HYBRIDKEY_DISK_VERSION_ENCRYPTED;
    }

    // Attempts to parse a record stored with the original wallet layout
    // (first field is the embed-serialization version, i.e. CLIENT_VERSION).
    // Returns false if the stream does not contain a legacy record.
    static bool FromLegacyDiskFormat(CDataStream& ss, CHybridKeyDisk& out);

    void ComputeChecksum();
    bool CheckChecksum() const;
    static CHybridKeyDisk FromMemory(const CHybridKey& hk);
    static CHybridKeyDisk FromMemoryEncrypted(const CHybridKey& hk,
                                              const CKeyingMaterial& vMasterKey);
    bool DecryptPrivate(const CKeyingMaterial& vMasterKey,
                        CPrivKey& secpPrivOut,
                        std::vector<unsigned char>& mldsaPrivOut) const;

    // All layout decisions branch on the member nVersion (serialized as the
    // FIRST field), never on the stream's serialization version.
    IMPLEMENT_SERIALIZE(
        READWRITE(this->nVersion);
        READWRITE(this->nCreateTime);

        if (this->nVersion >= HYBRIDKEY_DISK_VERSION_ENCRYPTED) {
            READWRITE(this->secpPub);
            READWRITE(this->mldsaAlg);
            READWRITE(this->vchCryptedPrivate);
        } else {
            // legacy plaintext layout
            READWRITE(this->secpPriv);
            READWRITE(this->secpPub);
            if (this->nVersion >= 2) {
                READWRITE(this->mldsaAlg);
                READWRITE(this->mldsaPrivKey);
            }
        }

        READWRITE(this->hashChecksum);
    )
};

// -----------------------------
// Hybrid key helpers
// -----------------------------
void GenerateHybridKey(CHybridKey& hk);
std::unique_ptr<MLDSASigner> GetSignerFromKey(const CHybridKey& hk);

// -----------------------------
// Wallet integration
// -----------------------------
bool LoadHybridKey(class CWallet* wallet, const CHybridKeyDisk& disk,
                   const CKeyingMaterial& vMasterKey);
void NewHybridKeyPool(class CWallet* wallet, int nSize);

bool ValidateHybridKey(const CHybridKey& hk);

#endif  // WALLETHYBRID_H
