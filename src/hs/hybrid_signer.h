// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef HYBRID_SIGNER_H
#define HYBRID_SIGNER_H

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>

#include <openssl/opensslv.h>
#include <openssl/evp.h>

#include "key.h"

/* ------------------------------------------------------------------------- */
/* Serialization format constants                                            */
/* ------------------------------------------------------------------------- */

static constexpr uint8_t HYBRID_MAGIC[4] = { 'H','Y','B','K' };

static constexpr uint8_t HYBRID_VERSION       = 2;
static constexpr uint8_t HYBRID_VERSION_ENC   = 3;

static constexpr uint8_t HYBRID_SIG_MAGIC[4] = {'H','Y','B','S'};

static constexpr uint8_t HYBRIDKEY_DISK_VERSION = 2;
static constexpr uint8_t HYBRID_SIG_VERSION = 1;

/* Encrypted key serialization parameters (v3) */
static constexpr size_t ENC_SALT_LEN  = 16;
static constexpr size_t ENC_NONCE_LEN = 12;
static constexpr size_t ENC_TAG_LEN   = 16;

/* ------------------------------------------------------------------------- */
/*  Requirements                                                             */
/* ------------------------------------------------------------------------- */

// ML-DSA support landed in OpenSSL 3.5
#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "Hybrid signatures require OpenSSL 3.5+ (ML-DSA support)"
#endif

/* ------------------------------------------------------------------------- */
/*  Signature Types                                                          */
/* ------------------------------------------------------------------------- */

enum class SigAlg : uint8_t {
    ECDSA_SECP256K1 = 0x01,
    ML_DSA_65 = 0x02,
};

struct Signature {
    SigAlg alg;
    std::vector<uint8_t> bytes;
};

/* ------------------------------------------------------------------------- */
/*  Abstract Signer Interface                                                */
/* ------------------------------------------------------------------------- */

// A signer signs and verifies EXACT bytes.
// Hashing, domain separation, etc. are handled internally.
class ISigner {
public:
    virtual ~ISigner() = default;

    virtual SigAlg Algorithm() const = 0;

    virtual bool Sign(const std::vector<uint8_t>& msg,
                      std::vector<uint8_t>& sig) const = 0;

    virtual bool Verify(const std::vector<uint8_t>& msg,
                        const std::vector<uint8_t>& sig) const = 0;

    virtual std::vector<uint8_t> GetPublicKey() const = 0;

    // Optional: only implemented by PQ signers
    virtual std::vector<uint8_t> SerializePrivateKey() const {
        return {};
    }

    /* Encrypted private-key serialization (recommended) */
    virtual std::vector<uint8_t>
    SerializePrivateKeyEncrypted(
        const std::vector<uint8_t>& /*password*/) const {
        return {};
    }
};

/* ------------------------------------------------------------------------- */
/*  secp256k1 (Bitcoin) Signer                                               */
/* ------------------------------------------------------------------------- */

// Uses Bitcoin Core's CKey internally.
// Signs HASH256(msg) using ECDSA/secp256k1.
class Secp256k1Signer final : public ISigner {
public:
    explicit Secp256k1Signer(const CKey& key);

    SigAlg Algorithm() const override;

    bool Sign(const std::vector<uint8_t>& msg,
              std::vector<uint8_t>& sig) const override;

    bool Verify(const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& sig) const override;

    std::vector<uint8_t> GetPublicKey() const override;

private:
    CKey key_;
};

/* ------------------------------------------------------------------------- */
/*  ML-DSA (Dilithium-65) Signer                                             */
/* ------------------------------------------------------------------------- */

// Owns an EVP_PKEY (raw ML-DSA key).
class MLDSASigner final : public ISigner {
public:
    explicit MLDSASigner(EVP_PKEY* key);
    ~MLDSASigner() override;

    EVP_PKEY* GetKey() const { return pkey_; }

    MLDSASigner(const MLDSASigner&) = delete;
    MLDSASigner& operator=(const MLDSASigner&) = delete;

    SigAlg Algorithm() const override;

    bool Sign(const std::vector<uint8_t>& msg,
              std::vector<uint8_t>& sig) const override;

    bool Verify(const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& sig) const override;

    std::vector<uint8_t> GetPublicKey() const override;

    std::vector<uint8_t> SerializePrivateKey() const override;

    std::vector<uint8_t>
    SerializePrivateKeyEncrypted(
        const std::vector<uint8_t>& password) const override;

    static std::unique_ptr<MLDSASigner>
    FromSerialized(const std::vector<uint8_t>& in);

    static std::unique_ptr<MLDSASigner>
    FromSerializedV2(const std::vector<uint8_t>& in);

    static std::unique_ptr<MLDSASigner>
    FromEncryptedSerialized(
        const std::vector<uint8_t>& password,
        const std::vector<uint8_t>& in);

    static std::unique_ptr<MLDSASigner> GenerateNew();

private:
    EVP_PKEY* pkey_;
};

/* ------------------------------------------------------------------------- */
/*  Hybrid Signer                                                            */
/* ------------------------------------------------------------------------- */

// Coordinates multiple signers over the SAME message.
class HybridSigner {
public:
    void Add(std::unique_ptr<ISigner> signer);

    // Signs the same message with all signers
    bool SignAll(const std::vector<uint8_t>& msg,
                 std::vector<Signature>& sigs) const;

    bool VerifyAll(const std::vector<uint8_t>& msg,
                   const std::vector<Signature>& sigs) const;

    std::vector<std::vector<uint8_t>> SerializePrivateKeys() const;

private:
    std::vector<std::unique_ptr<ISigner>> signers_;
};

/* ------------------------------------------------------------------------- */
/*  Hybrid Message Construction                                              */
/* ------------------------------------------------------------------------- */

// Canonical message builder for hybrid signatures.
// Takes the complete sighash preimage produced by the transaction
// sighash construction, including SIGHASH type.
// Prepends "BIT-HYBRID-SIG-v1" for cryptographic domain separation.
// MUST be used by callers before SignAll().
extern std::vector<uint8_t>
BuildHybridMessage(const std::vector<uint8_t>& tx_sighash_preimage);

#endif  // HYBRID_SIGNER_H
