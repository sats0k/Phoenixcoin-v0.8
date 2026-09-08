// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef HYBRID_VERIFY_H
#define HYBRID_VERIFY_H

#pragma once

#include <vector>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "hybrid_script.h"
#include "../uint256.h"
#include "../script.h"


/**
 * ML-DSA-65 Signature Verification
 *
 * Provides ML-DSA-65 public-key signature verification using the
 * OpenSSL 3.x EVP interface.
 *
 * PhoenixCoin Quantum uses ML-DSA-65 together with ECDSA in its
 * hybrid signature scheme. This function verifies only the ML-DSA
 * portion of a hybrid signature; consensus validation requires both
 * ECDSA and ML-DSA signatures to succeed.
 *
 * Requires OpenSSL with ML-DSA-65 support enabled.
 */

// ============================================================================
// ML-DSA SIGNATURE VERIFICATION
// ============================================================================

/**
 * Verify an ML-DSA-65 signature.
 *
 * Verifies a raw ML-DSA-65 signature against the supplied message and
 * raw ML-DSA-65 public key using OpenSSL's EVP_PKEY API.
 *
 * Parameters:
 *   mldsaSig
 *       Raw ML-DSA-65 signature bytes.
 *
 *   mldsaPubKey
 *       Raw ML-DSA-65 public key bytes.
 *
 *   msg
 *       Message bytes to verify. For hybrid transaction validation this
 *       is the domain-separated hybrid message derived from the
 *       transaction sighash.
 *
 * Returns:
 *   true  - signature verified successfully.
 *   false - verification failed or an error occurred.
 *
 * Notes:
 *   - This function validates only the ML-DSA component.
 *   - Hybrid consensus validation additionally requires successful
 *     ECDSA verification.
 *   - Requires OpenSSL with ML-DSA-65 support.
 */
inline bool VerifyMLDSA(
    const std::vector<unsigned char>& mldsaSig,
    const std::vector<unsigned char>& mldsaPubKey,
    const std::vector<unsigned char>& msg)
{

    if (mldsaSig.size() != ML_DSA_65_SIG_SIZE - 1)
        return false;

    if (mldsaPubKey.size() != ML_DSA_65_PUBKEY_SIZE)
        return false;

    if (msg.empty())
        return false;

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key_ex(
        nullptr,
        "ML-DSA-65",
        nullptr,
        mldsaPubKey.data(),
        mldsaPubKey.size());

    if (!pkey)
        return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    const bool ok =
        EVP_DigestVerify(
            ctx,
            mldsaSig.data(),
            mldsaSig.size(),
            msg.data(),
            msg.size()) == 1;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ok;
}

// ============================================================================
// HYBRID SIGNATURE VERIFICATION
// ============================================================================

// Forward declarations
//class CScript;
//class CTransaction;

/**
 * Forward declaration for CheckSig from script.cpp
 * Verifies ECDSA secp256k1 signatures
 */
extern bool CheckSig(
    const std::vector<unsigned char>& vchSig,
    const std::vector<unsigned char>& vchPubKey,
    const CScript& scriptCode,
    const CTransaction& txTo,
    unsigned int nIn,
    int nHashType,
    const uint256* precomputedSighash = NULL
);

/**
 * Forward declaration for BuildHybridMessage from hybrid_signer.cpp
 * Creates domain-separated message for hybrid signatures
 */
extern std::vector<unsigned char> BuildHybridMessage(
    const std::vector<unsigned char>& tx_sighash_preimage
);

/**
 * Forward declaration for SignatureHash from script.cpp
 * Computes transaction signature hash
 * Note: defined in script.cpp, takes CScript by value
 */
extern uint256 SignatureHash(
    CScript scriptCode,
    const CTransaction& txTo,
    unsigned int nIn,
    int nHashType
);

/**
 * Forward declaration for ConstructSignatureHashPreimage from script.cpp
 * Constructs the canonical sighash preimage used by ECDSA and ML-DSA.
 */
extern bool ConstructSignatureHashPreimage(
    const CScript& scriptCode,
    const CTransaction& txTo,
    unsigned int nIn,
    int nHashType,
    std::vector<unsigned char>& preimageOut
);

/**
 * Verify a hybrid transaction signature.
 *
 * PhoenixCoin Quantum requires every hybrid spend to be authenticated by
 * both an ECDSA (secp256k1) signature and an ML-DSA-65 signature. Both
 * signatures are verified over the same transaction digest, with the
 * ML-DSA component using a domain-separated message.
 *
 * Script stack:
 *     sigECDSA  sigMLDSA  pubkeyECDSA  pubkeyMLDSA  -- bool
 *
 * Verification sequence:
 *   1. Construct the canonical transaction sighash preimage.
 *   2. Hash the preimage for ECDSA verification.
 *   3. Verify the ECDSA signature against that transaction hash.
 *   4. Build the domain-separated ML-DSA message from the same
 *      sighash preimage.
 *   5. Verify the ML-DSA-65 signature against that message.
 *   6. Return true only if both verifications succeed.
 *
 * Parameters:
 *   vchSigEC
 *       ECDSA signature including the sighash type byte.
 *
 *   vchSigML
 *       ML-DSA-65 signature including the sighash type byte.
 *
 *   vchPubKeyEC
 *       Compressed secp256k1 public key.
 *
 *   vchPubKeyML
 *       Raw ML-DSA-65 public key.
 *
 *   scriptCode
 *       Script used to compute the transaction signature hash.
 *
 *   txTo
 *       Transaction being verified.
 *
 *   nIn
 *       Input index being verified.
 *
 *   nHashType
 *       Signature hash type.
 *
 * Returns:
 *   true  - both ECDSA and ML-DSA verification succeeded.
 *   false - either signature failed or an error occurred.
 *
 * Notes:
 *   - Hybrid signatures are consensus-critical.
 *   - Failure of either signature causes script verification to fail.
 *   - Domain separation prevents cross-algorithm signature reuse between
 *     the ECDSA and ML-DSA components.
 */
inline bool VerifyHybridSignature(
    const std::vector<unsigned char>& vchSigEC,
    const std::vector<unsigned char>& vchSigML,
    const std::vector<unsigned char>& vchPubKeyEC,
    const std::vector<unsigned char>& vchPubKeyML,
    const CScript& scriptCode,
    const CTransaction& txTo,
    unsigned int nIn,
    int nHashType)
{
    // ------------------------------------------------------------
    // Basic validation
    // ------------------------------------------------------------
    if (vchSigEC.empty() ||
        vchSigML.empty() ||
        vchPubKeyEC.empty() ||
        vchPubKeyML.empty())
        return false;

    if (vchPubKeyEC.size() != ECDSA_PUBKEY_SIZE)
        return false;

    if (vchPubKeyML.size() != ML_DSA_65_PUBKEY_SIZE)
        return false;

    // ------------------------------------------------------------
    // Determine sighash type
    // Both signatures must carry the same hash type.
    // ------------------------------------------------------------
    int hashTypeEC = vchSigEC.back();
    int hashTypeML = vchSigML.back();

    if (hashTypeEC != hashTypeML)
        return false;

    if (nHashType != 0 && hashTypeEC != nHashType)
        return false;

    // ------------------------------------------------------------
    // Compute the transaction sighash for ECDSA.
    // ML-DSA independently uses the same canonical sighash preimage
    // with hybrid domain separation.
    // ------------------------------------------------------------
    uint256 sighash =
        SignatureHash(scriptCode, txTo, nIn, hashTypeEC);

    // ------------------------------------------------------------
    // Verify ECDSA signature
    // ------------------------------------------------------------
    if (!CheckSig(
            vchSigEC,
            vchPubKeyEC,
            scriptCode,
            txTo,
            nIn,
            hashTypeEC,
            &sighash))
    {
        return false;
    }

    // ------------------------------------------------------------
    // Remove sighash byte from ML-DSA signature
    // ------------------------------------------------------------
    std::vector<unsigned char> mldsaSig(
        vchSigML.begin(),
        vchSigML.end() - 1);

    // Construct the canonical sighash preimage using the same logic as SignatureHash()
    std::vector<unsigned char> sighash_preimage;
    if (!ConstructSignatureHashPreimage(scriptCode, txTo, nIn, hashTypeEC, sighash_preimage))
        return false;

    // Apply domain separation for ML-DSA
    std::vector<unsigned char> hybridMsg = BuildHybridMessage(sighash_preimage);

    // ------------------------------------------------------------
    // Verify ML-DSA signature
    // ------------------------------------------------------------
    if (!VerifyMLDSA(
            mldsaSig,
            vchPubKeyML,
            hybridMsg))
    {
        return false;
    }

    return true;
}

#endif // HYBRID_VERIFY_H
