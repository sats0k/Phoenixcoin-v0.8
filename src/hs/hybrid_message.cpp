// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "hs/hybrid_message.h"

#include <openssl/crypto.h>

#include "hs/hybrid_signer.h" // HYBRID_SIG_MAGIC, HYBRID_SIG_VERSION

bool ParseHybridMessage(const std::vector<unsigned char>& vchSig,
                        std::vector<unsigned char>& vchEcdsaCompact,
                        std::vector<unsigned char>& vchEcdsaPub,
                        std::vector<unsigned char>& vchMldsaPub,
                        std::vector<unsigned char>& vchMldsaSig)
{
    // Parse into locals so the caller's outputs are only touched on full
    // success (no partially accepted/partially populated data).
    std::vector<unsigned char> compact;
    std::vector<unsigned char> ecdsaPub;
    std::vector<unsigned char> mldsaPub;
    std::vector<unsigned char> mldsaSig;

    size_t off = 0;

    // Magic + version. 5 bytes minimum.
    if (off + 4 + 1 > vchSig.size())
        return false;
    if (CRYPTO_memcmp(&vchSig[0], HYBRID_SIG_MAGIC, 4) != 0)
        return false;
    off += 4;
    if (vchSig[off] != HYBRID_SIG_VERSION)
        return false;
    off += 1;

    // Fixed-size ECDSA components.
    if (!ReadBytes(vchSig, off, 65, compact))
        return false;
    if (!ReadBytes(vchSig, off, ECDSA_PUBKEY_SIZE, ecdsaPub))
        return false;

    // ML-DSA public key: length field must be exactly the ML-DSA-65 size.
    size_t mldsaPubLen = 0;
    if (!GetU16BE(vchSig, off, mldsaPubLen) ||
        mldsaPubLen != ML_DSA_65_PUBKEY_SIZE ||
        !ReadBytes(vchSig, off, mldsaPubLen, mldsaPub))
        return false;

    // ML-DSA signature: length field must be exactly the raw ML-DSA-65 size.
    size_t mldsaSigLen = 0;
    if (!GetU16BE(vchSig, off, mldsaSigLen) ||
        mldsaSigLen != ML_DSA_65_SIG_SIZE - 1 ||
        !ReadBytes(vchSig, off, mldsaSigLen, mldsaSig))
        return false;

    // No trailing bytes: the container must be fully consumed.
    if (off != vchSig.size())
        return false;

    vchEcdsaCompact = std::move(compact);
    vchEcdsaPub     = std::move(ecdsaPub);
    vchMldsaPub     = std::move(mldsaPub);
    vchMldsaSig     = std::move(mldsaSig);
    return true;
}