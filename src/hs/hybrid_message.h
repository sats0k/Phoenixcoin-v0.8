// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef HYBRID_MESSAGE_H
#define HYBRID_MESSAGE_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "hs/hybrid_script.h"

// ============================================================================
// HYBRID MESSAGE SIGNATURE (HYBS) CONTAINER PARSER
// ============================================================================
//
// v1 container layout:
//
//   magic  "HYBS"                   (4 bytes)
//   version                         (1 byte)
//   ECDSA recoverable signature     (65 bytes)
//   ECDSA compressed public key     (ECDSA_PUBKEY_SIZE bytes)
//   ML-DSA public key length        (2 bytes, big-endian)
//   ML-DSA public key               (N bytes)
//   ML-DSA signature length         (2 bytes, big-endian)
//   ML-DSA signature                (M bytes)
//
// ParseHybridMessage() is the pure, dependency-light structural parser: it
// performs all length handling and rejects any malformation without
// allocating beyond the input size. The ECDSA/ML-DSA cryptographic checks
// are layered on top by VerifyHybridMessage().

// Big-endian u16 reader/writer helpers.
static inline void PutU16BE(std::vector<unsigned char>& out, size_t v)
{
    out.push_back((unsigned char)(v >> 8));
    out.push_back((unsigned char)(v & 0xff));
}

static inline bool GetU16BE(const std::vector<unsigned char>& buf, size_t& off,
                            size_t& v)
{
    if (off + 2 > buf.size())
        return false;
    v = ((size_t)buf[off] << 8) | (size_t)buf[off + 1];
    off += 2;
    return true;
}

// Bounded read: never reads or allocates beyond the input buffer.
static inline bool ReadBytes(const std::vector<unsigned char>& buf, size_t& off,
                             size_t len, std::vector<unsigned char>& out)
{
    if (len > buf.size() || off + len > buf.size())
        return false;
    out.assign(buf.begin() + off, buf.begin() + off + len);
    off += len;
    return true;
}

/**
 * Parses a v1 HYBS container.
 *
 * Strict structural rules:
 *   - magic must be "HYBS" and version must be HYBRID_SIG_VERSION;
 *   - the ECDSA compact signature and public key are fixed-size;
 *   - the ML-DSA public-key length field must be exactly
 *     ML_DSA_65_PUBKEY_SIZE and the signature length field exactly
 *     ML_DSA_65_SIG_SIZE - 1;
 *   - the whole input must be consumed (no trailing bytes).
 *
 * Outputs are only populated on full success (transactional): on failure all
 * outputs are left empty and the function returns false. No allocation is
 * ever performed beyond the size of the input.
 */
bool ParseHybridMessage(const std::vector<unsigned char>& vchSig,
                        std::vector<unsigned char>& vchEcdsaCompact,
                        std::vector<unsigned char>& vchEcdsaPub,
                        std::vector<unsigned char>& vchMldsaPub,
                        std::vector<unsigned char>& vchMldsaSig);

#endif // HYBRID_MESSAGE_H