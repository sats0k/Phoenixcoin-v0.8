// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef HYBRID_TYPES_H
#define HYBRID_TYPES_H

#pragma once

#include <vector>

#include "uint256.h"
#include "util.h"

// Hybrid address identifier: Hash160(serialized hybrid public key)
class CHybridKeyID : public uint160
{
public:
    CHybridKeyID() {}
    CHybridKeyID(const uint160& in) : uint160(in) {}
};

/* Hybrid Public Key Storage */
struct CHybridPubKey {
    std::vector<unsigned char> ecdsaPubKey;    // 33 bytes (compressed secp256k1)
    std::vector<unsigned char> mldsaPubKey;    // 1952 bytes (raw ML-DSA-65)

    CHybridPubKey() = default;
    CHybridPubKey(const std::vector<unsigned char>& ecdsa,
                  const std::vector<unsigned char>& mldsa)
        : ecdsaPubKey(ecdsa), mldsaPubKey(mldsa) {}

    // Size validation
    static constexpr size_t ECDSA_SIZE = 33;
    static constexpr size_t MLDSA_SIZE = 1952;
    static constexpr size_t TOTAL_SIZE = ECDSA_SIZE + MLDSA_SIZE;

    bool IsValid() const {
        return ecdsaPubKey.size() == ECDSA_SIZE &&
               mldsaPubKey.size() == MLDSA_SIZE;
    }

    // Serialize to combined form (used in script)
    std::vector<unsigned char> Serialize() const {
        std::vector<unsigned char> result;
        result.reserve(TOTAL_SIZE);
        result.insert(result.end(), ecdsaPubKey.begin(), ecdsaPubKey.end());
        result.insert(result.end(), mldsaPubKey.begin(), mldsaPubKey.end());
        return result;
    }

    // Deserialize from combined form
    static CHybridPubKey Deserialize(const std::vector<unsigned char>& data) {
        if (data.size() != TOTAL_SIZE) {
            return CHybridPubKey();
        }
        return CHybridPubKey(
            std::vector<unsigned char>(data.begin(), data.begin() + ECDSA_SIZE),
            std::vector<unsigned char>(data.begin() + ECDSA_SIZE, data.end())
        );
    }

    // Required for std::set and std::map
    bool operator<(const CHybridPubKey& other) const {
        if (ecdsaPubKey.size() != other.ecdsaPubKey.size())
            return ecdsaPubKey.size() < other.ecdsaPubKey.size();
        if (ecdsaPubKey != other.ecdsaPubKey)
            return ecdsaPubKey < other.ecdsaPubKey;
        return mldsaPubKey < other.mldsaPubKey;
     }

    bool operator==(const CHybridPubKey& other) const {
        return ecdsaPubKey == other.ecdsaPubKey &&
               mldsaPubKey == other.mldsaPubKey;
    }

    CHybridKeyID GetID() const
    {
        std::vector<unsigned char> blob = Serialize();
            return CHybridKeyID(Hash160(blob));
    }
};

#endif // HYBRID_TYPES_H
