// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef WALLETDB_HYBRID_H
#define WALLETDB_HYBRID_H

#pragma once

#include <string>

#include "serialize.h"
#include "util.h"

struct CHybridKeyMetadata
{
    int32_t nCreateTime;
    int nVersion;

    CHybridKeyMetadata() : nCreateTime(0), nVersion(1) {}

    IMPLEMENT_SERIALIZE(
        READWRITE(nVersion);
        READWRITE(nCreateTime);
    )
};

// ============================================================================
// HYBRID ADDRESS BOOK METADATA
// ============================================================================

/**
 * Hybrid Address Entry
 * Stores metadata about hybrid keys in address book
 */
struct CHybridAddressEntry
{
    int nVersion;                           // Entry version
    int64 nCreateTime;                      // When address was created
    std::string strLabel;                   // User label/name
    std::string strPurpose;                 // "send", "receive", "change"

    CHybridAddressEntry() : nVersion(1), nCreateTime(0) {}

    CHybridAddressEntry(const std::string& label, const std::string& purpose = "receive")
        : nVersion(1), nCreateTime(GetTime()), strLabel(label), strPurpose(purpose) {}

    IMPLEMENT_SERIALIZE(
        READWRITE(nVersion);
        READWRITE(nCreateTime);
        READWRITE(strLabel);
        READWRITE(strPurpose);
    )
};

#endif // WALLETDB_HYBRID_H
