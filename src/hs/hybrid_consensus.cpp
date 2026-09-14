// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "hs/hybrid_consensus.h"
#include "main.h"

bool IsHybridConsensusActive()
{
    return nBestHeight >= HYBRID_ACTIVATION_HEIGHT;
}
