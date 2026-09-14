// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef RPCHYBRID_H
#define RPCHYBRID_H

#pragma once

#include "json/json_spirit.h"
#include "rpcmain.h"
#include "wallet.h"

/* ---- Hybrid RPC handlers (defined in hs/rpchybrid.cpp) ---- */

extern json_spirit::Value dumphybridkey(const json_spirit::Array &params, bool fHelp);

extern json_spirit::Value gethybridaddress(const json_spirit::Array &params, bool fHelp);

extern json_spirit::Value listhybridaddresses(const json_spirit::Array &params, bool fHelp);

extern json_spirit::Value gethybridkey(const json_spirit::Array &params, bool fHelp);

extern json_spirit::Value addhybridmultisigaddress(const json_spirit::Array &params, bool fHelp);

// Hybrid-aware helper to add size and signature type to a wallet-tx JSON entry.
// Used by listtransactions (defined in rpcwallet.cpp).
extern void WalletTxToJSONHybrid(const CWalletTx& wtx, const std::string& strAccount,
                                 json_spirit::Object& entry);

#endif // RPCHYBRID_H
