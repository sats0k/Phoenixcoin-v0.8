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

/*
 * Hybrid message signatures (used by signmessage / verifymessage).
 *
 * The signature is a self-describing container:
 *
 *   magic  "HYBS"                   (4 bytes)   HYBRID_SIG_MAGIC
 *   version                         (1 byte)    HYBRID_SIG_VERSION
 *   ECDSA recoverable signature     (65 bytes)  [header | r || s]
 *   ECDSA compressed public key     (33 bytes)
 *   ML-DSA public key length        (2 bytes, big-endian)
 *   ML-DSA public key               (N bytes)
 *   ML-DSA signature length         (2 bytes, big-endian)
 *   ML-DSA signature                (M bytes)
 *
 * Both public keys are embedded because ML-DSA signatures do not support key
 * recovery: verifymessage recomputes Hash160(ecdsa || mldsa) and requires it
 * to match the supplied hybrid address, so no wallet access is needed.
 *
 * The ECDSA component signs SHA256("Phoenixcoin Signed Message:\n" + message)
 * (Bitcoin-style recoverable compact signature); the ML-DSA component signs
 * BuildHybridMessage() of the same serialized message bytes, matching the
 * domain separation used by hybrid transaction signatures.
 */
extern bool SignHybridMessage(const CHybridKey& hk,
                              const std::string& strMessage,
                              std::vector<unsigned char>& vchSigOut);

extern bool VerifyHybridMessage(const std::vector<unsigned char>& vchSig,
                                const CHybridKeyID& hybridID,
                                const std::string& strMessage);

#endif // RPCHYBRID_H
