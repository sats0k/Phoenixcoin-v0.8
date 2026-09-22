// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <map>
#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "base58.h"
#include "wallet.h"
#include "walletdb.h"
#include "rpcmain.h"
#include "script.h"
#include "main.h"
#include "util.h"
#include "hs/rpchybrid.h"
#include "hs/hybrid_message.h"
#include "hs/hybrid_signer.h"
#include "hs/hybrid_script.h"
#include "hs/wallethybrid.h"

using namespace json_spirit;
using namespace std;

extern CWallet *pwalletMain;

extern void WalletTxToJSON(const CWalletTx& wtx, Object& entry);
extern string AccountFromValue(const Value& value);

// ============================================================================
// HYBRID KEY RPCs
// ============================================================================

Value dumphybridkey(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 1) {
        string msg =
            "dumphybridkey <address>\n"
            "Reveals the hybrid private key (secp256k1 + MLDSA) for <address>.";
        throw runtime_error(msg);
    }

    string strAddress = params[0].get_str();
    CCoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");

    // Parse hybrid address
    CTxDestination dest = address.Get();

    const CHybridKeyID* pHybridID = boost::get<CHybridKeyID>(&dest);

    if (!pHybridID)
        throw JSONRPCError(RPC_TYPE_ERROR, "Address is not a hybrid address");

    CHybridKeyID hybridID = *pHybridID;

    // Load the hybrid key
    CHybridKey hk;

    if (!pwalletMain->GetHybridKey(hybridID, hk))
        throw JSONRPCError(RPC_WALLET_ERROR, "No hybrid key for this address");

    // Recover the legacy KeyID
    CKeyID keyID = hk.GetKeyID();

    // ---- secp256k1 (same as dumpprivkey) ----
    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " +
                                                 strAddress + " is not known");
    }

    string wif = CCoinSecret(vchSecret, fCompressed).ToString();

    if (!pwalletMain->GetHybridKey(hybridID, hk))
        throw JSONRPCError(RPC_WALLET_ERROR, "No hybrid key for this address");

    MLDSASigner* signer = hk.mldsaSigner.get();

    if (!signer) throw JSONRPCError(RPC_WALLET_ERROR, "MLDSA signer missing");

    EVP_PKEY* pkey = signer->GetKey();

    if (!pkey) throw JSONRPCError(RPC_WALLET_ERROR, "MLDSA key missing");

    // Serialize MLDSA private key to DER
    unsigned char* buf = NULL;
    int len = i2d_PrivateKey(pkey, &buf);
    if (len <= 0 || !buf)
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to serialize MLDSA key");

    vector<unsigned char> der(buf, buf + len);
    OPENSSL_free(buf);

    string der_b64 = EncodeBase64(der.data(), der.size());

    Object result;
    result.push_back(Pair("address", address.ToString()));
    result.push_back(Pair("secp_wif", wif));
    result.push_back(Pair("mldsa_alg", "p384_mldsa65"));
    result.push_back(Pair("mldsa_priv_der_b64", der_b64));
    result.push_back(Pair("hybridkey_disk_version", HYBRIDKEY_DISK_VERSION));
    result.push_back(Pair("hybrid_sig_version", HYBRID_SIG_VERSION));

    return result;
}

Value importhybridkey(const Array& params, bool fHelp) {
    if (fHelp || params.size() < 2 || params.size() > 4) {
        string msg =
            "importhybridkey \"secp_wif\" \"mldsa_priv_der_b64\" [\"label\"] [rescan]\n"
            "Adds a hybrid private key to the wallet.\n"
            "The two components are the output of 'dumphybridkey': the ECDSA\n"
            "half as WIF ('secp_wif') and the ML-DSA-65 half as Base64-encoded\n"
            "DER ('mldsa_priv_der_b64').\n"
            "\"label\" (string, optional) gives the imported address a label in\n"
            "the address book (default \"\").\n"
            "rescan (boolean, optional) rescans the block chain for\n"
            "transactions paying to the imported address, true by default.";
        throw runtime_error(msg);
    }

    // ---- ECDSA half (WIF) ----
    string strWif = params[0].get_str();
    CCoinSecret vchSecret;
    if (!vchSecret.SetString(strWif))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid secp256k1 private key (WIF)");

    CKey key;
    bool fCompressed = false;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    if (!key.SetSecret(secret, fCompressed) || !key.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid secp256k1 private key (WIF)");

    // ---- ML-DSA half (Base64 DER) ----
    string strDerB64 = params[1].get_str();
    bool fInvalidBase64 = false;
    vector<unsigned char> mldsaPriv =
        DecodeBase64(strDerB64.c_str(), &fInvalidBase64);
    // The ML-DSA-65 private key is the expanded 4,032-byte form, wrapped in
    // a ~66-byte PKCS#8 header => ~4,098 bytes of DER. Allow a generous
    // upper bound only as a sanity guard; d2i_AutoPrivateKey + validation
    // reject anything malformed.
    if (fInvalidBase64 || mldsaPriv.empty() || mldsaPriv.size() > 8192)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid ML-DSA private key (Base64 DER expected)");

    const unsigned char* p = mldsaPriv.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, mldsaPriv.size());
    // Guard the d2i ref before the validity checks so a malformed or
    // trailing-byte DER blob cannot leak the handle; MLDSASigner up-refs
    // its own handle, so the guard releases the d2i ref.
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(
        pkey, &EVP_PKEY_free);
    if (!pkey || p != mldsaPriv.data() + mldsaPriv.size())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "ML-DSA private key decode failed");

    string strLabel;
    if (params.size() > 2) strLabel = params[2].get_str();

    bool fRescan = true;
    if (params.size() > 3) fRescan = params[3].get_bool();

    // Encrypted wallets must be unlocked so the private material can be
    // re-encrypted with the wallet master key and persisted at rest.
    if (pwalletMain->IsCrypted() && pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with "
                           "walletpassphrase first.");

    // ---- Build and validate the hybrid key ----
    CHybridKey hk;
    std::unique_ptr<MLDSASigner> signerCopy;
    try {
        hk.secpPriv    = key.GetPrivKey();
        hk.secpPub     = key.GetPubKey();
        hk.nCreateTime = GetTime();
        hk.mldsaAlg    = "p384_mldsa65";
        hk.mldsaSigner = std::make_unique<MLDSASigner>(pkey_guard.get());
        signerCopy     = std::make_unique<MLDSASigner>(pkey_guard.get());

        if (!ValidateHybridKey(hk))
            throw std::runtime_error("Hybrid key validation failed");
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           string("Invalid hybrid key: ") + e.what());
    }

    CHybridKeyID hybridID = hk.GetHybridID();

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if (pwalletMain->HaveHybridKey(hybridID))
            throw JSONRPCError(RPC_WALLET_ERROR, "Already have this hybrid key");

        // ---- Persist at rest (same path as wallet-generated keys) ----
        if (pwalletMain->fFileBacked) {
            try {
                CHybridKeyDisk disk = pwalletMain->MakeHybridKeyDisk(hk);
                CWalletDB walletdb(pwalletMain->strWalletFile);
                if (!walletdb.WriteHybridKey(hybridID, disk))
                    throw JSONRPCError(RPC_WALLET_ERROR,
                                       "Error writing hybrid key to wallet");
                // Encrypted wallets rebuild plaintext keys from these records
                // on unlock, so keep the disk form cached now.
                if (pwalletMain->IsCrypted())
                    pwalletMain->mapHybridKeyDisk[hybridID] = disk;
            } catch (Object&) {
                throw;
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   string("Error persisting hybrid key: ") +
                                       e.what());
            }
        }

        pwalletMain->mapHybridKeys.emplace(hybridID, std::move(hk));
        pwalletMain->mapHybridSigners.emplace(hybridID, std::move(signerCopy));

        if (!strLabel.empty()) {
            pwalletMain->SetHybridAddressBookName(hybridID, strLabel);
            CWalletDB walletdb(pwalletMain->strWalletFile);
            walletdb.WriteHybridAddressEntry(hybridID, strLabel);
        }

        if (fRescan) {
            pwalletMain->UpdateTimeFirstKey();
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return CCoinAddress(hybridID).ToString();
}

Value gethybridaddress(const Array& params, bool fHelp) {
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "gethybridaddress [label]\n"
            "Returns a new hybrid (quantum-resistant) address.");

    if (pwalletMain->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with "
                           "walletpassphrase first.");

    LOCK(pwalletMain->cs_wallet);

    // Allocate one unused key; this also tops up the pool when running low
    // and persists the key as used so it is never re-issued after a restart.
    CHybridKeyID hybridID;
    if (!pwalletMain->GetUnusedHybridKey(hybridID))
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Error: No unused hybrid keys available.");

    // Optional address label.
    if (params.size() > 0) {
        std::string strLabel = params[0].get_str();

        pwalletMain->SetHybridAddressBookName(hybridID, strLabel);

        CWalletDB walletdb(pwalletMain->strWalletFile);
        walletdb.WriteHybridAddressEntry(hybridID, strLabel);
    }

    return CCoinAddress(hybridID).ToString();
}

Value listhybridaddresses(const Array& params, bool fHelp) {
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "listhybridaddresses [includeempty]\n"
            "Returns a list of all hybrid addresses in the wallet.");

    bool fIncludeEmpty = true;
    if (params.size() > 0) fIncludeEmpty = params[0].get_bool();

    Array result;
    {
        LOCK(pwalletMain->cs_wallet);

        for (std::map<CHybridKeyID, CHybridKey>::const_iterator it =
                 pwalletMain->mapHybridKeys.begin();
             it != pwalletMain->mapHybridKeys.end(); ++it) {
            const CHybridKeyID& hybridID = it->first;
            const CHybridKey& hybridKey = it->second;

            printf("Stored ID    : %s\n", hybridID.ToString().c_str());
            printf("Address      : %s\n",
                   CCoinAddress(hybridID).ToString().c_str());

            std::string strLabel;

            std::map<CHybridKeyID, CHybridAddressEntry>::const_iterator ab =
                pwalletMain->mapHybridAddressBook.find(hybridID);

            if (ab != pwalletMain->mapHybridAddressBook.end())
                strLabel = ab->second.strLabel;

            if (!fIncludeEmpty && strLabel.empty()) continue;

            CCoinAddress address(hybridID);

            Object obj;
            obj.push_back(Pair("address", address.ToString()));
            obj.push_back(Pair("label", strLabel));
            obj.push_back(
                Pair("pubkey_ecdsa", HexStr(hybridKey.secpPub.Raw())));
            obj.push_back(Pair(
                "created", static_cast<boost::int64_t>(hybridKey.nCreateTime)));

            result.push_back(obj);
        }
    }

    return result;
}

Value gethybridkey(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "gethybridkey \"address\"\n"
            "Returns the public key components for the given hybrid address.\n"
            "Reveals both ECDSA and ML-DSA-65 public key components (not "
            "private keys).\n"
            "\nArguments: 1. address (string, required) - The hybrid address\n"
            "\nResult object contains: address, pubkey_ecdsa, "
            "pubkey_mldsa_b64, algorithm_mldsa, created, label\n"
            "Note: Use 'dumphybridkey' to get private keys.\n");

    string strAddress = params[0].get_str();
    CCoinAddress address(strAddress);

    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Invalid Phoenixcoin address");

    CHybridKeyID hybridID;

    CTxDestination dest = address.Get();

    const CHybridKeyID* pHybridID = boost::get<CHybridKeyID>(&dest);

    if (!pHybridID)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                           "Address is not a hybrid address");

    hybridID = *pHybridID;

    CPubKey secpPub;
    std::string mldsaAlg;
    int64_t nCreateTime = 0;
    std::string strMldsaPubB64;
    std::vector<unsigned char> mldsaPub;

    {
        LOCK(pwalletMain->cs_wallet);

        map<CHybridKeyID, CHybridKey>::const_iterator it =
            pwalletMain->mapHybridKeys.find(hybridID);

        if (it == pwalletMain->mapHybridKeys.end())
            throw JSONRPCError(
                RPC_INVALID_ADDRESS_OR_KEY,
                "Address does not correspond to a hybrid key in this wallet");

        // Copy the needed fields (and the MLDSA public key bytes) while
        // holding the lock; other threads may rebalance/erase this map entry.
        secpPub = it->second.secpPub;
        mldsaAlg = it->second.mldsaAlg;
        nCreateTime = it->second.nCreateTime;

        if (it->second.mldsaSigner) {
            mldsaPub = it->second.mldsaSigner->GetPublicKey();

            if (!mldsaPub.empty())
                strMldsaPubB64 = EncodeBase64(mldsaPub.data(), mldsaPub.size());
        }
    }

    // Build response
    Object result;
    result.push_back(Pair("address", strAddress));
    result.push_back(Pair("pubkey_ecdsa", HexStr(secpPub.Raw())));
    result.push_back(Pair("pubkey_mldsa_b64", strMldsaPubB64));
    result.push_back(Pair("algorithm_mldsa", mldsaAlg));
    result.push_back(Pair("created", nCreateTime));

    if (secpPub.IsValid() &&
        mldsaPub.size() == CHybridPubKey::MLDSA_SIZE) {
        CHybridPubKey hybridPub(secpPub.Raw(), mldsaPub);
        result.push_back(
            Pair("pubkey_serialized_hex", HexStr(hybridPub.Serialize())));
    }

    // Add label if exists
    {
        LOCK(pwalletMain->cs_wallet);
        std::map<CHybridKeyID, CHybridAddressEntry>::const_iterator ab =
            pwalletMain->mapHybridAddressBook.find(hybridID);

        if (ab != pwalletMain->mapHybridAddressBook.end())
            result.push_back(Pair("label", ab->second.strLabel));
    }

    return result;
}

Value addhybridmultisigaddress(const Array &params, bool fHelp) {

    if(fHelp || (params.size() < 2) || (params.size() > 3)) {
        string msg = "addhybridmultisigaddress <n-required> <'[\"hybridpubkey\",\"hybridpubkey\"]'> [account]\n"
          "Adds an N-required-to-sign hybrid multisignature address to the wallet.\n"
          "Each key is the hex-encoded serialized hybrid public key (33-byte ECDSA\n"
          "followed by 1952-byte ML-DSA-65), returned as pubkey_serialized_hex by\n"
          "'gethybridkey'. The output is wrapped in pay-to-script-hash.\n"
          "If [account] is specified, assigns the address to it.";
        throw(runtime_error(msg));
    }

    int nRequired = params[0].get_int();
    const Array& keys = params[1].get_array();
    string strAccount;
    if (params.size() > 2)
        strAccount = AccountFromValue(params[2]);

    if(nRequired < 1) {
        throw(runtime_error("a multisignature address must require at least one key to redeem"));
    }

    if(nRequired > 16 || (int)keys.size() > 16) {
        throw(runtime_error("valid hybrid multisignature scripts support at most 16 keys"));
    }

    if((int)keys.size() < nRequired) {
        throw(runtime_error(strprintf("not enough keys supplied " \
          "(got %" PRIszu " keys, but need at least %d to redeem)", keys.size(), nRequired)));
    }

    std::vector<CHybridPubKey> pubkeys;
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();

        if (!IsHex(ks))
            throw runtime_error(" Invalid hybrid public key (expected hex): "+ks);

        std::vector<unsigned char> data = ParseHex(ks);
        CHybridPubKey pub = CHybridPubKey::Deserialize(data);
        if (!pub.IsValid())
            throw runtime_error(" Invalid hybrid public key: "+ks);

        pubkeys.push_back(pub);
    }

    CScript inner = GetScriptForHybridMultisig(nRequired, pubkeys);
    if (inner.empty())
        throw runtime_error(" Failed to construct hybrid multisig script");

    CScriptID innerID = inner.GetID();
    pwalletMain->AddCScript(inner);

    pwalletMain->SetAddressBookName(innerID, strAccount);
    return(CCoinAddress(innerID).ToString());
}

// Hybrid-aware helper to add size and signature type
void WalletTxToJSONHybrid(const CWalletTx& wtx, const string& /*strAccount*/, Object& entry)
{
    // Fill standard fields
    WalletTxToJSON(wtx, entry);

    // Transaction size in bytes
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << wtx;
    int nSize = ssTx.size();
    entry.push_back(Pair("size_bytes", nSize));

    // Simple hybrid signature detection (heuristic)
    string sigType = "ECDSA";
    for (const CTxIn &txin : wtx.vin) {
        if (txin.scriptSig.size() > 70) { // ECDSA ~70 bytes, ML-DSA adds extra
            sigType = "Hybrid (ECDSA + ML-DSA-65)";
            break;
        }
    }
    entry.push_back(Pair("sig_type", sigType));
}

// ============================================================================
// HYBRID MESSAGE SIGNATURES (signmessage / verifymessage)
// ============================================================================

static bool VerifyMlDsaRaw(const std::vector<unsigned char>& msg,
                           const std::vector<unsigned char>& mldsaPub,
                           const std::vector<unsigned char>& mldsaSig)
{
    // Same exact-length constraints the consensus verifier applies.
    if (mldsaPub.size() != ML_DSA_65_PUBKEY_SIZE ||
        mldsaSig.size() != ML_DSA_65_SIG_SIZE - 1)
        return false;

    EVP_PKEY* pkey =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ML_DSA_65, nullptr,
                                    mldsaPub.data(), mldsaPub.size());
    if (!pkey)
        return false;

    std::unique_ptr<MLDSASigner> signer;
    try {
        signer = std::make_unique<MLDSASigner>(pkey);
    } catch (const std::exception&) {
        EVP_PKEY_free(pkey);
        return false;
    }
    EVP_PKEY_free(pkey); // MLDSASigner up-ref'd its own handle

    return signer->Verify(msg, mldsaSig);
}

bool SignHybridMessage(const CHybridKey& hk, const std::string& strMessage,
                       std::vector<unsigned char>& vchSigOut)
{
    if (hk.secpPriv.empty() || !hk.mldsaSigner)
        return false;

    std::vector<unsigned char> vchMsg;
    {
        CDataStream ss(SER_GETHASH, 0);
        ss << strMessageMagic;
        ss << strMessage;
        vchMsg.assign(ss.begin(), ss.end());
    }

    uint256 hash = Hash(vchMsg.begin(), vchMsg.end());

    std::vector<unsigned char> vchEcdsaCompact;
    CKey secpKey = hk.GetCKey();
    if (!secpKey.SignCompact(hash, vchEcdsaCompact))
        return false;

    std::vector<unsigned char> vchMldsaSig;
    if (!hk.mldsaSigner->Sign(BuildHybridMessage(vchMsg), vchMldsaSig))
        return false;

    std::vector<unsigned char> vchEcdsaPub = hk.secpPub.Raw();
    std::vector<unsigned char> vchMldsaPub = hk.mldsaSigner->GetPublicKey();

    if (vchEcdsaPub.size() != CHybridPubKey::ECDSA_SIZE ||
        vchMldsaPub.size() != CHybridPubKey::MLDSA_SIZE)
        return false;

    vchSigOut.clear();
    vchSigOut.insert(vchSigOut.end(), HYBRID_SIG_MAGIC,
                     HYBRID_SIG_MAGIC + 4);
    vchSigOut.push_back(HYBRID_SIG_VERSION);
    vchSigOut.insert(vchSigOut.end(), vchEcdsaCompact.begin(),
                     vchEcdsaCompact.end());
    vchSigOut.insert(vchSigOut.end(), vchEcdsaPub.begin(), vchEcdsaPub.end());
    PutU16BE(vchSigOut, vchMldsaPub.size());
    vchSigOut.insert(vchSigOut.end(), vchMldsaPub.begin(), vchMldsaPub.end());
    PutU16BE(vchSigOut, vchMldsaSig.size());
    vchSigOut.insert(vchSigOut.end(), vchMldsaSig.begin(), vchMldsaSig.end());

    return true;
}

bool VerifyHybridMessage(const std::vector<unsigned char>& vchSig,
                         const CHybridKeyID& hybridID,
                         const std::string& strMessage)
{
    std::vector<unsigned char> vchEcdsaCompact;
    std::vector<unsigned char> vchEcdsaPub;
    std::vector<unsigned char> vchMldsaPub;
    std::vector<unsigned char> vchMldsaSig;

    // Pure structural parse: magic/version, fixed ECDSA blocks, exact
    // ML-DSA length fields, no trailing bytes, bounded reads.
    if (!ParseHybridMessage(vchSig, vchEcdsaCompact, vchEcdsaPub, vchMldsaPub,
                            vchMldsaSig))
        return false;

    // The embedded public keys must reproduce exactly the hybrid address
    // the caller asked us to verify against.
    CHybridPubKey hybridPub(vchEcdsaPub, vchMldsaPub);
    if (hybridPub.GetID() != hybridID)
        return false;

    std::vector<unsigned char> vchMsg;
    {
        CDataStream ss(SER_GETHASH, 0);
        ss << strMessageMagic;
        ss << strMessage;
        vchMsg.assign(ss.begin(), ss.end());
    }
    uint256 hash = Hash(vchMsg.begin(), vchMsg.end());

    // Recover the ECDSA public key and require it to match the embedded one.
    CKey rec;
    if (!rec.SetCompactSignature(hash, vchEcdsaCompact))
        return false;
    if (rec.GetPubKey().Raw() != vchEcdsaPub)
        return false;

    return VerifyMlDsaRaw(BuildHybridMessage(vchMsg), vchMldsaPub, vchMldsaSig);
}
