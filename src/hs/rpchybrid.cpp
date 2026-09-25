// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <algorithm>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/variant/get.hpp>

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
// HYBRID KEY FILE EXPORT / IMPORT HELPERS
// ============================================================================

// Serializes the private components of an in-memory hybrid key into the
// portable pair used by the export file: the secp256k1 half as WIF and the
// ML-DSA-65 half as Base64-encoded PKCS#8 DER.
static void EncodeHybridPrivKey(CWallet* pwallet, const CHybridKey& hk,
                                std::string& wifOut, std::string& derB64Out)
{
    // Test-only failure injection (see
    // regression_hybridkeys_exportfail.sh): when
    // PHOENIX_TEST_FAIL_HYBRID_EXPORT is set to this key's hex id, the first
    // serialization attempt throws, driving DumpHybridKeys down its per-key
    // failure path (the export must fail instead of silently omitting a key).
    // One-shot per id so an immediate retry in the same daemon succeeds.
    {
        const char* psFail = std::getenv("PHOENIX_TEST_FAIL_HYBRID_EXPORT");
        const std::string sFail = (psFail && *psFail) ? std::string(psFail)
                                                      : std::string();
        if (!sFail.empty() && hk.GetHybridID().GetHex() == sFail) {
            static CCriticalSection csFailedIds;
            static std::set<std::string> sFailedIds;
            LOCK(csFailedIds);
            if (sFailedIds.insert(sFail).second)
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   "Private key for address is not known");
        }
    }

    CSecret vchSecret;
    bool fCompressed;
    if (!pwallet->GetSecret(hk.GetKeyID(), vchSecret, fCompressed))
        throw JSONRPCError(RPC_WALLET_ERROR,
                           "Private key for address is not known");

    wifOut = CCoinSecret(vchSecret, fCompressed).ToString();

    MLDSASigner* signer = hk.mldsaSigner.get();
    if (!signer) throw JSONRPCError(RPC_WALLET_ERROR, "MLDSA signer missing");

    EVP_PKEY* pkey = signer->GetKey();
    if (!pkey) throw JSONRPCError(RPC_WALLET_ERROR, "MLDSA key missing");

    unsigned char* buf = NULL;
    int len = i2d_PrivateKey(pkey, &buf);
    if (len <= 0 || !buf)
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to serialize MLDSA key");

    std::vector<unsigned char> der(buf, buf + len);
    OPENSSL_free(buf);

    derB64Out = EncodeBase64(der.data(), der.size());
}

// The one-line dump/parse helpers mirror the classic dumpwallet file grammar so
// hybrid dumps and classic dumps stay interchangeable in spirit.

const std::locale dumpTimeFormats[] = {
    std::locale(std::locale::classic(),
                new boost::posix_time::time_input_facet(
                    "%Y-%m-%dT%H:%M:%SZ")),
    std::locale(std::locale::classic(),
                new boost::posix_time::time_input_facet("%Y-%m-%d~%H:%M:%S")),
    std::locale(std::locale::classic(),
                new boost::posix_time::time_input_facet("%Y-%m-%d %H:%M:%S")),
    std::locale(std::locale::classic(),
                new boost::posix_time::time_input_facet("%Y/%m/%d %H:%M:%S")),
    std::locale(std::locale::classic(),
                new boost::posix_time::time_input_facet("%d.%m.%Y %H:%M:%S")),
    std::locale(std::locale::classic(),
                new boost::posix_time::time_input_facet("%Y-%m-%d")),
};

// Parses a dump-file timestamp into nTimeOut. Returns false (and leaves
// nTimeOut untouched) when the field is not a valid timestamp, so a malformed
// line can be rejected explicitly instead of being silently treated as epoch
// time. Trailing garbage is also rejected, so "2020-01-01junk" fails.
static bool DecodeDumpTimeHybrid(const std::string& s, int64& nTimeOut)
{
    bool fParsed = false;
    boost::posix_time::ptime pt;
    size_t i;

    for (i = 0; i < sizeof(dumpTimeFormats) / sizeof(dumpTimeFormats[0]); ++i) {
        std::istringstream is(s);
        is.imbue(dumpTimeFormats[i]);
        // Reset the candidate: a failed extraction leaves pt untouched, which
        // could otherwise carry a stale value from an earlier attempt.
        pt = boost::posix_time::ptime();
        is >> pt;
        if (pt == boost::posix_time::ptime())
            continue;
        // Reject trailing garbage: the whole field must be one timestamp.
        // Only a format that matched completely sets fParsed; otherwise the
        // last (e.g. date-only) format could match a prefix of a longer
        // string and leave a stale pt behind after the loop.
        char cTrailing;
        if (is >> cTrailing)
            continue;
        fParsed = true;
        break;
    }

    if (!fParsed)
        return false;

    nTimeOut = (pt - boost::posix_time::ptime(
                            boost::gregorian::date(1970, 1, 1)))
                   .total_seconds();
    return true;
}

static std::string EncodeDumpTimeHybrid(int64 nTime)
{
    return DateTimeStrFormat("%Y-%m-%dT%H:%M:%SZ", nTime);
}

static std::string EncodeDumpStringHybrid(const std::string& str)
{
    std::stringstream ret;

    for (size_t i = 0; i < str.size(); i++) {
        unsigned char c = str[i];
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << HexStr(&c, &c + 1);
        } else {
            ret << c;
        }
    }
    return ret.str();
}

static std::string DecodeDumpStringHybrid(const std::string& str)
{
    std::stringstream ret;
    size_t pos;

    for (pos = 0; pos < str.length(); pos++) {
        unsigned char c = str[pos];
        if (c == '%' && (pos + 2) < str.length()) {
            c = (((str[pos + 1] >> 6) * 9 + ((str[pos + 1] - '0') & 15)) << 4) |
                ((str[pos + 2] >> 6) * 9 + ((str[pos + 2] - '0') & 15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

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

    string wif;
    string der_b64;
    EncodeHybridPrivKey(pwalletMain, hk, wif, der_b64);

    Object result;
    result.push_back(Pair("address", address.ToString()));
    result.push_back(Pair("secp_wif", wif));
    result.push_back(Pair("mldsa_alg", hk.mldsaAlg));
    result.push_back(Pair("mldsa_priv_der_b64", der_b64));
    result.push_back(Pair("hybridkey_disk_version", HYBRIDKEY_DISK_VERSION));
    result.push_back(Pair("hybrid_sig_version", HYBRID_SIG_VERSION));

    return result;
}

// Imports one hybrid key given its portable components (WIF + ML-DSA DER
// Base64). Shared by 'importhybridkey' (per-address RPC), 'importhybridkeys'
// (bulk file import) and the Qt wallet (ImportHybridKeysFile). Returns the
// hybrid address of the imported key.
static std::string ImportHybridKeyFromComponents(CWallet* pwallet,
                                                 const std::string& strWif,
                                                 const std::string& strDerB64,
                                                 const std::string& strLabel,
                                                 bool fRescan,
                                                 int64 nCreateTime)
{
    // ---- ECDSA half (WIF) ----
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

    // Encrypted wallets must be unlocked so the private material can be
    // re-encrypted with the wallet master key and persisted at rest.
    if (pwallet->IsCrypted() && pwallet->IsLocked())
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED,
                           "Error: Please enter the wallet passphrase with "
                           "walletpassphrase first.");

    // ---- Build and validate the hybrid key ----
    CHybridKey hk;
    std::unique_ptr<MLDSASigner> signerCopy;
    try {
        hk.secpPriv    = key.GetPrivKey();
        hk.secpPub     = key.GetPubKey();
        hk.nCreateTime = nCreateTime;
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
        LOCK2(cs_main, pwallet->cs_wallet);

        if (pwallet->HaveHybridKey(hybridID))
            throw JSONRPCError(RPC_WALLET_ERROR, "Already have this hybrid key");

        CKey secpKey;
        CKeyID keyID;
        try {
            secpKey = hk.GetCKey();
            keyID   = secpKey.GetPubKey().GetID();
        } catch (const std::exception& e) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                               "Invalid hybrid ECDSA key");
        }

        // The ECDSA record is owned by the keystore: persist it only if this
        // key is not already present (recovering from partial imports) and
        // register it in memory only after the transaction commits.
        bool fPersistKeyRecord = !pwallet->HaveKey(keyID);

        // Fallible key-material preparation happens before any database
        // transaction is opened, so a crypto failure cannot leave a partial
        // import behind.
        CKeyMetadata keyMeta(hk.nCreateTime);
        vector<unsigned char> vchCryptedSecret;
        if (fPersistKeyRecord && pwallet->IsCrypted() &&
            !pwallet->EncryptKeySecret(secpKey, vchCryptedSecret))
            throw JSONRPCError(RPC_WALLET_ERROR,
                               "Error encrypting ECDSA key with wallet master key");

        // ---- Persist at rest in one database transaction ----
        if (pwallet->fFileBacked) {
            CHybridKeyDisk disk;
            try {
                disk = pwallet->MakeHybridKeyDisk(hk);
            } catch (Object&) {
                throw;
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   string("Error building hybrid key record: ") +
                                       e.what());
            }

            CWalletDB walletdb(pwallet->strWalletFile);
            if (!walletdb.TxnBegin())
                throw JSONRPCError(RPC_DATABASE_ERROR, "database error");

            try {
                // ECDSA half, written through the same CWalletDB so it joins
                // this transaction (mirrors CWallet::AddKey persisting).
                if (fPersistKeyRecord &&
                    !pwallet->StageKeyRecord(walletdb, secpKey, keyMeta,
                                             vchCryptedSecret))
                    throw std::runtime_error("failed to write ECDSA key record");

                if (!walletdb.WriteHybridKey(hybridID, disk))
                    throw std::runtime_error("failed to write hybrid key");

                if (!strLabel.empty()) {
                    CHybridAddressEntry entry(strLabel);
                    if (!walletdb.WriteHybridAddressEntry(hybridID, entry))
                        throw std::runtime_error("failed to write address label");
                }

                if (!walletdb.TxnCommit())
                    throw JSONRPCError(RPC_DATABASE_ERROR,
                                       "database error: hybrid key import commit failed");
            } catch (Object&) {
                walletdb.TxnAbort();
                throw;
            } catch (const std::exception& e) {
                walletdb.TxnAbort();
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   string("Error persisting hybrid key: ") +
                                       e.what());
            }

            // Encrypted wallets rebuild plaintext keys from these records on
            // unlock, so keep the disk form cached now (post-commit).
            if (pwallet->IsCrypted())
                pwallet->mapHybridKeyDisk[hybridID] = disk;
        }

        // ---- Register in memory only after the commit succeeds ----
        if (fPersistKeyRecord) {
            if (pwallet->IsCrypted())
                pwallet->LoadCryptedKey(secpKey.GetPubKey(),
                                        vchCryptedSecret);
            else
                pwallet->LoadKey(secpKey);
            pwallet->mapKeyMetadata[keyID] = keyMeta;
        }
        pwallet->mapHybridKeys.emplace(hybridID, std::move(hk));
        pwallet->mapHybridSigners.emplace(hybridID, std::move(signerCopy));

        // Mirrors SetHybridAddressBookName, but skips its own disk write
        // (already in the transaction above) and its mapHybridKeys check.
        if (!strLabel.empty())
            pwallet->mapHybridAddressBook[hybridID] =
                CHybridAddressEntry(strLabel);

        if (fRescan) {
            pwallet->UpdateTimeFirstKey();
            pwallet->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwallet->ReacceptWalletTransactions();
        }
    }

    return CCoinAddress(hybridID).ToString();
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

    string strWif   = params[0].get_str();
    string strDerB64 = params[1].get_str();

    string strLabel;
    if (params.size() > 2) strLabel = params[2].get_str();

    bool fRescan = true;
    if (params.size() > 3) fRescan = params[3].get_bool();

    return ImportHybridKeyFromComponents(pwalletMain, strWif, strDerB64,
                                         strLabel, fRescan, GetTime());
}

// ============================================================================
// HYBRID KEY FILE EXPORT / IMPORT (core, wallet-agnostic)
// ============================================================================
//
// These two functions are the non-RPC backbone used by both the RPC handlers
// (dumphybridkeys / importhybridkeys) and the Qt GUI (WalletModel). The file
// grammar matches the classic dumpwallet/importwallet format, extended with
// the ML-DSA half and the mldsa_alg marker.

bool DumpHybridKeys(CWallet* pwallet, const std::string& strDst,
                    std::string& strError)
{
    // Never overwrite an existing backup: a failed or partial export must not
    // clobber a previous good file. Enforced here, in the shared helper, so
    // every caller (RPC and Qt GUI alike) gets the same guarantee; there is no
    // check/TOCTOU split between an RPC pre-check and the actual write.
    if (boost::filesystem::exists(boost::filesystem::path(strDst))) {
        strError = "The file for wallet keys exists already";
        return false;
    }

    if (pwallet->IsCrypted() && pwallet->IsLocked())
    {
        strError = "Error: Please enter the wallet passphrase with "
                   "walletpassphrase first.";
        return false;
    }

    // Build every key's line while holding the wallet lock, so the export
    // stays consistent even if another thread allocates/rebalances the
    // hybrid key pool. Actual file I/O happens after the lock is released.
    // A backup must never silently omit a key: any serialization failure
    // marks the whole export as failed.
    bool fGood = true;
    int nSkipped = 0;
    std::vector<std::pair<int64, std::string> > vLines;
    {
        LOCK(pwallet->cs_wallet);

        for (std::map<CHybridKeyID, CHybridKey>::const_iterator hit =
                 pwallet->mapHybridKeys.begin();
             hit != pwallet->mapHybridKeys.end(); ++hit) {
            const CHybridKeyID& hybridID = hit->first;

            std::string wif;
            std::string derB64;
            try {
                EncodeHybridPrivKey(pwallet, hit->second, wif, derB64);
            } catch (const std::exception& e) {
                printf("DumpHybridKeys: skipping %s (%s)\n",
                       CCoinAddress(hybridID).ToString().c_str(), e.what());
                fGood = false;
                nSkipped++;
                continue;
            } catch (const Object&) {
                printf("DumpHybridKeys: skipping %s\n",
                       CCoinAddress(hybridID).ToString().c_str());
                fGood = false;
                nSkipped++;
                continue;
            }

            std::string strTime = EncodeDumpTimeHybrid(hit->second.nCreateTime);
            std::string strAddr = CCoinAddress(hybridID).ToString();

            std::string flags;
            std::map<CHybridKeyID, CHybridAddressEntry>::const_iterator ab =
                pwallet->mapHybridAddressBook.find(hybridID);
            if (ab != pwallet->mapHybridAddressBook.end() &&
                !ab->second.strLabel.empty()) {
                flags = strprintf("label=%s",
                                  EncodeDumpStringHybrid(ab->second.strLabel)
                                      .c_str());
            } else if (pwallet->setUnusedHybridKeys.count(hybridID)) {
                flags = "reserve=1";
            } else {
                flags = "change=1";
            }

            vLines.push_back(std::make_pair(
                hit->second.nCreateTime,
                strprintf("%s %s %s %s # addr=%s # mldsa_alg=%s\n",
                          wif.c_str(), derB64.c_str(), strTime.c_str(),
                          flags.c_str(), strAddr.c_str(),
                          hit->second.mldsaAlg.c_str())));
        }
    }

    if (!fGood) {
        // Never leave a partial private-key backup behind: the file may hold
        // an empty placeholder claimed earlier by the RPC wrapper. Remove it
        // so a failed export cannot be mistaken for a complete backup.
        boost::system::error_code ec;
        boost::filesystem::remove(boost::filesystem::path(strDst), ec);
        strError = strprintf(
            "%i hybrid key(s) could not be serialized and were skipped; no "
            "backup file was written (see debug log)",
            nSkipped);
        return false;
    }

    /* Sort time/key pairs so the file is deterministic for the same wallet. */
    std::sort(vLines.begin(), vLines.end());

    // Write to a temporary file in the same directory and rename it into place
    // only once it is complete and synced. A mid-write failure (e.g. a full
    // disk) can then never leave a partially written backup at the destination
    // path, and the stream state is checked so a failed write is reported
    // instead of a false success.
    const std::string strTmp = strDst + ".tmp";
    boost::system::error_code ec;

    boost::filesystem::ofstream file;
    file.open(boost::filesystem::path(strTmp), std::ios_base::out |
                                                   std::ios_base::trunc);
    if (!file.is_open()) {
        strError = "Cannot create the file for wallet keys";
        return false;
    }

    file << strprintf("# Hybrid wallet export created by Phoenixcoin %s (%s)\n",
                      CLIENT_BUILD_VERSION.c_str(),
                      CLIENT_BUILD_DATE_TIME.c_str());
    file << strprintf("# * Created on %s\n",
                      EncodeDumpTimeHybrid(GetTime()).c_str());
    file << strprintf("# * The best block at the creation time was %i (%s),\n",
                      nBestHeight, hashBestChain.ToString().c_str());
    file << strprintf("#   mined on %s\n",
                      EncodeDumpTimeHybrid(pindexBest ? pindexBest->nTime : 0)
                          .c_str());
    file << "# * Each line below is one hybrid key:\n";
    file << "#   <secp_wif> <mldsa_priv_der_b64> <created> "
            "[label=<label>|change=1|reserve=1] # addr=<hybrid address> "
            "# mldsa_alg=<alg>\n";
    file << "\n";

    for (std::vector<std::pair<int64, std::string> >::const_iterator it =
             vLines.begin();
         it != vLines.end(); ++it)
        file << it->second;

    file << "\n";
    file << "# End of hybrid export\n";

    file.flush();
    if (file.fail()) {
        file.close();
        boost::filesystem::remove(boost::filesystem::path(strTmp), ec);
        strError = "Failed while writing the hybrid key export";
        return false;
    }
    file.close();
    if (file.fail()) {
        boost::filesystem::remove(boost::filesystem::path(strTmp), ec);
        strError = "Failed while writing the hybrid key export";
        return false;
    }

    // Sync the temp file to disk before renaming it into place, so the target
    // name can never end up pointing at unsynced or partially flushed data.
    FILE* fCommit = fopen(strTmp.c_str(), "rb");
    if (!fCommit) {
        boost::filesystem::remove(boost::filesystem::path(strTmp), ec);
        strError = "Cannot open the file for syncing the hybrid key export";
        return false;
    }
    int nCommit = FileCommit(fCommit);
    fclose(fCommit);
    if (nCommit != 0) {
        boost::filesystem::remove(boost::filesystem::path(strTmp), ec);
        strError = "Failed to sync the hybrid key export to disk";
        return false;
    }

    boost::filesystem::rename(boost::filesystem::path(strTmp),
                              boost::filesystem::path(strDst), ec);
    if (ec) {
        boost::filesystem::remove(boost::filesystem::path(strTmp), ec);
        strError = "Failed to move the hybrid key export into place";
        return false;
    }

    return true;
}

bool ImportHybridKeysFile(CWallet* pwallet, const std::string& strSrc,
                          std::string& strError)
{
    if (pwallet->IsCrypted() && pwallet->IsLocked())
    {
        strError = "Error: Please enter the wallet passphrase with "
                   "walletpassphrase first.";
        return false;
    }

    ifstream file;
    file.open(strSrc.c_str());
    if (!file.is_open()) {
        strError = "Cannot open the file with wallet keys";
        return false;
    }

    int64 nTimeBegin = pindexBest ? pindexBest->nTime : GetTime();
    bool fGood = true;
    int nImported = 0;

    while (file.good()) {
        std::string line;
        std::getline(file, line);
        if (line.empty() || line[0] == '#')
            continue;

        std::vector<std::string> vstr;
        istringstream iss(line);
        copy(istream_iterator<string>(iss), istream_iterator<string>(),
             back_inserter(vstr));
        // A backup/restore format must not silently drop records: a non-
        // comment line that is not a valid key record (or carries a
        // timestamp we cannot parse) fails the whole import instead of
        // quietly disappearing.
        if (vstr.size() < 3) {
            printf("Malformed hybrid key line (expected <secp_wif> "
                   "<mldsa_priv_der_b64> <created> ...): '%s'\n",
                   line.c_str());
            fGood = false;
            continue;
        }

        const std::string& wif = vstr[0];
        const std::string& der = vstr[1];
        int64 nTime;
        if (!DecodeDumpTimeHybrid(vstr[2], nTime)) {
            printf("Hybrid key line has an invalid timestamp '%s': '%s'\n",
                   vstr[2].c_str(), line.c_str());
            fGood = false;
            continue;
        }
        // The wallet persists no hybrid key with a non-positive creation time
        // (see ValidateHybridKey), so a line whose timestamp is 0 or negative
        // is corrupt: reject it like any other bad timestamp instead of
        // failing deep inside the importer.
        if (nTime <= 0) {
            printf("Hybrid key line has an invalid timestamp '%s': '%s'\n",
                   vstr[2].c_str(), line.c_str());
            fGood = false;
            continue;
        }

        std::string strLabel;
        bool fLabel = false;
        for (size_t nStr = 3; nStr < vstr.size(); nStr++) {
            if (boost::algorithm::starts_with(vstr[nStr], "#"))
                break;
            if (vstr[nStr] == "change=1")
                fLabel = false;
            if (vstr[nStr] == "reserve=1")
                fLabel = false;
            if (boost::algorithm::starts_with(vstr[nStr], "label=")) {
                strLabel = DecodeDumpStringHybrid(vstr[nStr].substr(6));
                fLabel = true;
            }
        }
        if (!fLabel)
            strLabel.clear();

        try {
            std::string addr = ImportHybridKeyFromComponents(
                pwallet, wif, der, strLabel, false, nTime);
            printf("Importing hybrid key %s...\n", addr.c_str());
            nImported++;
        } catch (const std::exception& e) {
            printf("Failed to import hybrid key on line '%s': %s\n",
                   line.c_str(), e.what());
            fGood = false;
            continue;
        } catch (const Object& obj) {
            std::string strMsg;
            for (const Pair& p : obj) {
                if (p.name_ == "message")
                    strMsg = p.value_.get_str();
            }
            printf("Failed to import hybrid key on line '%s': %s\n",
                   line.c_str(), strMsg.c_str());
            fGood = false;
            continue;
        }
        nTimeBegin = std::min(nTimeBegin, nTime);
    }
    file.close();

    if (nImported > 0) {
        CBlockIndex* pindex = pindexBest;
        while (pindex && pindex->pprev &&
               (pindex->nTime > (nTimeBegin - 7200)))
            pindex = pindex->pprev;

        printf("Rescanning last %i blocks\n",
               pindexBest->nHeight - pindex->nHeight + 1);
        pwallet->ScanForWalletTransactions(pindex);
        pwallet->ReacceptWalletTransactions();
        pwallet->MarkDirty();
    }

    if (!fGood) {
        strError = "Some hybrid keys could not be imported (see log)";
        return false;
    }

    return true;
}

Value dumphybridkeys(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 1) {
        string msg =
            "dumphybridkeys <file>\n"
            "Dumps ALL hybrid private keys to a <file> in a human readable "
            "format.\n"
            "The file may be loaded again later with 'importhybridkeys'.\n"
            "The file name may be specified with a directory path.";
        throw runtime_error(msg);
    }

    EnsureWalletIsUnlocked();

    boost::filesystem::path pathDumpFile = params[0].get_str().c_str();
    if (!pathDumpFile.is_absolute())
        pathDumpFile = GetDataDir(true) / pathDumpFile;

    // Overwrite protection lives in DumpHybridKeys itself, so the Qt GUI and
    // the RPC share the same guarantee (and the RPC does no separate pre-check
    // that could diverge from what the write path actually enforces).
    std::string strError;
    if (!DumpHybridKeys(pwalletMain, pathDumpFile.string(), strError))
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return Value::null;
}

Value importhybridkeys(const Array& params, bool fHelp) {
    if (fHelp || params.size() != 1) {
        string msg =
            "importhybridkeys <file>\n"
            "Imports hybrid private keys from a <file> generated by RPC "
            "'dumphybridkeys'.\n"
            "The file name may be specified with a directory path.";
        throw runtime_error(msg);
    }

    EnsureWalletIsUnlocked();

    boost::filesystem::path pathImportFile = params[0].get_str().c_str();
    if (!pathImportFile.is_absolute())
        pathImportFile = GetDataDir(true) / pathImportFile;
    if (!boost::filesystem::exists(pathImportFile))
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "The file with wallet keys doesn't exist");

    std::string strError;
    if (!ImportHybridKeysFile(pwalletMain, pathImportFile.string(), strError))
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    return Value::null;
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
