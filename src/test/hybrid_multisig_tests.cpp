#include <boost/test/unit_test.hpp>

#include <cstring>
#include <algorithm>
#include <memory>

#include "main.h"
#include "script.h"
#include "keystore.h"
#include "hs/hybrid_signer.h"
#include "hs/wallethybrid.h"
#include "wallet.h"
#include "crypter.h"

#include <openssl/rand.h>
#include <openssl/evp.h>

extern uint256 SignatureHash(CScript scriptCode,
                            const CTransaction& txTo,
                            unsigned int nIn,
                            int nHashType);

BOOST_AUTO_TEST_CASE(hybrid_multisig_sighash_types)
{
    /*
     * Regression test for OP_CHECKMULTIHYBRIDSIG sighash handling.
     *
     * The signatures are created with nHashType == 0 at script
     * verification time, so the opcode must obtain the sighash type
     * from the final byte of the signatures themselves.
     *
     * Test:
     *   SIGHASH_ALL
     *   SIGHASH_NONE
     *   SIGHASH_SINGLE
     *   SIGHASH_ALL | SIGHASH_ANYONECANPAY
     */

    CKey ecdsaKey;
    ecdsaKey.MakeNewKey(true);

    std::unique_ptr<MLDSASigner> mldsaSigner =
        MLDSASigner::GenerateNew();

    BOOST_REQUIRE(mldsaSigner);

    const std::vector<unsigned char> ecdsaPub =
        ecdsaKey.GetPubKey().Raw();

    const std::vector<unsigned char> mldsaPub =
        mldsaSigner->GetPublicKey();

    BOOST_REQUIRE_EQUAL(ecdsaPub.size(), 33U);
    BOOST_REQUIRE_EQUAL(mldsaPub.size(), 1952U);

    /*
     * Build the 1-of-1 hybrid multisig script explicitly.
     *
     * The OP_CHECKMULTIHYBRIDSIG implementation expects the ECDSA
     * and ML-DSA public keys as separate stack items.
     */
    CScript scriptPubKey;
    scriptPubKey
        << OP_1
        << ecdsaPub
        << mldsaPub
        << OP_1
        << OP_CHECKMULTIHYBRIDSIG;

    /*
     * Transaction with one input and two outputs.
     *
     * Two outputs are important so SIGHASH_SINGLE at input 0 has a
     * corresponding output.
     */
    CTransaction tx;
    tx.vin.resize(1);
    tx.vout.resize(2);

    tx.vin[0].prevout.n = 0;
    tx.vin[0].prevout.hash = uint256(1);

    tx.vout[0].nValue = 100;
    tx.vout[1].nValue = 200;

    const int hashTypes[] = {
        SIGHASH_ALL,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY
    };

    for (size_t testIndex = 0;
         testIndex < sizeof(hashTypes) / sizeof(hashTypes[0]);
         ++testIndex) {

        const int hashType = hashTypes[testIndex];

        /*
         * Compute exactly the sighash that the consensus opcode
         * must use.
         */
        uint256 sighash =
            SignatureHash(scriptPubKey, tx, 0, hashType);

        /*
         * ECDSA component.
         */
        std::vector<unsigned char> sigEC;

        BOOST_REQUIRE(
            ecdsaKey.Sign(sighash, sigEC));

        sigEC.push_back((unsigned char)hashType);

        /*
         * ML-DSA signs the domain-separated canonical sighash preimage.
         * This must exactly match OP_CHECKMULTIHYBRIDSIG verification.
         */
        std::vector<unsigned char> sighash_preimage;

        BOOST_REQUIRE(
            ConstructSignatureHashPreimage(
                scriptPubKey,
                tx,
                0,
                hashType,
                sighash_preimage));

        std::vector<unsigned char> hybridMsg =
            BuildHybridMessage(sighash_preimage);

        std::vector<unsigned char> sigML;

        BOOST_REQUIRE(
            mldsaSigner->Sign(hybridMsg, sigML));

        sigML.push_back((unsigned char)hashType);

        /*
         * ScriptSig:
         *
         *   <ECDSA signature>
         *   <ML-DSA signature>
         *
         * The scriptPubKey then supplies:
         *
         *   1
         *   <ECDSA pubkey>
         *   <ML-DSA pubkey>
         *   1
         *   OP_CHECKMULTIHYBRIDSIG
         */
        CScript scriptSig;
        scriptSig
            << sigEC
            << sigML;

        /*
         * IMPORTANT:
         *
         * nHashType is deliberately ZERO here.
         *
         * This forces OP_CHECKMULTIHYBRIDSIG to obtain the actual
         * sighash type from the signature's final byte.
         *
         * The old implementation fails this regression because it
         * precomputed SignatureHash(..., 0).
         */
        BOOST_CHECK_MESSAGE(
            VerifyScript(
                scriptSig,
                scriptPubKey,
                tx,
                0,
                true,
                0),
            strprintf(
                "OP_CHECKMULTIHYBRIDSIG failed for sighash type 0x%02x",
                hashType));
    }
}

class CHybridTestKeyStore : public CBasicKeyStore
{
private:
    std::map<CHybridKeyID, CHybridKey> mapHybridKeys;

public:
    bool AddHybridKey(CHybridKey& key)
    {
        LOCK(cs_KeyStore);
        mapHybridKeys.emplace(key.GetHybridID(), std::move(key));
        return true;
    }

    virtual bool HaveHybridKey(const CHybridKeyID& address) const override
    {
        LOCK(cs_KeyStore);
        return mapHybridKeys.count(address) > 0;
    }

    virtual bool HaveHybridKeyByHash(const uint160& keyHash) const override
    {
        LOCK(cs_KeyStore);
        return mapHybridKeys.count(CHybridKeyID(keyHash)) > 0;
    }

    virtual bool HaveHybridKeyByLegacyID(const CKeyID& keyID) const override
    {
        LOCK(cs_KeyStore);
        for (const auto& entry : mapHybridKeys)
            if (entry.second.GetKeyID() == keyID)
                return true;
        return false;
    }

    virtual bool GetHybridKey(const CHybridKeyID& address,
                              CHybridKey& keyOut) const override
    {
        LOCK(cs_KeyStore);
        std::map<CHybridKeyID, CHybridKey>::const_iterator it =
            mapHybridKeys.find(address);
        if (it == mapHybridKeys.end())
            return false;

        keyOut.secpPriv = it->second.secpPriv;
        keyOut.secpPub = it->second.secpPub;
        keyOut.mldsaAlg = it->second.mldsaAlg;
        keyOut.nCreateTime = it->second.nCreateTime;
        keyOut.mldsaSigner = GetSignerFromKey(it->second);
        return keyOut.mldsaSigner != NULL;
    }

    virtual bool GetHybridKeyByHash(const uint160& keyHash,
                                    CHybridKey& keyOut) const override
    {
        return GetHybridKey(CHybridKeyID(keyHash), keyOut);
    }

    virtual bool GetHybridKeyByLegacyID(const CKeyID& keyID,
                                        CHybridKey& keyOut) const override
    {
        LOCK(cs_KeyStore);
        for (const auto& entry : mapHybridKeys)
            if (entry.second.GetKeyID() == keyID)
            {
                keyOut.secpPriv = entry.second.secpPriv;
                keyOut.secpPub = entry.second.secpPub;
                keyOut.mldsaAlg = entry.second.mldsaAlg;
                keyOut.nCreateTime = entry.second.nCreateTime;
                keyOut.mldsaSigner = GetSignerFromKey(entry.second);
                return keyOut.mldsaSigner != NULL;
            }
        return false;
    }
};

class CLockedHybridTestKeyStore : public CHybridTestKeyStore
{
public:
    virtual bool IsLocked() const override { return true; }
};

static std::vector<CHybridPubKey> BuildTestHybridPubs(CHybridTestKeyStore& store,
                                                      int nKeys)
{
    std::vector<CHybridPubKey> pubs;
    for (int i = 0; i < nKeys; ++i) {
        CHybridKey hk;
        GenerateHybridKey(hk);
        pubs.push_back(CHybridPubKey(hk.secpPub.Raw(),
                                     hk.mldsaSigner->GetPublicKey()));
        store.AddHybridKey(hk);
    }
    return pubs;
}

static bool GetHybridKey(const CHybridTestKeyStore& store,
                         const CHybridPubKey& pub, CHybridKey& keyOut)
{
    return store.GetHybridKeyByLegacyID(CPubKey(pub.ecdsaPubKey).GetID(), keyOut);
}

static CScript SignHybridPair(const CHybridKey& key,
                              const CScript& scriptPubKey,
                              const CTransaction& txTo,
                              unsigned int nIn,
                              int nHashType,
                              std::vector<unsigned char>& ecSigOut,
                              std::vector<unsigned char>& mlSigOut)
{
    uint256 sighash = SignatureHash(scriptPubKey, txTo, nIn, nHashType);

    std::vector<unsigned char> preimage;
    if (!ConstructSignatureHashPreimage(scriptPubKey, txTo, nIn, nHashType, preimage))
        return CScript();

    std::vector<unsigned char> msg = BuildHybridMessage(preimage);

    std::vector<unsigned char> ecSig;
    if (!key.GetCKey().Sign(sighash, ecSig))
        return CScript();
    ecSig.push_back((unsigned char)nHashType);

    std::vector<unsigned char> mlSig;
    if (!key.mldsaSigner || !key.mldsaSigner->Sign(msg, mlSig))
        return CScript();
    mlSig.push_back((unsigned char)nHashType);

    ecSigOut = ecSig;
    mlSigOut = mlSig;

    CScript ret;
    ret << ecSig << mlSig;
    return ret;
}

static void MakeHybridSpend(const CScript& script,
                            CTransaction& txFrom, CTransaction& txTo)
{
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey = script;

    txTo.vin.resize(1);
    txTo.vout.resize(1);
    txTo.vin[0].prevout.hash = txFrom.GetHash();
    txTo.vin[0].prevout.n = 0;
}

static bool SetupEncryptedTestWallet(CWallet& wallet, CKey& keyOut,
                                     CMasterKey& masterKeyOut)
{
    keyOut.MakeNewKey(true);

    CKeyingMaterial vMasterKey;
    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    masterKeyOut.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    RAND_bytes(&masterKeyOut.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);
    masterKeyOut.nDeriveIterations = 25000;
    masterKeyOut.nDerivationMethod = 0;

    SecureString pass("correct horse battery staple\n");

    CCrypter crypter;
    if (!crypter.SetKeyFromPassphrase(pass, masterKeyOut.vchSalt,
                                      masterKeyOut.nDeriveIterations,
                                      masterKeyOut.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, masterKeyOut.vchCryptedKey))
        return false;

    bool fCompressed;
    CSecret vchSecret = keyOut.GetSecret(fCompressed);
    std::vector<unsigned char> vchCryptedSecret;
    if (!EncryptSecret(vMasterKey, vchSecret, keyOut.GetPubKey().GetHash(),
                       vchCryptedSecret))
        return false;
    if (!wallet.AddCryptedKey(keyOut.GetPubKey(), vchCryptedSecret))
        return false;

    wallet.mapMasterKeys[0] = masterKeyOut;
    wallet.nMasterKeyMaxID = 1;
    return true;
}

static CScript SignHybridPartial(const CHybridKey& key,
                                 const CScript& scriptPubKey,
                                 const CTransaction& txTo,
                                 unsigned int nIn,
                                 int nHashType)
{
    std::vector<unsigned char> ecSig, mlSig;
    return SignHybridPair(key, scriptPubKey, txTo, nIn, nHashType, ecSig, mlSig);
}

BOOST_AUTO_TEST_CASE(hybrid_multisig_ismine_and_spend)
{
    CHybridTestKeyStore keystore;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 3);

    CScript inner = GetScriptForHybridMultisig(2, pubs);
    BOOST_REQUIRE(!inner.empty());

    CHybridTestKeyStore partial;
    {
        CHybridKey one;
        GenerateHybridKey(one);
        partial.AddHybridKey(one);
    }

    CHybridTestKeyStore empty;
    BOOST_CHECK(IsMine(partial, inner) == MINE_NO);
    BOOST_CHECK(IsMine(empty, inner) == MINE_NO);

    BOOST_CHECK(IsMine(keystore, inner) == MINE_SPENDABLE);

    CTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey = inner;

    CTransaction txTo;
    txTo.vin.resize(1);
    txTo.vout.resize(1);
    txTo.vin[0].prevout.hash = txFrom.GetHash();
    txTo.vin[0].prevout.n = 0;

    BOOST_CHECK(SignSignature(keystore, txFrom, txTo, 0, SIGHASH_ALL));
    BOOST_CHECK(VerifyScript(txTo.vin[0].scriptSig, inner, txTo, 0, false, 0));
}

BOOST_AUTO_TEST_CASE(hybrid_multisig_p2sh_ismine_and_spend)
{
    CHybridTestKeyStore keystore;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 2);

    CScript inner = GetScriptForHybridMultisig(2, pubs);
    BOOST_REQUIRE(!inner.empty());

    keystore.AddCScript(inner);

    CScript p2sh;
    p2sh << OP_HASH160 << inner.GetID() << OP_EQUAL;

    BOOST_CHECK(IsMine(keystore, p2sh) == MINE_SPENDABLE);

    CTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey = p2sh;

    CTransaction txTo;
    txTo.vin.resize(1);
    txTo.vout.resize(1);
    txTo.vin[0].prevout.hash = txFrom.GetHash();
    txTo.vin[0].prevout.n = 0;

    BOOST_CHECK(SignSignature(keystore, txFrom, txTo, 0, SIGHASH_ALL));
    BOOST_CHECK(VerifyScript(txTo.vin[0].scriptSig, p2sh, txTo, 0, true, 0));
}

BOOST_AUTO_TEST_CASE(hybrid_multisig_locked_ismine)
{
    CLockedHybridTestKeyStore keystore;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 2);

    CScript inner = GetScriptForHybridMultisig(2, pubs);
    BOOST_REQUIRE(!inner.empty());

    BOOST_CHECK(IsMine(keystore, inner) == MINE_NO);
}

BOOST_AUTO_TEST_CASE(hybrid_multisig_combine_partial)
{
    CHybridTestKeyStore keystore;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 3);

    CScript inner = GetScriptForHybridMultisig(2, pubs);
    BOOST_REQUIRE(!inner.empty());

    CTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey = inner;

    CTransaction txTo;
    txTo.vin.resize(1);
    txTo.vout.resize(1);
    txTo.vin[0].prevout.hash = txFrom.GetHash();
    txTo.vin[0].prevout.n = 0;

    CHybridKey key0, key1;
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[0], key0));
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[1], key1));

    CScript sigA = SignHybridPartial(key0, inner, txTo, 0, SIGHASH_ALL);
    CScript sigB = SignHybridPartial(key1, inner, txTo, 0, SIGHASH_ALL);
    BOOST_REQUIRE(!sigA.empty());
    BOOST_REQUIRE(!sigB.empty());

    BOOST_CHECK(!VerifyScript(sigA, inner, txTo, 0, false, 0));
    BOOST_CHECK(!VerifyScript(sigB, inner, txTo, 0, false, 0));

    CScript combined = CombineSignatures(inner, txTo, 0, sigA, sigB);
    BOOST_CHECK(combined != sigA);
    BOOST_CHECK(combined != sigB);
    BOOST_CHECK(VerifyScript(combined, inner, txTo, 0, false, 0));

    BOOST_CHECK(!VerifyScript(CombineSignatures(inner, txTo, 0, sigA, sigA),
                              inner, txTo, 0, false, 0));

    keystore.AddCScript(inner);

    CScript p2sh;
    p2sh << OP_HASH160 << inner.GetID() << OP_EQUAL;

    CTransaction txFromP2;
    txFromP2.vout.resize(1);
    txFromP2.vout[0].scriptPubKey = p2sh;

    CTransaction txToP2;
    txToP2.vin.resize(1);
    txToP2.vout.resize(1);
    txToP2.vin[0].prevout.hash = txFromP2.GetHash();
    txToP2.vin[0].prevout.n = 0;

    CScript sigAP2 = SignHybridPartial(key0, inner, txToP2, 0, SIGHASH_ALL);
    CScript sigBP2 = SignHybridPartial(key1, inner, txToP2, 0, SIGHASH_ALL);
    std::vector<unsigned char> sub(inner.begin(), inner.end());
    sigAP2 << sub;
    sigBP2 << sub;

    CScript combinedP2 = CombineSignatures(p2sh, txToP2, 0, sigAP2, sigBP2);
    BOOST_CHECK(VerifyScript(combinedP2, p2sh, txToP2, 0, true, 0));
}

/*
 * Regression test: the hybrid multisig combining layer must require BOTH
 * the ECDSA and the ML-DSA half of a signature pair to verify before the
 * pair is accepted and propagated into the combined scriptSig.
 *
 * Previously only the ECDSA half was checked, so a pair consisting of a
 * valid ECDSA signature and an invalid ML-DSA signature was accepted by
 * the combiner and carried into the resulting scriptSig.
 */
BOOST_AUTO_TEST_CASE(hybrid_multisig_combine_rejects_invalid_mldsa)
{
    CHybridTestKeyStore keystore;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 3);

    CScript inner = GetScriptForHybridMultisig(2, pubs);
    BOOST_REQUIRE(!inner.empty());

    CTransaction txFrom, txTo;
    MakeHybridSpend(inner, txFrom, txTo);

    CHybridKey key0;
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[0], key0));

    std::vector<unsigned char> ecSig, mlSig;
    CScript valid = SignHybridPair(key0, inner, txTo, 0, SIGHASH_ALL, ecSig, mlSig);
    BOOST_REQUIRE(!valid.empty());
    BOOST_REQUIRE(!ecSig.empty());
    BOOST_REQUIRE(!mlSig.empty());

    // Keep the ECDSA half valid but corrupt the ML-DSA half. The byte used
    // is in the middle of the signature so the length and the trailing
    // sighash-type byte are preserved.
    std::vector<unsigned char> badMl = mlSig;
    badMl[badMl.size() / 2] ^= 0x01;

    CScript badPair;
    badPair << ecSig << badMl;

    // The tampered pair is rejected by consensus (both halves must verify).
    BOOST_CHECK(!VerifyScript(badPair, inner, txTo, 0, false, 0));

    // Combining the valid pair with the tampered pair must not accept the
    // tampered ML-DSA half, even though the ECDSA half verifies.
    CScript combined = CombineSignatures(inner, txTo, 0, valid, badPair);
    BOOST_CHECK(combined != badPair);

    // The combined script still cannot satisfy the 2-of-3 requirement.
    BOOST_CHECK(!VerifyScript(combined, inner, txTo, 0, false, 0));

    // The tampered ML-DSA material must not have been propagated.
    std::vector<unsigned char> combinedBytes(combined.begin(), combined.end());
    BOOST_CHECK(std::search(combinedBytes.begin(), combinedBytes.end(),
                            badMl.begin(), badMl.end()) == combinedBytes.end());

    // A combiner that received only the tampered pair produces nothing.
    CScript onlyBad = CombineSignatures(inner, txTo, 0, badPair, badPair);
    BOOST_CHECK(onlyBad.empty() || !VerifyScript(onlyBad, inner, txTo, 0, false, 0));
    std::vector<unsigned char> onlyBadBytes(onlyBad.begin(), onlyBad.end());
    BOOST_CHECK(std::search(onlyBadBytes.begin(), onlyBadBytes.end(),
                            badMl.begin(), badMl.end()) == onlyBadBytes.end());
}

BOOST_AUTO_TEST_CASE(hybrid_multisig_m_of_n_combinations)
{
    CHybridTestKeyStore keystore;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 3);

    for (int m = 1; m <= 3; ++m) {
        CScript inner = GetScriptForHybridMultisig(m, pubs);
        BOOST_REQUIRE(!inner.empty());

        CTransaction txFrom;
        txFrom.vout.resize(1);
        txFrom.vout[0].scriptPubKey = inner;

        CTransaction txTo;
        txTo.vin.resize(1);
        txTo.vout.resize(1);
        txTo.vin[0].prevout.hash = txFrom.GetHash();
        txTo.vin[0].prevout.n = 0;

        CScript scriptSig;
        for (int i = 0; i < m; ++i) {
            CHybridKey key;
            BOOST_REQUIRE(GetHybridKey(keystore, pubs[i], key));
            CScript partial = SignHybridPartial(key, inner, txTo, 0, SIGHASH_ALL);
            BOOST_REQUIRE(!partial.empty());
            scriptSig += partial;
        }

        BOOST_CHECK(VerifyScript(scriptSig, inner, txTo, 0, false, 0));

        for (int k = m - 1; k >= 1; --k) {
            CScript tooFew;
            for (int i = 0; i < k; ++i) {
                CHybridKey key;
                BOOST_REQUIRE(GetHybridKey(keystore, pubs[i], key));
                tooFew += SignHybridPartial(key, inner, txTo, 0, SIGHASH_ALL);
            }
            BOOST_CHECK(!VerifyScript(tooFew, inner, txTo, 0, false, 0));
        }
    }
}

BOOST_AUTO_TEST_CASE(hybrid_multisig_pair_order_and_mismatch)
{
    CHybridTestKeyStore keystore;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 3);

    CScript inner = GetScriptForHybridMultisig(2, pubs);
    BOOST_REQUIRE(!inner.empty());

    CTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey = inner;

    CTransaction txTo;
    txTo.vin.resize(1);
    txTo.vout.resize(1);
    txTo.vin[0].prevout.hash = txFrom.GetHash();
    txTo.vin[0].prevout.n = 0;

    CHybridKey key0, key1, key2;
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[0], key0));
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[1], key1));
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[2], key2));

    std::vector<unsigned char> ec0, ml0, ec1, ml1;
    BOOST_REQUIRE(!SignHybridPair(key0, inner, txTo, 0, SIGHASH_ALL, ec0, ml0).empty());
    BOOST_REQUIRE(!SignHybridPair(key1, inner, txTo, 0, SIGHASH_ALL, ec1, ml1).empty());

    // Correct pair order (ECDSA, then ML-DSA) verifies.
    CScript correct;
    correct << ec0 << ml0 << ec1 << ml1;
    BOOST_CHECK(VerifyScript(correct, inner, txTo, 0, false, 0));

    // Reversed order within each pair (ML-DSA first) must be rejected.
    CScript reversed;
    reversed << ml0 << ec0 << ml1 << ec1;
    BOOST_CHECK(!VerifyScript(reversed, inner, txTo, 0, false, 0));

    // Mismatched pair: ECDSA half belongs to key0, ML-DSA half to key1.
    CScript mismatched;
    mismatched << ec0 << ml1;
    BOOST_CHECK(!VerifyScript(mismatched, inner, txTo, 0, false, 0));

    // Mismatched pair cannot be rescued by adding a second valid pair.
    CScript mismatchedFull;
    mismatchedFull << ec0 << ml1 << ec1 << ml1;
    BOOST_CHECK(!VerifyScript(mismatchedFull, inner, txTo, 0, false, 0));
}

BOOST_AUTO_TEST_CASE(hybrid_multisig_signature_argument_limits)
{
    CHybridTestKeyStore keystore;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 3);

    std::vector<CHybridPubKey> pubs2(pubs.begin(), pubs.begin() + 2);

    CScript inner22 = GetScriptForHybridMultisig(2, pubs2);
    CScript inner11 = GetScriptForHybridMultisig(1, pubs2);
    BOOST_REQUIRE(!inner22.empty());
    BOOST_REQUIRE(!inner11.empty());

    CTransaction txFrom22, txTo22;
    MakeHybridSpend(inner22, txFrom22, txTo22);
    CTransaction txFrom11, txTo11;
    MakeHybridSpend(inner11, txFrom11, txTo11);

    CHybridKey key0, key1;
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[0], key0));
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[1], key1));

    std::vector<unsigned char> ec0, ml0, ec1, ml1;
    BOOST_REQUIRE(!SignHybridPair(key0, inner22, txTo22, 0, SIGHASH_ALL, ec0, ml0).empty());
    BOOST_REQUIRE(!SignHybridPair(key1, inner22, txTo22, 0, SIGHASH_ALL, ec1, ml1).empty());

    // Full 2-of-2 must verify.
    CScript ok22;
    ok22 << ec0 << ml0 << ec1 << ml1;
    BOOST_CHECK(VerifyScript(ok22, inner22, txTo22, 0, false, 0));

    // Missing: only one pair supplied for a 2-of-2.
    CScript missing22;
    missing22 << ec0 << ml0;
    BOOST_CHECK(!VerifyScript(missing22, inner22, txTo22, 0, false, 0));

    // Malformed: garbage ML-DSA half in the first pair.
    std::vector<unsigned char> garbage(64, 0x42);
    CScript malformedML22;
    malformedML22 << ec0 << garbage << ec1 << ml1;
    BOOST_CHECK(!VerifyScript(malformedML22, inner22, txTo22, 0, false, 0));

    // Malformed: garbage ECDSA half in the first pair.
    CScript malformedEC22;
    malformedEC22 << garbage << ml0 << ec1 << ml1;
    BOOST_CHECK(!VerifyScript(malformedEC22, inner22, txTo22, 0, false, 0));

    // Malformed: empty element within a pair.
    CScript emptyElem22;
    emptyElem22 << ec0 << OP_0 << ec1 << ml1;
    BOOST_CHECK(!VerifyScript(emptyElem22, inner22, txTo22, 0, false, 0));

    std::vector<unsigned char> fec0, fml0, fec1, fml1;
    BOOST_REQUIRE(!SignHybridPair(key0, inner11, txTo11, 0, SIGHASH_ALL, fec0, fml0).empty());
    BOOST_REQUIRE(!SignHybridPair(key1, inner11, txTo11, 0, SIGHASH_ALL, fec1, fml1).empty());

    // Full 1-of-2 must verify.
    CScript one11;
    one11 << fec0 << fml0;
    BOOST_CHECK(VerifyScript(one11, inner11, txTo11, 0, false, 0));

    // Extra: two pairs supplied for a 1-of-2.  Consensus accepts the
    // spend (no cleanstack requirement), but standardness rejects it
    // because the stack size does not match nArgsExpected == 2*m.
    CScript extra11;
    extra11 << fec0 << fml0 << fec1 << fml1;
    BOOST_CHECK(VerifyScript(extra11, inner11, txTo11, 0, false, 0));

    std::map<uint256, std::pair<CTxIndex, CTransaction> > mapInputs;
    mapInputs[txFrom11.GetHash()] = std::make_pair(CTxIndex(), txFrom11);

    CTransaction txToStd;
    txToStd.vin.resize(1);
    txToStd.vout.resize(1);
    txToStd.vin[0].prevout.hash = txFrom11.GetHash();
    txToStd.vin[0].prevout.n = 0;

    txToStd.vin[0].scriptSig = one11;
    BOOST_CHECK(txToStd.AreInputsStandard(mapInputs));

    txToStd.vin[0].scriptSig = extra11;
    BOOST_CHECK(!txToStd.AreInputsStandard(mapInputs));
}

BOOST_AUTO_TEST_CASE(wallet_crypto_unlock_failure_keeps_locked)
{
    CWallet wallet;

    CKey key;
    CMasterKey kMasterKey;
    BOOST_REQUIRE(SetupEncryptedTestWallet(wallet, key, kMasterKey));

    SecureString pass("correct horse battery staple\n");
    SecureString wrong("wrong passphrase\n");

    BOOST_CHECK(wallet.IsCrypted());
    BOOST_CHECK(wallet.IsLocked());

    CKey keyOut;
    BOOST_CHECK(!wallet.GetKey(key.GetPubKey().GetID(), keyOut));

    BOOST_CHECK(!wallet.Unlock(wrong));
    BOOST_CHECK(wallet.IsLocked());
    BOOST_CHECK(!wallet.GetKey(key.GetPubKey().GetID(), keyOut));

    BOOST_CHECK(wallet.Unlock(pass));
    BOOST_CHECK(!wallet.IsLocked());
    BOOST_CHECK(wallet.GetKey(key.GetPubKey().GetID(), keyOut));
    BOOST_CHECK(keyOut.GetPubKey() == key.GetPubKey());

    wallet.Lock();
    BOOST_CHECK(wallet.IsLocked());
    BOOST_CHECK(!wallet.GetKey(key.GetPubKey().GetID(), keyOut));
}

BOOST_AUTO_TEST_CASE(hybrid_key_plaintext_to_encrypted_migration)
{
    CHybridKey plainKey;
    GenerateHybridKey(plainKey);
    BOOST_REQUIRE(plainKey.mldsaSigner);

    CKeyingMaterial vMasterKey;
    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CKeyingMaterial wrongKey;
    wrongKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&wrongKey[0], WALLET_CRYPTO_KEY_SIZE);
    if (wrongKey == vMasterKey)
        wrongKey[0] ^= 0x01;

    // Plaintext at-rest record (pre-encryption form).
    CHybridKeyDisk plainDisk = CHybridKeyDisk::FromMemory(plainKey);
    BOOST_CHECK(!plainDisk.IsEncrypted());
    BOOST_CHECK(plainDisk.CheckChecksum());
    BOOST_CHECK(plainDisk.secpPub == plainKey.secpPub);

    CPrivKey plainSecpOut;
    std::vector<unsigned char> plainMldsaOut;
    BOOST_CHECK(plainDisk.DecryptPrivate(vMasterKey, plainSecpOut, plainMldsaOut));
    BOOST_CHECK(plainSecpOut == plainKey.secpPriv);
    BOOST_CHECK(!plainMldsaOut.empty());

    // Migration to the encrypted at-rest record.
    CHybridKeyDisk encDisk = CHybridKeyDisk::FromMemoryEncrypted(plainKey, vMasterKey);
    BOOST_CHECK(encDisk.IsEncrypted());
    BOOST_CHECK(encDisk.CheckChecksum());
    BOOST_CHECK(encDisk.secpPub == plainKey.secpPub);
    BOOST_CHECK(!encDisk.vchCryptedPrivate.empty());

    // The encrypted record must still round-trip the private material when
    // decrypted with the correct master key.
    CPrivKey secpOut;
    std::vector<unsigned char> mldsaOut;
    BOOST_CHECK(encDisk.DecryptPrivate(vMasterKey, secpOut, mldsaOut));
    BOOST_CHECK(secpOut == plainKey.secpPriv);

    // The decrypted MLDSA private key reproduces the original public key.
    const unsigned char* p = mldsaOut.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, mldsaOut.size());
    BOOST_REQUIRE(pkey);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkeyGuard(pkey, &EVP_PKEY_free);
    MLDSASigner recovered(pkey);
    BOOST_CHECK(recovered.GetPublicKey() == plainKey.mldsaSigner->GetPublicKey());

    // Neither the encrypted blob nor the full record contains the plaintext.
    CDataStream plainTuple(SER_DISK, CLIENT_VERSION);
    plainTuple << secpOut << mldsaOut;
    std::vector<unsigned char> tupleBytes(plainTuple.begin(), plainTuple.end());

    BOOST_CHECK(std::search(encDisk.vchCryptedPrivate.begin(),
                            encDisk.vchCryptedPrivate.end(),
                            tupleBytes.begin(), tupleBytes.end()) ==
                encDisk.vchCryptedPrivate.end());

    CDataStream rawRecord(SER_DISK, CLIENT_VERSION);
    rawRecord << encDisk;
    std::vector<unsigned char> rawBytes(rawRecord.begin(), rawRecord.end());
    BOOST_CHECK(std::search(rawBytes.begin(), rawBytes.end(),
                            tupleBytes.begin(), tupleBytes.end()) ==
                rawBytes.end());

    // A wrong master key must not reproduce the original private material.
    CPrivKey junkSecp;
    std::vector<unsigned char> junkMldsa;
    BOOST_CHECK(!(encDisk.DecryptPrivate(wrongKey, junkSecp, junkMldsa) &&
                  junkSecp == plainKey.secpPriv));

    // Tampering with the encrypted blob breaks the checksum.
    CHybridKeyDisk tampered = encDisk;
    tampered.vchCryptedPrivate[tampered.vchCryptedPrivate.size() / 2] ^= 0x01;
    BOOST_CHECK(!tampered.CheckChecksum());

    // Migration without an unlocked master key is refused.
    CKeyingMaterial noKey;
    BOOST_CHECK_THROW(CHybridKeyDisk::FromMemoryEncrypted(plainKey, noKey),
                      std::runtime_error);

    // CWallet::MakeHybridKeyDisk: plaintext wallet keeps plaintext records.
    CWallet wallet;
    CHybridKeyDisk walletPlain = wallet.MakeHybridKeyDisk(plainKey);
    BOOST_CHECK(!walletPlain.IsEncrypted());
    BOOST_CHECK(walletPlain.CheckChecksum());

    // Encrypted but locked wallet throws when migrating a plaintext key.
    CKey walletKey;
    CMasterKey kMasterKey;
    BOOST_REQUIRE(SetupEncryptedTestWallet(wallet, walletKey, kMasterKey));
    BOOST_CHECK_THROW(wallet.MakeHybridKeyDisk(plainKey), std::runtime_error);

    // Unlocked wallet migrates the key to an encrypted at-rest record using
    // the wallet master key.
    SecureString pass("correct horse battery staple\n");
    BOOST_CHECK(wallet.Unlock(pass));
    CHybridKeyDisk walletEnc = wallet.MakeHybridKeyDisk(plainKey);
    BOOST_CHECK(walletEnc.IsEncrypted());
    BOOST_CHECK(walletEnc.CheckChecksum());

    // Recover the wallet master key from the passphrase and verify the
    // migrated record decrypts back to the original private material.
    CCrypter crypter;
    CKeyingMaterial unlockedMaster;
    BOOST_REQUIRE(crypter.SetKeyFromPassphrase(pass, kMasterKey.vchSalt,
                                               kMasterKey.nDeriveIterations,
                                               kMasterKey.nDerivationMethod));
    BOOST_REQUIRE(crypter.Decrypt(kMasterKey.vchCryptedKey, unlockedMaster));

    CPrivKey wSecp;
    std::vector<unsigned char> wMldsa;
    BOOST_CHECK(walletEnc.DecryptPrivate(unlockedMaster, wSecp, wMldsa));
    BOOST_CHECK(wSecp == plainKey.secpPriv);
}

/*
 * Regression test: GetScriptForHybridMultisig / addhybridmultisigaddress
 * must not reach CScript::EncodeOP_N (which ASSERTS on n outside 1..16)
 * with an out-of-range key count or required count.
 *
 * An RPC caller could previously supply nRequired = 17, or 17 keys, and
 * trigger the assertion (daemon crash / DoS). The constructor is now
 * defensive and returns an empty script, and the RPC rejects explicitly.
 */
BOOST_AUTO_TEST_CASE(hybrid_multisig_script_size_limits)
{
    for (int nKeys : { 17, 32 }) {
        CHybridTestKeyStore store;
        std::vector<CHybridPubKey> pubs =
            BuildTestHybridPubs(store, nKeys);
        BOOST_REQUIRE_EQUAL((int)pubs.size(), nKeys);

        // nRequired within range but too many keys -> rejected (empty).
        for (int nReq = 1; nReq <= 16; ++nReq) {
            if (nReq <= nKeys) {
                BOOST_CHECK(GetScriptForHybridMultisig(nReq, pubs).empty());
            }
        }

        // nRequired > 16 -> rejected (empty), regardless of key count.
        BOOST_CHECK(GetScriptForHybridMultisig(17, pubs).empty());
        BOOST_CHECK(GetScriptForHybridMultisig(100, pubs).empty());
    }

    // nRequired < 1 -> rejected.
    CHybridTestKeyStore store;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(store, 2);
    BOOST_CHECK(GetScriptForHybridMultisig(0, pubs).empty());
    BOOST_CHECK(GetScriptForHybridMultisig(-5, pubs).empty());

    // Empty key list -> rejected.
    std::vector<CHybridPubKey> none;
    BOOST_CHECK(GetScriptForHybridMultisig(1, none).empty());

    // nRequired exceeding the number of keys -> rejected.
    BOOST_CHECK(GetScriptForHybridMultisig(3, pubs).empty());

    // Boundary: exactly 16 keys with a valid nRequired still builds.
    std::vector<CHybridPubKey> sixteen;
    CHybridTestKeyStore store16;
    for (int i = 0; i < 16; ++i) {
        CHybridKey hk;
        GenerateHybridKey(hk);
        sixteen.push_back(CHybridPubKey(hk.secpPub.Raw(),
                                       hk.mldsaSigner->GetPublicKey()));
        store16.AddHybridKey(hk);
    }
    for (int nReq = 1; nReq <= 16; ++nReq) {
        CScript s = GetScriptForHybridMultisig(nReq, sixteen);
        BOOST_CHECK(!s.empty());
    }
}
