#include <boost/test/unit_test.hpp>

#include <cstring>

#include "main.h"
#include "script.h"
#include "keystore.h"
#include "hs/hybrid_signer.h"
#include "hs/wallethybrid.h"

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
