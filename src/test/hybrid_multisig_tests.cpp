#include <boost/test/unit_test.hpp>

#include <cstring>
#include <algorithm>
#include <memory>

#include "main.h"
#include "script.h"
#include "keystore.h"
#include "base58.h"
#include "hs/hybrid_signer.h"
#include "hs/hybrid_verify.h"
#include "hs/hybrid_script.h"
#include "hs/hybrid_message.h"
#include "hs/wallethybrid.h"
#include "hs/rpchybrid.h"
#include "wallet.h"
#include "crypter.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <secp256k1.h>

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

// CHybridChurnKeyStore hands a CHybridKey out after churning its stored
// ECDSA component (CKey) through the copy/move pathways CKey supports.
// SignHybridTx then derives its own signing key with CHybridKey::GetCKey()
// and signs the ECDSA half of the hybrid signature. Under the old implicit
// shallow CKey copies every chain shared one EVP_PKEY with no refcount and
// destroyed the same pointer twice; the refcounted CKey must keep every
// hand-out independently valid.
class CHybridChurnKeyStore : public CHybridTestKeyStore
{
public:
    enum ChurnMode {
        COPY_CHAIN,     // explicit copy-constructor chain + copy-assign
        MOVE_CHAIN,     // move chain; every moved-from copy is left null
        MOVE_ASSIGN_OUT // copy, then move-assign into a null key
    };

    ChurnMode mode = MOVE_CHAIN;

private:
    void ChurnCKey(const CHybridKey& hk) const
    {
        const CPubKey pub = hk.secpPub;
        for (int i = 0; i < 8; ++i) {
            switch (mode) {
            case COPY_CHAIN: {
                CKey k0 = hk.GetCKey();
                CKey k1(k0);
                CKey k2(k1);
                CKey k3;
                k3 = k2;
                BOOST_CHECK(k0.GetPubKey() == pub);
                BOOST_CHECK(k1.GetPubKey() == pub);
                BOOST_CHECK(k2.GetPubKey() == pub);
                BOOST_CHECK(k3.GetPubKey() == pub);
                break;
            }
            case MOVE_CHAIN: {
                CKey k0 = hk.GetCKey();
                CKey k1(std::move(k0));
                CKey k2(std::move(k1));
                CKey k3(std::move(k2));
                BOOST_CHECK(k0.IsNull());
                BOOST_CHECK(k1.IsNull());
                BOOST_CHECK(k2.IsNull());
                BOOST_CHECK(k3.GetPubKey() == pub);
                break;
            }
            case MOVE_ASSIGN_OUT: {
                CKey k0 = hk.GetCKey();
                CKey k1;
                k1 = std::move(k0);
                BOOST_CHECK(k0.IsNull());
                BOOST_CHECK(k1.GetPubKey() == pub);
                break;
            }
            }
        }
    }

    // CHybridKey owns its ML-DSA signer in a unique_ptr, so the hand-out is
    // filled memberwise and the signer is moved rather than copied.
    static void StealInto(CHybridKey& keyOut, CHybridKey& tmp)
    {
        keyOut.secpPriv = tmp.secpPriv;
        keyOut.secpPub = tmp.secpPub;
        keyOut.mldsaAlg = tmp.mldsaAlg;
        keyOut.nCreateTime = tmp.nCreateTime;
        keyOut.mldsaSigner = std::move(tmp.mldsaSigner);
    }

public:
    virtual bool GetHybridKeyByLegacyID(const CKeyID& keyID,
                                        CHybridKey& keyOut) const override
    {
        CHybridKey tmp;
        if (!CHybridTestKeyStore::GetHybridKeyByLegacyID(keyID, tmp))
            return false;
        ChurnCKey(tmp);
        StealInto(keyOut, tmp);
        return keyOut.mldsaSigner != NULL;
    }

    virtual bool GetHybridKey(const CHybridKeyID& address,
                              CHybridKey& keyOut) const override
    {
        CHybridKey tmp;
        if (!CHybridTestKeyStore::GetHybridKey(address, tmp))
            return false;
        ChurnCKey(tmp);
        StealInto(keyOut, tmp);
        return keyOut.mldsaSigner != NULL;
    }

    virtual bool GetHybridKeyByHash(const uint160& keyHash,
                                    CHybridKey& keyOut) const override
    {
        return GetHybridKey(CHybridKeyID(keyHash), keyOut);
    }
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

static std::vector<std::vector<unsigned char> > ScriptSigItems(const CScript& script)
{
    std::vector<std::vector<unsigned char> > items;
    CScript::const_iterator it = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    while (script.GetOp(it, opcode, vch)) {
        items.push_back(vch);
    }
    return items;
}

static std::vector<unsigned char> Bytes(const std::string& s)
{
    return std::vector<unsigned char>(s.begin(), s.end());
}

// Builds the v1 ML-DSA-65 private-key record parsed by FromSerialized():
//   [alg:1] [pub_len:2 BE] pub [priv_len:2 BE] priv
static std::vector<unsigned char> MakeV1Record(
    uint16_t pubLen, const std::vector<unsigned char>& pub,
    uint16_t privLen, const std::vector<unsigned char>& priv)
{
    std::vector<unsigned char> out;
    out.push_back(static_cast<unsigned char>(SigAlg::ML_DSA_65));
    out.push_back(pubLen >> 8);
    out.push_back(pubLen & 0xff);
    out.insert(out.end(), pub.begin(), pub.end());
    out.push_back(privLen >> 8);
    out.push_back(privLen & 0xff);
    out.insert(out.end(), priv.begin(), priv.end());
    return out;
}

// Re-wraps a v1 record into the v2 disk record parsed by
// FromSerializedV2():
//   'HYBK' [version:1] [alg:1] [flags:1] <v1 tail>
static std::vector<unsigned char> MakeV2Record(const std::vector<unsigned char>& v1)
{
    std::vector<unsigned char> out(HYBRID_MAGIC, HYBRID_MAGIC + 4);
    out.push_back(HYBRID_VERSION);
    out.push_back(v1[0]);
    out.push_back(0); // flags
    for (size_t i = 1; i < v1.size(); ++i)
        out.push_back(v1[i]);
    return out;
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
 * Regression test: CombineHybridMultisig must cap the combined scriptSig at
 * exactly nMa signature pairs.
 *
 * Scenario: a 2-of-3 is spent by two partial signatures carrying 1 + 2 = 3
 * valid pairs between them. OP_CHECKMULTIHYBRIDSIG's two-pointer matcher
 * (script.cpp) always walks all nKeysCount keys and requires sigIndex ==
 * nSigsCount, so the third, surplus pair is never matched and remains on the
 * stack. This fork has no clean-stack rule, so consensus still accepts the
 * spend; the surplus pair instead trips AreInputsStandard, which expects
 * exactly nMa * 2 signature items (ScriptSigArgsExpected). The combiner
 * therefore must forward only the first nMa matched pairs, in key order.
 *
 *   - partial signatures combine to 3 valid pairs
 *   - the combined scriptSig contains exactly 2 pairs
 *   - the resulting script verifies successfully (bare and P2SH paths)
 *   - 2 pairs are a standard input; 3 pairs are not
 */
BOOST_AUTO_TEST_CASE(hybrid_multisig_combine_caps_sigs_at_m)
{
    CHybridTestKeyStore keystore;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 3);

    CScript inner = GetScriptForHybridMultisig(2, pubs);
    BOOST_REQUIRE(!inner.empty());

    CTransaction txFrom, txTo;
    MakeHybridSpend(inner, txFrom, txTo);

    CHybridKey key0, key1, key2;
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[0], key0));
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[1], key1));
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[2], key2));

    // Three valid pairs for keys 0, 1 and 2 (bare 2-of-3 context).
    std::vector<unsigned char> e0, m0, e1, m1, e2, m2;
    BOOST_REQUIRE(!SignHybridPair(key0, inner, txTo, 0, SIGHASH_ALL, e0, m0).empty());
    BOOST_REQUIRE(!SignHybridPair(key1, inner, txTo, 0, SIGHASH_ALL, e1, m1).empty());
    BOOST_REQUIRE(!SignHybridPair(key2, inner, txTo, 0, SIGHASH_ALL, e2, m2).empty());

    // Two partials: one pair (key 0) and two pairs (keys 1 and 2).
    CScript partialA;
    partialA << e0 << m0;
    CScript partialB;
    partialB << e1 << m1 << e2 << m2;

    CScript combined = CombineSignatures(inner, txTo, 0, partialA, partialB);
    BOOST_CHECK(combined != partialA);

    // Exactly nMa = 2 pairs (4 signature items) regardless of the 3 valid
    // pairs that were combined.
    std::vector<std::vector<unsigned char> > items = ScriptSigItems(combined);
    BOOST_REQUIRE_EQUAL(items.size(), 4U);

    // The surviving pairs are the first nMa matched keys, in key order.
    BOOST_CHECK(items[0] == e0);
    BOOST_CHECK(items[1] == m0);
    BOOST_CHECK(items[2] == e1);
    BOOST_CHECK(items[3] == m1);

    // The 2-pair result satisfies the consensus script.
    BOOST_CHECK(VerifyScript(combined, inner, txTo, 0, false, 0));

    // Standardness gate: AreInputsStandard expects exactly 2*m signature
    // items. 2 pairs pass, the pre-fix 3-pair output does not.
    std::map<uint256, std::pair<CTxIndex, CTransaction> > mapInputs;
    mapInputs[txFrom.GetHash()] = std::make_pair(CTxIndex(), txFrom);
    CTransaction txToStd;
    txToStd.vin.resize(1);
    txToStd.vout.resize(1);
    txToStd.vin[0].prevout.hash = txFrom.GetHash();
    txToStd.vin[0].prevout.n = 0;

    txToStd.vin[0].scriptSig = combined;
    BOOST_CHECK(txToStd.AreInputsStandard(mapInputs));

    CScript threePairs;
    threePairs << e0 << m0 << e1 << m1 << e2 << m2;
    txToStd.vin[0].scriptSig = threePairs;
    BOOST_CHECK(!txToStd.AreInputsStandard(mapInputs));

    // P2SH path (how hybrid multisigs are actually committed on-chain).
    keystore.AddCScript(inner);
    CScript p2sh;
    p2sh << OP_HASH160 << inner.GetID() << OP_EQUAL;

    CTransaction txFromP2, txToP2;
    MakeHybridSpend(p2sh, txFromP2, txToP2);

    std::vector<unsigned char> sub(inner.begin(), inner.end());

    std::vector<unsigned char> p0e, p0m, p1e, p1m, p2e, p2m;
    BOOST_REQUIRE(!SignHybridPair(key0, inner, txToP2, 0, SIGHASH_ALL, p0e, p0m).empty());
    BOOST_REQUIRE(!SignHybridPair(key1, inner, txToP2, 0, SIGHASH_ALL, p1e, p1m).empty());
    BOOST_REQUIRE(!SignHybridPair(key2, inner, txToP2, 0, SIGHASH_ALL, p2e, p2m).empty());

    CScript aP2;
    aP2 << p0e << p0m << sub;
    CScript bP2;
    bP2 << p1e << p1m << p2e << p2m << sub;

    CScript cP2 = CombineSignatures(p2sh, txToP2, 0, aP2, bP2);
    std::vector<std::vector<unsigned char> > itemsP2 = ScriptSigItems(cP2);
    BOOST_REQUIRE_EQUAL(itemsP2.size(), 5U); // 2 pairs + redeem script

    BOOST_CHECK(itemsP2[0] == p0e);
    BOOST_CHECK(itemsP2[1] == p0m);
    BOOST_CHECK(itemsP2[2] == p1e);
    BOOST_CHECK(itemsP2[3] == p1m);
    BOOST_CHECK(itemsP2[4] == sub);

    // 2 pairs + redeem verify under P2SH.
    BOOST_CHECK(VerifyScript(cP2, p2sh, txToP2, 0, true, 0));

    // Sanity: this fork has no clean-stack rule, so a 3-pair scriptSig does
    // still verify at consensus. That is exactly why the cap must live in
    // the combiner/standardness layer rather than in consensus.
    CScript threeP2;
    threeP2 << p0e << p0m << p1e << p1m << p2e << p2m << sub;
    BOOST_CHECK(VerifyScript(threeP2, p2sh, txToP2, 0, true, 0));
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
 * Hybrid-key pool invariants.
 *
 * EnsureHybridKeyPool / GetUnusedHybridKey manage the wallet's pool of
 * pre-generated hybrid keys:
 *
 *   - EnsureHybridKeyPool(nTarget) tops up until mapHybridKeys reaches
 *     nTarget and is a no-op beyond it; every CHybridKeyID in the pool is
 *     unique.
 *   - GetUnusedHybridKey tops up when setUnusedHybridKeys runs below 5, so
 *     pool exhaustion triggers a +20-key top-up.
 *   - every pooled legacy ECDSA key maps 1:1 back to its CHybridKeyID via
 *     GetHybridKeyIDByLegacyKeyID (and remains spendable as a plain key).
 */
BOOST_AUTO_TEST_CASE(hybrid_key_pool_invariants)
{
    CWallet wallet;

    // Top-up 0 -> 20, then a repeat is a no-op (already at target).
    BOOST_CHECK(wallet.EnsureHybridKeyPool(20));
    BOOST_REQUIRE_EQUAL(wallet.mapHybridKeys.size(), 20U);
    BOOST_CHECK(wallet.EnsureHybridKeyPool(20));
    BOOST_REQUIRE_EQUAL(wallet.mapHybridKeys.size(), 20U);

    // Rebuilding the unused set from the loaded pool keeps every key.
    BOOST_CHECK(wallet.RebuildUnusedHybridKeySet());
    BOOST_REQUIRE_EQUAL(wallet.setUnusedHybridKeys.size(), 20U);

    // All pooled hybrid IDs are distinct, and each legacy ECDSA key maps
    // 1:1 back to its own hybrid ID via GetHybridKeyIDByLegacyKeyID.
    std::set<CHybridKeyID> seen;
    std::set<CKeyID> seenLegacy;
    for (const auto& entry : wallet.mapHybridKeys)
    {
        BOOST_CHECK(seen.insert(entry.first).second);
        BOOST_CHECK(wallet.HaveHybridKey(entry.first));

        CKeyID legacy = entry.second.GetKeyID();
        BOOST_CHECK(seenLegacy.insert(legacy).second);
        BOOST_CHECK(wallet.HaveKey(legacy));

        CHybridKeyID reverse;
        BOOST_CHECK(wallet.GetHybridKeyIDByLegacyKeyID(legacy, reverse));
        BOOST_CHECK(reverse == entry.first);
    }
    BOOST_CHECK_EQUAL(seen.size(), 20U);
    BOOST_CHECK_EQUAL(seenLegacy.size(), 20U);

    // Drain the pool down to just below the top-up threshold (5).
    std::vector<CHybridKeyID> issued;
    while (wallet.setUnusedHybridKeys.size() >= 5)
    {
        CHybridKeyID id;
        BOOST_CHECK(wallet.GetUnusedHybridKey(id));
        issued.push_back(id);
    }
    BOOST_REQUIRE_EQUAL(wallet.setUnusedHybridKeys.size(), 4U);

    // Pool exhaustion triggers a top-up of mapHybridKeys.size() + 20.
    CHybridKeyID toppedUp;
    BOOST_CHECK(wallet.GetUnusedHybridKey(toppedUp));
    BOOST_REQUIRE_EQUAL(wallet.mapHybridKeys.size(), 40U);
    issued.push_back(toppedUp);

    // Issued keys stay unique across top-ups, used == issued, and the
    // pool accounting holds: map keys == used + unused.
    std::set<CHybridKeyID> issuedSet(issued.begin(), issued.end());
    BOOST_CHECK_EQUAL(issuedSet.size(), issued.size());
    BOOST_CHECK_EQUAL(wallet.setUsedHybridKeys.size(), issued.size());
    BOOST_CHECK_EQUAL(wallet.mapHybridKeys.size() - wallet.setUsedHybridKeys.size(),
                      wallet.setUnusedHybridKeys.size());

    // Every issued key still round-trips its legacy ID back to its hybrid
    // ID after being allocated.
    for (const CHybridKeyID& id : issued)
    {
        CHybridKey key;
        BOOST_REQUIRE(wallet.GetHybridKey(id, key));
        CHybridKeyID reverse;
        BOOST_CHECK(wallet.GetHybridKeyIDByLegacyKeyID(key.GetKeyID(), reverse));
        BOOST_CHECK(reverse == id);
    }

    // The pool refuses to grow while the wallet is locked; unlocking
    // restores top-up and allocation.
    CWallet lockedWallet;
    CKey encKey;
    CMasterKey masterKey;
    BOOST_REQUIRE(SetupEncryptedTestWallet(lockedWallet, encKey, masterKey));
    BOOST_CHECK(lockedWallet.IsLocked());
    BOOST_CHECK(!lockedWallet.EnsureHybridKeyPool(2));
    CHybridKeyID locker;
    BOOST_CHECK(!lockedWallet.GetUnusedHybridKey(locker));

    SecureString pass("correct horse battery staple\n");
    BOOST_REQUIRE(lockedWallet.Unlock(pass));
    BOOST_CHECK(lockedWallet.EnsureHybridKeyPool(2));
    BOOST_CHECK(lockedWallet.GetUnusedHybridKey(locker));
}

/*
 * Hybrid address round trip, IsMine, and Base58 corruption.
 *
 * CCoinAddress(CHybridKeyID) encodes the 20-byte hybrid key ID under the
 * hybrid address version byte. ToString()/SetString() must restore the
 * exact same CHybridKeyID, and IsMine on the resulting destination must
 * reflect whether the keystore holds the key. Because the 4-byte Base58Check
 * checksum covers the version byte and the full payload, flipping any single
 * character of the encoded string must make the address invalid.
 */
BOOST_AUTO_TEST_CASE(hybrid_address_roundtrip)
{
    CHybridTestKeyStore keystore;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 1);

    CHybridKey hk;
    BOOST_REQUIRE(GetHybridKey(keystore, pubs[0], hk));
    CHybridKeyID id = hk.GetHybridID();

    // Encode a CHybridKeyID as a Base58 hybrid address.
    CCoinAddress addr(id);
    BOOST_CHECK(addr.IsValid());
    std::string enc = addr.ToString();
    BOOST_CHECK(!enc.empty());

    // Round trip back to the same key ID.
    CCoinAddress back(enc);
    BOOST_CHECK(back.IsValid());
    CHybridKeyID round;
    BOOST_CHECK(back.GetHybridKeyID(round));
    BOOST_CHECK(round == id);
    BOOST_CHECK(boost::get<CHybridKeyID>(back.Get()) == id);
    BOOST_CHECK(back.ToString() == enc);

    // CTxDestination round trip through the same code path.
    CCoinAddress fromDest(static_cast<CTxDestination>(id));
    BOOST_CHECK(fromDest.ToString() == enc);

    // The ECDSA-only PubKey address of the same key's legacy ID is NOT a
    // hybrid address: different version byte, different encoding, and it
    // must not decode as a hybrid key ID.
    CCoinAddress legacyAddr(hk.GetKeyID());
    BOOST_CHECK(legacyAddr.IsValid());
    BOOST_CHECK(legacyAddr.ToString() != enc);
    CHybridKeyID junk;
    BOOST_CHECK(!legacyAddr.GetHybridKeyID(junk));

    // IsMine on the hybrid address destination.
    CTxDestination dest = id;
    BOOST_CHECK(IsMine(keystore, dest) == MINE_SPENDABLE);

    CHybridTestKeyStore empty;
    BOOST_CHECK(IsMine(empty, dest) == MINE_NO);

    // Base58 corruption: the checksum covers version + payload, so a
    // single-character flip at ANY position must fail to parse.
    const std::string alphabet(
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    for (size_t pos = 0; pos < enc.size(); ++pos)
    {
        std::string bad = enc;
        bad[pos] = alphabet[(alphabet.find(bad[pos]) + 1)
                            % alphabet.size()];
        BOOST_CHECK(bad != enc);

        CCoinAddress tampered(bad);
        BOOST_CHECK(!tampered.IsValid());
        CHybridKeyID out;
        BOOST_CHECK(!tampered.GetHybridKeyID(out));
    }

    // A completely bogus string is rejected outright.
    CCoinAddress bogus("1BogusHybridAddress11");
    BOOST_CHECK(!bogus.IsValid());
    BOOST_CHECK(!bogus.SetString("zzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
    CHybridKeyID out;
    BOOST_CHECK(!bogus.GetHybridKeyID(out));
}

/*
 * ValidateHybridKey negatives.
 *
 * ValidateHybridKey (wallethybrid.cpp) is the gatekeeper for the wallet's
 * hybrid key records. It requires, in order: a non-empty ECDSA secret, a
 * valid compression-prefixed (33-byte) ECDSA public key, the exact MLDSA
 * algorithm tag ("p384_mldsa65"), a live MLDSA signer, a self-consistent
 * ECDSA key pair, and a strictly positive creation time. This test starts
 * from a GenerateHybridKey key (which validates clean) and breaks each
 * requirement in isolation.
 */
BOOST_AUTO_TEST_CASE(validate_hybrid_key_negatives)
{
    CHybridKey good;
    GenerateHybridKey(good);
    BOOST_CHECK(ValidateHybridKey(good));

    // Wrong MLDSA algorithm tag.
    CHybridKey badAlg;
    GenerateHybridKey(badAlg);
    badAlg.mldsaAlg = "dilithium3";
    BOOST_CHECK(!ValidateHybridKey(badAlg));

    badAlg.mldsaAlg = "";
    BOOST_CHECK(!ValidateHybridKey(badAlg));

    badAlg.mldsaAlg = "p384_ml-dsa-65";   // near-miss spelling
    BOOST_CHECK(!ValidateHybridKey(badAlg));

    // Missing MLDSA signer.
    CHybridKey noSigner;
    GenerateHybridKey(noSigner);
    noSigner.mldsaSigner.reset();
    BOOST_CHECK(!ValidateHybridKey(noSigner));

    // Uncompressed (65-byte) secp256k1 public key. CKey::MakeNewKey(false)
    // still stores a compressed 33-byte pubkey (SerializePubKey always uses
    // SECP256K1_EC_COMPRESSED; the flag only affects recovery IDs), so
    // synthesize a genuine on-curve uncompressed point with libsecp256k1
    // from the same secret that produced the compressed key.
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    BOOST_REQUIRE(ctx);

    CHybridKey uncompressed;
    GenerateHybridKey(uncompressed);

    std::vector<unsigned char> pub65(65);
    {
        secp256k1_pubkey pub;
        BOOST_REQUIRE(secp256k1_ec_pubkey_create(
            ctx, &pub, &uncompressed.secpPriv[0]));
        size_t len = 65;
        BOOST_REQUIRE(secp256k1_ec_pubkey_serialize(
            ctx, &pub65[0], &len, &pub, SECP256K1_EC_UNCOMPRESSED));
        BOOST_REQUIRE_EQUAL(len, 65U);
    }
    secp256k1_context_destroy(ctx);

    uncompressed.secpPub = CPubKey(pub65);
    BOOST_CHECK_EQUAL(uncompressed.secpPub.Raw().size(), 65U);
    BOOST_CHECK(uncompressed.secpPub.IsValid());
    BOOST_CHECK(!ValidateHybridKey(uncompressed));

    // Creation time == 0 (and negative).
    CHybridKey noTime;
    GenerateHybridKey(noTime);
    noTime.nCreateTime = 0;
    BOOST_CHECK(!ValidateHybridKey(noTime));

    noTime.nCreateTime = -1;
    BOOST_CHECK(!ValidateHybridKey(noTime));

    // Positive control: restoring valid fields validates again.
    good.nCreateTime = GetTime();
    BOOST_CHECK(ValidateHybridKey(good));
}

/*
 * VerifyHybridSignature unit isolation.
 *
 * VerifyHybridSignature (hybrid_verify.h) is normally reached only from
 * script execution (OP_CHECKHYBRIDSIG via EvalScript). Exercise it
 * directly: the size guards on the two public keys
 * (hybrid_verify.h:247-251), the shared sighash-type requirement between
 * the EC and ML signatures, and the nHashType enforcement gate all run
 * independent of any script interpreter.
 */
BOOST_AUTO_TEST_CASE(verify_hybrid_signature_isolation)
{
    CHybridKey key;
    GenerateHybridKey(key);

    CHybridPubKey pub(key.secpPub.Raw(), key.mldsaSigner->GetPublicKey());
    BOOST_REQUIRE(pub.IsValid());

    CScript scriptPubKey = GetScriptForHybridPubKey(pub);
    BOOST_REQUIRE(!scriptPubKey.empty());

    CTransaction txFrom, txTo;
    MakeHybridSpend(scriptPubKey, txFrom, txTo);

    const std::vector<unsigned char> ecPub = key.secpPub.Raw();
    const std::vector<unsigned char> mlPub = key.mldsaSigner->GetPublicKey();
    BOOST_REQUIRE_EQUAL(ecPub.size(), 33U);
    BOOST_REQUIRE_EQUAL(mlPub.size(), 1952U);

    std::vector<unsigned char> ecSig, mlSig;
    BOOST_REQUIRE(!SignHybridPair(
        key, scriptPubKey, txTo, 0, SIGHASH_ALL, ecSig, mlSig).empty());

    // Positive controls: the exact hash type and the "any type" mode.
    BOOST_CHECK(VerifyHybridSignature(
        ecSig, mlSig, ecPub, mlPub, scriptPubKey, txTo, 0, SIGHASH_ALL));
    BOOST_CHECK(VerifyHybridSignature(
        ecSig, mlSig, ecPub, mlPub, scriptPubKey, txTo, 0, 0));

    // 1) nHashType enforcement: the signatures carry SIGHASH_ALL but the
    //    caller demands a different type.
    BOOST_CHECK(!VerifyHybridSignature(
        ecSig, mlSig, ecPub, mlPub, scriptPubKey, txTo, 0, SIGHASH_NONE));
    BOOST_CHECK(!VerifyHybridSignature(
        ecSig, mlSig, ecPub, mlPub, scriptPubKey, txTo, 0, SIGHASH_SINGLE));

    // 2) EC/ML sighash-type mismatch: resign with SIGHASH_NONE to get a
    //    second pair in which both halves are individually valid...
    std::vector<unsigned char> ecSigNone, mlSigNone;
    BOOST_REQUIRE(!SignHybridPair(
        key, scriptPubKey, txTo, 0, SIGHASH_NONE, ecSigNone, mlSigNone).empty());
    BOOST_CHECK(VerifyHybridSignature(
        ecSigNone, mlSigNone, ecPub, mlPub, scriptPubKey, txTo, 0, 0));

    //    ...then cross the halves: EC=ALL + ML=NONE and EC=NONE + ML=ALL
    //    must both be rejected (hashTypeEC != hashTypeML).
    BOOST_CHECK(!VerifyHybridSignature(
        ecSig, mlSigNone, ecPub, mlPub, scriptPubKey, txTo, 0, 0));
    BOOST_CHECK(!VerifyHybridSignature(
        ecSigNone, mlSig, ecPub, mlPub, scriptPubKey, txTo, 0, 0));

    // 3) Size guards on the public keys (hybrid_verify.h:247-251):
    //    empty, undersized and oversized for the EC key...
    const std::vector<unsigned char> empty;
    BOOST_CHECK(!VerifyHybridSignature(
        ecSig, mlSig, empty, mlPub, scriptPubKey, txTo, 0, 0));
    BOOST_CHECK(!VerifyHybridSignature(
        ecSig, mlSig, ecPub, empty, scriptPubKey, txTo, 0, 0));

    std::vector<unsigned char> ecSmall(ecPub.begin(), ecPub.end() - 1);
    std::vector<unsigned char> ecBig = ecPub;
    ecBig.push_back(0x01);
    BOOST_CHECK(!VerifyHybridSignature(
        ecSig, mlSig, ecSmall, mlPub, scriptPubKey, txTo, 0, 0));
    BOOST_CHECK(!VerifyHybridSignature(
        ecSig, mlSig, ecBig, mlPub, scriptPubKey, txTo, 0, 0));

    //    ...and the ML-DSA key.
    std::vector<unsigned char> mlSmall(mlPub.begin(), mlPub.end() - 1);
    std::vector<unsigned char> mlBig = mlPub;
    mlBig.push_back(0x01);
    BOOST_CHECK(!VerifyHybridSignature(
        ecSig, mlSig, ecPub, mlSmall, scriptPubKey, txTo, 0, 0));
    BOOST_CHECK(!VerifyHybridSignature(
        ecSig, mlSig, ecPub, mlBig, scriptPubKey, txTo, 0, 0));

    // 4) Genuinely broken material still fails, so none of the gates above
    //    are indiscriminately rejecting everything.
    std::vector<unsigned char> badEc = ecSig;
    badEc[badEc.size() / 2] ^= 0x01;
    BOOST_CHECK(!VerifyHybridSignature(
        badEc, mlSig, ecPub, mlPub, scriptPubKey, txTo, 0, 0));

    std::vector<unsigned char> badMl = mlSig;
    badMl[badMl.size() / 2] ^= 0x01;
    BOOST_CHECK(!VerifyHybridSignature(
        ecSig, badMl, ecPub, mlPub, scriptPubKey, txTo, 0, 0));

    std::vector<unsigned char> badPub = mlPub;
    badPub[badPub.size() / 2] ^= 0x01;
    BOOST_CHECK(!VerifyHybridSignature(
        ecSig, mlSig, ecPub, badPub, scriptPubKey, txTo, 0, 0));
}

/*
 * Exact ML-DSA-65 signature-length validation.
 *
 * ML_DSA_65_SIG_SIZE (3310) is the wire-form signature: the raw FIPS 204
 * ML-DSA-65 signature (3309 bytes) plus the trailing sighash byte. Every
 * consumer must enforce the exact size, not a bounding range:
 *   - VerifyMLDSA            (hybrid_verify.h:72)    raw 3309,
 *   - VerifyHybridSignature  (hybrid_verify.h)       wire 3310,
 *   - OP_CHECKHYBRIDSIG via EvalScript               wire 3310,
 *   - ParseHybridMessage     (hybrid_message.cpp:52) raw 3309.
 * Each signature is exercised at the exact boundary - one byte short, the
 * raw signature, one byte long, empty, and oversized - with the trailing
 * sighash byte kept valid where the format expects it, so only the length
 * gate can fire.
 */
BOOST_AUTO_TEST_CASE(hybrid_ml_dsa_sig_length_exact)
{
    static_assert(ML_DSA_65_SIG_SIZE == 3310, "wire ML-DSA-65 signature size");
    static_assert(ML_DSA_65_SIG_SIZE - 1 == 3309,
                  "raw ML-DSA-65 signature size");

    CHybridKey key;
    GenerateHybridKey(key);
    BOOST_REQUIRE(key.mldsaSigner);

    const std::vector<unsigned char> ecPub = key.secpPub.Raw();
    const std::vector<unsigned char> mlPub = key.mldsaSigner->GetPublicKey();
    BOOST_REQUIRE_EQUAL(mlPub.size(), ML_DSA_65_PUBKEY_SIZE);

    CScript scriptPubKey = GetScriptForHybridPubKey(CHybridPubKey(ecPub, mlPub));
    BOOST_REQUIRE(!scriptPubKey.empty());

    CTransaction txFrom, txTo;
    MakeHybridSpend(scriptPubKey, txFrom, txTo);

    std::vector<unsigned char> ecSig, mlSig;
    BOOST_REQUIRE(!SignHybridPair(key, scriptPubKey, txTo, 0, SIGHASH_ALL,
                                  ecSig, mlSig).empty());
    BOOST_REQUIRE_EQUAL(mlSig.size(), ML_DSA_65_SIG_SIZE);      // 3310 wire

    const std::vector<unsigned char> rawSig(mlSig.begin(), mlSig.end() - 1);
    BOOST_REQUIRE_EQUAL(rawSig.size(), ML_DSA_65_SIG_SIZE - 1); // 3309 raw

    std::vector<unsigned char> hybridMsg;
    {
        std::vector<unsigned char> preimage;
        BOOST_REQUIRE(ConstructSignatureHashPreimage(scriptPubKey, txTo, 0,
                                                     SIGHASH_ALL, preimage));
        hybridMsg = BuildHybridMessage(preimage);
    }

    // 1) VerifyMLDSA: exactly the raw 3309 bytes are accepted.
    BOOST_CHECK(VerifyMLDSA(rawSig, mlPub, hybridMsg));
    for (size_t n : { (size_t)0, (size_t)1, (size_t)2,
                      ML_DSA_65_SIG_SIZE - 2,       // short
                      ML_DSA_65_SIG_SIZE,           // raw + 1
                      ML_DSA_65_SIG_SIZE + 1,       // oversized
                      (size_t)4096 }) {
        std::vector<unsigned char> m(rawSig.begin(),
                                     rawSig.begin() + std::min(n, rawSig.size()));
        m.resize(n, 0x5a);
        BOOST_CHECK(!VerifyMLDSA(m, mlPub, hybridMsg));
    }

    // 2) VerifyHybridSignature: the wire signature must be exactly 3310.
    auto wireSig = [&](size_t n) {
        std::vector<unsigned char> s;
        const size_t content = n > 0 ? n - 1 : 0;
        s.reserve(content);
        const size_t take = std::min(content, rawSig.size());
        s.insert(s.end(), rawSig.begin(), rawSig.begin() + take);
        s.resize(content, 0x5a);
        if (n > 0)
            s.push_back((unsigned char)SIGHASH_ALL);
        return s;
    };

    BOOST_CHECK(VerifyHybridSignature(ecSig, mlSig, ecPub, mlPub,
                                      scriptPubKey, txTo, 0, 0));
    // The cryptographically valid raw 3309 bytes WITHOUT the sighash byte
    // fail here: the wire format demands exactly 3310.
    BOOST_CHECK(!VerifyHybridSignature(ecSig, rawSig, ecPub, mlPub,
                                       scriptPubKey, txTo, 0, 0));
    for (size_t n : { 0u, 1u, 2u, 3308u, 3309u, 3311u, 4096u }) {
        BOOST_CHECK(!VerifyHybridSignature(ecSig, wireSig(n), ecPub, mlPub,
                                           scriptPubKey, txTo, 0, 0));
    }

    // Layout: the LAST byte of the wire signature is the shared sighash
    // type. Flipping it, flipping raw signature bytes, or submitting any
    // correctly-sized 3310-byte blob all fail - the length gate alone does
    // not accept arbitrary data.
    {
        std::vector<unsigned char> badTail = mlSig;
        badTail.back() ^= 0x01;
        BOOST_CHECK(!VerifyHybridSignature(ecSig, badTail, ecPub, mlPub,
                                           scriptPubKey, txTo, 0, 0));

        std::vector<unsigned char> badRaw = mlSig;
        badRaw[badRaw.size() / 2] ^= 0x01;
        BOOST_CHECK(!VerifyHybridSignature(ecSig, badRaw, ecPub, mlPub,
                                           scriptPubKey, txTo, 0, 0));

        std::vector<unsigned char> filler(ML_DSA_65_SIG_SIZE - 1, 0x5a);
        filler.push_back((unsigned char)SIGHASH_ALL);
        BOOST_CHECK(!VerifyHybridSignature(ecSig, filler, ecPub, mlPub,
                                           scriptPubKey, txTo, 0, 0));
    }

    // 3) Script execution (TX_HYBRID_PUBKEY / OP_CHECKHYBRIDSIG):
    //    only a 3310-byte ML-DSA push verifies.
    {
        CScript sigGood;
        sigGood << ecSig << mlSig;
        BOOST_CHECK(VerifyScript(sigGood, scriptPubKey, txTo, 0, false, 0));

        for (size_t n : { 1u, 3309u, 3311u }) {
            CScript sigBad;
            sigBad << ecSig << wireSig(n);
            BOOST_CHECK(!VerifyScript(sigBad, scriptPubKey, txTo, 0, false, 0));
        }

        CScript sigRaw;
        sigRaw << ecSig << rawSig;   // 3309-byte push, no sighash byte
        BOOST_CHECK(!VerifyScript(sigRaw, scriptPubKey, txTo, 0, false, 0));
    }

    // 4) HYBS container: the ML-DSA signature length field must hold
    //    exactly the raw 3309 bytes (ParseHybridMessage/hybrid_message.cpp:52).
    //    The systematic malformed matrix already sweeps the negative field
    //    values; here the exact-3309 positive is paired with the +-1 field
    //    values so the boundary is pinned in one place.
    {
        const std::string hmsg = "hybs exact ML-DSA sig length";
        std::vector<unsigned char> hsig;
        BOOST_REQUIRE(SignHybridMessage(key, hmsg, hsig));

        const size_t sigLenOff =
            4u + 1u + 65u + ECDSA_PUBKEY_SIZE + 2u + ML_DSA_65_PUBKEY_SIZE;
        const size_t sigOff = sigLenOff + 2;
        const size_t realLen = hsig.size() - sigOff;
        BOOST_REQUIRE_EQUAL(realLen, ML_DSA_65_SIG_SIZE - 1);

        std::vector<unsigned char> c, p, mp, ms;
        BOOST_CHECK(ParseHybridMessage(hsig, c, p, mp, ms));
        BOOST_CHECK_EQUAL(ms.size(), ML_DSA_65_SIG_SIZE - 1);
        BOOST_REQUIRE(VerifyHybridMessage(hsig, key.GetHybridID(), hmsg));

        auto buildContainer = [&](size_t fieldLen) {
            std::vector<unsigned char> b = hsig;
            b[sigLenOff]     = (unsigned char)(fieldLen >> 8);
            b[sigLenOff + 1] = (unsigned char)(fieldLen & 0xFF);
            b.resize(sigOff + fieldLen, 0x00);
            return b;
        };
        for (size_t n : { 0u, 3308u, 3310u }) {
            std::vector<unsigned char> b = buildContainer(n);
            std::vector<unsigned char> c2, p2, mp2, ms2;
            BOOST_CHECK(!ParseHybridMessage(b, c2, p2, mp2, ms2));
            BOOST_CHECK(c2.empty() && p2.empty() && mp2.empty() && ms2.empty());
            BOOST_CHECK(!VerifyHybridMessage(b, key.GetHybridID(), hmsg));
        }
    }
}

/*
 * CHybridKeyDisk format tampering.
 *
 * Every field of both the plaintext (v2) and encrypted (v3) at-rest records
 * is covered by the payload checksum (Hash of the serialized layout except
 * hashChecksum itself), so a single-byte flip anywhere must invalidate the
 * record. The version byte is the FIRST serialized byte, so flipping it
 * forges a plaintext record as encrypted (or vice versa); the record then
 * misparses and fails the checksum.
 */
BOOST_AUTO_TEST_CASE(hybrid_key_disk_format_tampering)
{
    CHybridKey hk;
    GenerateHybridKey(hk);
    BOOST_REQUIRE(hk.mldsaSigner);

    CKeyingMaterial vMasterKey;
    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CHybridKeyDisk v2 = CHybridKeyDisk::FromMemory(hk);
    BOOST_REQUIRE(!v2.IsEncrypted());
    BOOST_REQUIRE(v2.CheckChecksum());
    BOOST_REQUIRE(!v2.secpPriv.empty());
    BOOST_REQUIRE(!v2.mldsaPrivKey.empty());

    // v2: a byte flip in any payload field breaks the checksum.
    {
        CHybridKeyDisk d = v2;
        d.secpPriv[d.secpPriv.size() / 2] ^= 0x01;
        BOOST_CHECK(!d.CheckChecksum());
    }
    {
        CHybridKeyDisk d = v2;
        std::vector<unsigned char> pub = d.secpPub.Raw();
        pub[pub.size() / 2] ^= 0x01;
        d.secpPub = CPubKey(pub);
        BOOST_CHECK(!d.CheckChecksum());
    }
    {
        CHybridKeyDisk d = v2;
        d.mldsaAlg[d.mldsaAlg.size() / 2] ^= 0x01;
        BOOST_CHECK(!d.CheckChecksum());
    }
    {
        CHybridKeyDisk d = v2;
        d.mldsaPrivKey[d.mldsaPrivKey.size() / 2] ^= 0x01;
        BOOST_CHECK(!d.CheckChecksum());
    }
    {
        CHybridKeyDisk d = v2;
        d.nCreateTime += 1;
        BOOST_CHECK(!d.CheckChecksum());
    }
    // Corrupting the checksum field itself is also detected.
    {
        CHybridKeyDisk d = v2;
        d.hashChecksum ^= uint256((uint64)1);
        BOOST_CHECK(!d.CheckChecksum());
    }

    // Serialization round trip preserves the record exactly, with the
    // version byte first.
    CDataStream ser(SER_DISK, CLIENT_VERSION);
    ser << v2;
    {
        CHybridKeyDisk round;
        CDataStream des(ser.begin(), ser.end(), SER_DISK, CLIENT_VERSION);
        des >> round;
        BOOST_CHECK(round.CheckChecksum());
        BOOST_CHECK(!round.IsEncrypted());
        BOOST_CHECK(round.secpPriv == v2.secpPriv);
        BOOST_CHECK(round.mldsaPrivKey == v2.mldsaPrivKey);
        std::vector<unsigned char> raw(ser.begin(), ser.end());
        BOOST_REQUIRE(raw.size() >= 4);
        BOOST_CHECK_EQUAL(raw[0], HYBRIDKEY_DISK_VERSION);
    }

    // v3 encrypted record.
    CHybridKeyDisk v3 = CHybridKeyDisk::FromMemoryEncrypted(hk, vMasterKey);
    BOOST_REQUIRE(v3.IsEncrypted());
    BOOST_REQUIRE(v3.CheckChecksum());
    BOOST_REQUIRE(!v3.vchCryptedPrivate.empty());

    {
        CHybridKeyDisk d = v3;
        d.vchCryptedPrivate[d.vchCryptedPrivate.size() / 2] ^= 0x01;
        BOOST_CHECK(!d.CheckChecksum());
    }
    {
        CHybridKeyDisk d = v3;
        d.mldsaAlg[d.mldsaAlg.size() / 2] ^= 0x01;
        BOOST_CHECK(!d.CheckChecksum());
    }
    {
        CHybridKeyDisk d = v3;
        std::vector<unsigned char> pub = d.secpPub.Raw();
        pub[pub.size() / 2] ^= 0x01;
        d.secpPub = CPubKey(pub);
        BOOST_CHECK(!d.CheckChecksum());
    }
    {
        CHybridKeyDisk d = v3;
        d.nCreateTime += 1;
        BOOST_CHECK(!d.CheckChecksum());
    }
    {
        CHybridKeyDisk d = v3;
        d.hashChecksum ^= uint256((uint64)1);
        BOOST_CHECK(!d.CheckChecksum());
    }
    // v3 serialization: version byte 3 first.
    {
        CDataStream s(SER_DISK, CLIENT_VERSION);
        s << v3;
        std::vector<unsigned char> raw(s.begin(), s.end());
        BOOST_REQUIRE(raw.size() >= 4);
        BOOST_CHECK_EQUAL(raw[0], HYBRIDKEY_DISK_VERSION_ENCRYPTED);
    }

    // Forged version byte: a plaintext record rewritten as v3 parses as
    // encrypted (empty ciphertext blob); a v3 record rewritten as v2 parses
    // as plaintext (empty private fields). Both fail the checksum.
    {
        CHybridKeyDisk d = v2;
        d.nVersion = HYBRIDKEY_DISK_VERSION_ENCRYPTED;
        BOOST_CHECK(d.IsEncrypted());
        BOOST_CHECK(d.vchCryptedPrivate.empty());
        BOOST_CHECK(!d.CheckChecksum());
    }
    {
        CHybridKeyDisk d = v3;
        d.nVersion = HYBRIDKEY_DISK_VERSION;
        BOOST_CHECK(!d.IsEncrypted());
        BOOST_CHECK(d.secpPriv.empty());
        BOOST_CHECK(d.mldsaPrivKey.empty());
        BOOST_CHECK(!d.CheckChecksum());
    }

    // ---- FromLegacyDiskFormat ----
    // A valid legacy record starts with the stream serialization version
    // (not the member nVersion) and reuses the v2 payload checksum.
    CHybridKeyDisk legacy = v2;
    CDataStream legacyStream(SER_DISK, CLIENT_VERSION);
    {
        int32_t nStreamVersion = HYBRIDKEY_DISK_VERSION;
        legacyStream << nStreamVersion;
        legacyStream << legacy.nCreateTime;
        legacyStream << legacy.secpPriv;
        legacyStream << legacy.secpPub;
        legacyStream << legacy.mldsaAlg;
        legacyStream << legacy.mldsaPrivKey;
        legacyStream << legacy.hashChecksum;
    }
    std::vector<unsigned char> legacyBytes(legacyStream.begin(),
                                           legacyStream.end());
    {
        CDataStream ss(legacyBytes, SER_DISK, CLIENT_VERSION);
        CHybridKeyDisk parsedLegacy;
        BOOST_CHECK(CHybridKeyDisk::FromLegacyDiskFormat(ss,
                                                         parsedLegacy));
        BOOST_CHECK(parsedLegacy.fLegacyDisk);
        BOOST_CHECK(!parsedLegacy.IsEncrypted());
        BOOST_CHECK(parsedLegacy.CheckChecksum());
        CPrivKey sOut;
        std::vector<unsigned char> mOut;
        BOOST_CHECK(parsedLegacy.DecryptPrivate(vMasterKey, sOut, mOut));
        BOOST_CHECK(sOut == hk.secpPriv);
        BOOST_CHECK(mOut == v2.mldsaPrivKey);
    }

    // Truncated legacy record (checksum cut short) is rejected.
    {
        std::vector<unsigned char> bytes = legacyBytes;
        BOOST_REQUIRE(bytes.size() >= 40);
        bytes.resize(bytes.size() - 4);
        CDataStream ss(bytes, SER_DISK, CLIENT_VERSION);
        CHybridKeyDisk out;
        BOOST_CHECK(!CHybridKeyDisk::FromLegacyDiskFormat(ss, out));
    }

    // An empty stream (which CDataStream would otherwise zero-fill) is
    // rejected, as is a stream too short to hold the serialization version.
    {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        CHybridKeyDisk out;
        BOOST_CHECK(!CHybridKeyDisk::FromLegacyDiskFormat(ss, out));
    }
    {
        std::vector<unsigned char> bytes(legacyBytes.begin(),
                                         legacyBytes.begin() + 2);
        CDataStream ss(bytes, SER_DISK, CLIENT_VERSION);
        CHybridKeyDisk out;
        BOOST_CHECK(!CHybridKeyDisk::FromLegacyDiskFormat(ss, out));
    }

    // Trailing garbage after a well-formed legacy record is rejected.
    {
        CDataStream ss(legacyBytes, SER_DISK, CLIENT_VERSION);
        ss.write("XXXX", 4);
        CHybridKeyDisk out;
        BOOST_CHECK(!CHybridKeyDisk::FromLegacyDiskFormat(ss, out));
    }

    // Version/layout mismatch: stream declares serialization version 1 (no
    // MLDSA fields) but carries MLDSA data, leaving trailing garbage.
    {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        int32_t nStreamVersion = 1;
        ss << nStreamVersion;
        ss << legacy.nCreateTime;
        ss << legacy.secpPriv << legacy.secpPub;
        ss << legacy.mldsaAlg << legacy.mldsaPrivKey;
        ss << legacy.hashChecksum;
        CHybridKeyDisk out;
        BOOST_CHECK(!CHybridKeyDisk::FromLegacyDiskFormat(ss, out));
    }

    // Version/layout mismatch: stream declares version 2 but omits the
    // MLDSA fields, so the parse runs out of data.
    {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        int32_t nStreamVersion = 2;
        ss << nStreamVersion;
        ss << legacy.nCreateTime;
        ss << legacy.secpPriv << legacy.secpPub;
        ss << legacy.hashChecksum;
        CHybridKeyDisk out;
        BOOST_CHECK(!CHybridKeyDisk::FromLegacyDiskFormat(ss, out));
    }

    // ---- LoadHybridKey ----
    // Load-time rejections: bad checksum, unsupported version, and an
    // encrypted record in a plaintext wallet.
    {
        CWallet wallet;
        CHybridKeyDisk bad = v2;
        bad.secpPriv[bad.secpPriv.size() / 2] ^= 0x01;
        CKeyingMaterial emptyKey;
        BOOST_CHECK(!LoadHybridKey(&wallet, bad, emptyKey));
    }
    {
        CWallet wallet;
        CHybridKeyDisk bad = v2;
        bad.nVersion = 99;
        CKeyingMaterial emptyKey;
        BOOST_CHECK(!LoadHybridKey(&wallet, bad, emptyKey));
    }
    {
        CWallet wallet;
        CKeyingMaterial emptyKey;
        BOOST_CHECK(!LoadHybridKey(&wallet, v3, emptyKey));
    }
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

/*
 * Tamper tests on the single-signer (P2PH) path: corrupting a single byte
 * of the ECDSA signature, a single byte of the ML-DSA signature, or a
 * single byte of the ML-DSA public key must each cause verification to
 * fail.
 */
BOOST_AUTO_TEST_CASE(hybrid_single_tamper_rejected)
{
    CHybridKey key;
    GenerateHybridKey(key);

    CHybridPubKey pub(key.secpPub.Raw(), key.mldsaSigner->GetPublicKey());
    BOOST_REQUIRE(pub.IsValid());

    CScript scriptPubKey = GetScriptForHybridPubKey(pub);
    BOOST_REQUIRE(!scriptPubKey.empty());

    CTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey = scriptPubKey;

    CTransaction txTo;
    txTo.vin.resize(1);
    txTo.vout.resize(1);
    txTo.vin[0].prevout.hash = txFrom.GetHash();
    txTo.vin[0].prevout.n = 0;

    std::vector<unsigned char> ecSig, mlSig;
    CScript valid =
        SignHybridPair(key, scriptPubKey, txTo, 0, SIGHASH_ALL, ecSig, mlSig);
    BOOST_REQUIRE(!valid.empty());
    BOOST_REQUIRE(!ecSig.empty());
    BOOST_REQUIRE(!mlSig.empty());

    // Baseline: the untampered pair verifies.
    BOOST_CHECK(VerifyScript(valid, scriptPubKey, txTo, 0, false, 0));

    // 1) Corrupt a single byte in the middle of the ECDSA signature.
    std::vector<unsigned char> badEc = ecSig;
    BOOST_REQUIRE(badEc.size() > 2);
    badEc[badEc.size() / 2] ^= 0x01;
    CScript badEcScript;
    badEcScript << badEc << mlSig;
    BOOST_CHECK(!VerifyScript(badEcScript, scriptPubKey, txTo, 0, false, 0));

    // 2) Corrupt a single byte in the middle of the ML-DSA signature.
    std::vector<unsigned char> badMl = mlSig;
    BOOST_REQUIRE(badMl.size() > 2);
    badMl[badMl.size() / 2] ^= 0x01;
    CScript badMlScript;
    badMlScript << ecSig << badMl;
    BOOST_CHECK(!VerifyScript(badMlScript, scriptPubKey, txTo, 0, false, 0));

    // 3) Corrupt a single byte of the ML-DSA public key.
    //    Verified directly against the hybrid message so the corruption is
    //    isolated (a script-level re-check would also rehash the script).
    std::vector<unsigned char> preimage;
    BOOST_REQUIRE(ConstructSignatureHashPreimage(
        scriptPubKey, txTo, 0, SIGHASH_ALL, preimage));
    std::vector<unsigned char> msg = BuildHybridMessage(preimage);

    std::vector<unsigned char> mldsaSigBody(mlSig.begin(), mlSig.end() - 1);
    BOOST_CHECK(VerifyMLDSA(mldsaSigBody, pub.mldsaPubKey, msg));

    std::vector<unsigned char> badMldsaPub = pub.mldsaPubKey;
    BOOST_REQUIRE(badMldsaPub.size() > 2);
    badMldsaPub[badMldsaPub.size() / 2] ^= 0x01;
    BOOST_CHECK(!VerifyMLDSA(mldsaSigBody, badMldsaPub, msg));
}

/*
 * Pay-to-Hybrid-Public-Key-Hash (P2HPKH) spend path.
 *
 * scriptPubKey is:
 *
 *   OP_DUPHYBRID OP_HASHHYBRID160 <Hash160(pubEC || pubML)>
 *   OP_EQUALVERIFY OP_CHECKHYBRIDSIG
 *
 * and is what hybrid coinbase outputs use (`main.cpp` CreateNewBlock with
 * -minehybrid, via GetScriptForHybridPubKeyHash). Unlike P2PH the public
 * keys are NOT in the script, so the spender must reveal them: the
 * scriptSig is <sigEC> <sigML> <pubEC> <pubML>. OP_DUPHYBRID duplicates
 * the top two stack items (the two public keys) before they are hashed.
 */
BOOST_AUTO_TEST_CASE(hybrid_p2hphk_spend)
{
    CHybridTestKeyStore keystore;
    std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 1);
    BOOST_REQUIRE_EQUAL(pubs.size(), 1U);
    BOOST_REQUIRE(pubs[0].IsValid());

    // Mirror main.cpp: coinbase output for a hybrid mining key.
    CScript p2hphk = GetScriptForHybridPubKeyHash(uint160(pubs[0].GetID()));
    BOOST_REQUIRE(!p2hphk.empty());

    txnouttype whichType;
    std::vector<std::vector<unsigned char> > solutions;
    BOOST_CHECK(Solver(p2hphk, whichType, solutions));
    BOOST_CHECK_EQUAL(whichType, TX_HYBRID_PUBKEYHASH);
    BOOST_CHECK_EQUAL(ScriptSigArgsExpected(whichType, solutions), 4);

    CHybridTestKeyStore empty;
    BOOST_CHECK(IsMine(empty, p2hphk) == MINE_NO);
    BOOST_CHECK(IsMine(keystore, p2hphk) == MINE_SPENDABLE);

    CTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey = p2hphk;

    CTransaction txTo;
    txTo.vin.resize(1);
    txTo.vout.resize(1);
    txTo.vin[0].prevout.hash = txFrom.GetHash();
    txTo.vin[0].prevout.n = 0;

    // The wallet keystore signs the P2HPKH output (SignHybridTx's
    // TX_HYBRID_PUBKEYHASH branch).
    BOOST_REQUIRE(SignSignature(keystore, txFrom, txTo, 0, SIGHASH_ALL));
    BOOST_CHECK(VerifyScript(txTo.vin[0].scriptSig, p2hphk, txTo, 0, false, 0));

    // The scriptSig must reveal <sigEC> <sigML> <pubEC> <pubML> so that
    // OP_DUPHYBRID finds the public keys on the stack.
    std::vector<std::vector<unsigned char> > items =
        ScriptSigItems(txTo.vin[0].scriptSig);
    BOOST_REQUIRE_EQUAL(items.size(), 4U);
    BOOST_CHECK(items[0].size() >= 70 && items[0].size() <= 73); // DER sig + sighash byte
    BOOST_CHECK_EQUAL(items[1].size(), 3310U);                   // ML-DSA-65 + sighash byte
    BOOST_CHECK_EQUAL(items[2].size(), 33U);                     // compressed secp pubkey
    BOOST_CHECK_EQUAL(items[3].size(), 1952U);                   // raw ML-DSA-65 pubkey
    BOOST_CHECK(items[2] == pubs[0].ecdsaPubKey);
    BOOST_CHECK(items[3] == pubs[0].mldsaPubKey);

    // Negative: a byte flip anywhere in the scriptPubKey hash makes
    // OP_EQUALVERIFY fail.
    {
        std::vector<unsigned char> badScript(p2hphk.begin(), p2hphk.end());
        BOOST_REQUIRE(badScript.size() > 0);
        badScript[badScript.size() / 2] ^= 0x01;
        CScript p2hphkBad(badScript.begin(), badScript.end());
        BOOST_CHECK(!VerifyScript(txTo.vin[0].scriptSig, p2hphkBad, txTo, 0, false, 0));
    }

    // Negative: a byte flip in the revealed ML-DSA public key changes the
    // Hash160, so OP_EQUALVERIFY aborts before any signature check.
    {
        std::vector<unsigned char> badMldsaPub = items[3];
        BOOST_REQUIRE(badMldsaPub.size() > 2);
        badMldsaPub[badMldsaPub.size() / 2] ^= 0x01;

        CScript badScriptSig;
        badScriptSig << items[0] << items[1] << items[2] << badMldsaPub;
        BOOST_CHECK(!VerifyScript(badScriptSig, p2hphk, txTo, 0, false, 0));
    }

    // Negative: OP_DUPHYBRID requires four stack items
    // (sigEC sigML pubEC pubML); a scriptSig with only the signatures
    // (public keys missing) must be rejected before any hashing.
    {
        CScript missingKeys;
        missingKeys << items[0] << items[1];
        BOOST_CHECK(!VerifyScript(missingKeys, p2hphk, txTo, 0, false, 0));
    }
}

/*
 * CKey copy/move through the hybrid transaction signing path.
 *
 * SignSignature -> SignHybridTx obtains the signer's ECDSA key as a fresh
 * CKey (CHybridKey::GetCKey) and signs the ECDSA half of the hybrid
 * signature over the same sighash whose preimage feeds the ML-DSA half
 * (BuildHybridMessage). CHybridChurnKeyStore churns the stored CKey through
 * the copy/move pathways on every hand-out, so the signing key must still
 * be intact when SignHybridTx uses its own copy of it. Every churn chain
 * under the old implicit shallow copies destroyed the same shared EVP_PKEY
 * twice and aborted; the refcounted CKey must survive each mode and produce
 * hybrid signatures that VerifyScript accepts for every hybrid output type.
 */
BOOST_AUTO_TEST_CASE(key_copy_move_hybrid_signing)
{
    const CHybridChurnKeyStore::ChurnMode modes[] = {
        CHybridChurnKeyStore::COPY_CHAIN,
        CHybridChurnKeyStore::MOVE_CHAIN,
        CHybridChurnKeyStore::MOVE_ASSIGN_OUT,
    };

    for (size_t mi = 0; mi < 3; ++mi) {
        CHybridChurnKeyStore keystore;
        keystore.mode = modes[mi];

        std::vector<CHybridPubKey> pubs = BuildTestHybridPubs(keystore, 2);
        BOOST_REQUIRE_EQUAL(pubs.size(), 2U);

        CScript p2ph = GetScriptForHybridPubKey(pubs[0]);
        CScript p2hphk = GetScriptForHybridPubKeyHash(uint160(pubs[1].GetID()));
        CScript mscript = GetScriptForHybridMultisig(2, pubs);
        BOOST_REQUIRE(!p2ph.empty());
        BOOST_REQUIRE(!p2hphk.empty());
        BOOST_REQUIRE(!mscript.empty());

        // Direct spend of each hybrid output type: SignHybridTx signs the
        // ECDSA half with a CKey derived from the churned hand-out.
        const CScript* scripts[] = { &p2ph, &p2hphk, &mscript };
        for (size_t s = 0; s < 3; ++s) {
            const CScript& script = *scripts[s];
            CTransaction txFrom, txTo;
            MakeHybridSpend(script, txFrom, txTo);
            BOOST_REQUIRE(SignSignature(keystore, txFrom, txTo, 0, SIGHASH_ALL));
            BOOST_CHECK(VerifyScript(txTo.vin[0].scriptSig,
                                     txFrom.vout[0].scriptPubKey, txTo, 0,
                                     false, 0));
        }

        // P2SH spend of a hybrid output recurses through the redeem script
        // into SignHybridTx with the same keystore churn.
        {
            keystore.AddCScript(mscript);
            CScript p2sh;
            p2sh << OP_HASH160 << mscript.GetID() << OP_EQUAL;

            CTransaction txFrom, txTo;
            MakeHybridSpend(p2sh, txFrom, txTo);
            BOOST_REQUIRE(SignSignature(keystore, txFrom, txTo, 0, SIGHASH_ALL));
            BOOST_CHECK(VerifyScript(txTo.vin[0].scriptSig,
                                     txFrom.vout[0].scriptPubKey, txTo, 0,
                                     true, 0));
        }

        // Re-signing after the same churn: the scriptSig must keep
        // verifying, and the ECDSA half (RFC6979) must be stable across
        // runs even though the ML-DSA half is randomized (hedged signing).
        {
            CTransaction txFrom, txTo;
            MakeHybridSpend(p2ph, txFrom, txTo);
            std::vector<unsigned char> firstEcSig;
            for (int i = 0; i < 10; ++i) {
                BOOST_REQUIRE(SignSignature(keystore, txFrom, txTo, 0,
                                            SIGHASH_ALL));
                BOOST_REQUIRE(VerifyScript(txTo.vin[0].scriptSig,
                                           txFrom.vout[0].scriptPubKey, txTo,
                                           0, false, 0));

                std::vector<std::vector<unsigned char> > items =
                    ScriptSigItems(txTo.vin[0].scriptSig);
                BOOST_REQUIRE_EQUAL(items.size(), 2U); // <sigEC> <sigML>
                if (i == 0)
                    firstEcSig = items[0];
                else
                    BOOST_CHECK(items[0] == firstEcSig);
            }
        }

        // The signed hybrid spend survives a serialization round-trip.
        {
            CTransaction txFrom, txTo;
            MakeHybridSpend(mscript, txFrom, txTo);
            BOOST_REQUIRE(SignSignature(keystore, txFrom, txTo, 0, SIGHASH_ALL));

            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << txTo;
            CTransaction txCopy;
            ss >> txCopy;
            BOOST_CHECK(txCopy.vin[0].scriptSig == txTo.vin[0].scriptSig);
            BOOST_CHECK(VerifyScript(txCopy.vin[0].scriptSig,
                                     txFrom.vout[0].scriptPubKey, txCopy, 0,
                                     false, 0));
        }
    }
}

/*
 * OP_CHECKHYBRIDSIGVERIFY: the VERIFY variant of the single-key hybrid
 * check.
 *
 * Unlike OP_CHECKHYBRIDSIG (which pushes a boolean and continues), a
 * successful VERIFY pops the four stack items and continues without
 * pushing anything; a failed VERIFY aborts the entire script. The VERIFY
 * form is not a recognized output template, so Solver reports it as
 * TX_NONSTANDARD - it is intended for mid-script use.
 */
BOOST_AUTO_TEST_CASE(hybrid_checksigverify_opcode)
{
    CHybridKey key;
    GenerateHybridKey(key);

    CHybridPubKey pub(key.secpPub.Raw(), key.mldsaSigner->GetPublicKey());
    BOOST_REQUIRE(pub.IsValid());

    CScript verifyScript;
    verifyScript
        << pub.ecdsaPubKey
        << pub.mldsaPubKey
        << OP_CHECKHYBRIDSIGVERIFY
        << OP_1;

    txnouttype whichType;
    std::vector<std::vector<unsigned char> > solutions;
    BOOST_CHECK(!Solver(verifyScript, whichType, solutions));
    BOOST_CHECK_EQUAL(whichType, TX_NONSTANDARD);

    CTransaction txFrom;
    txFrom.vout.resize(1);
    txFrom.vout[0].scriptPubKey = verifyScript;

    CTransaction txTo;
    txTo.vin.resize(1);
    txTo.vout.resize(1);
    txTo.vin[0].prevout.hash = txFrom.GetHash();
    txTo.vin[0].prevout.n = 0;

    std::vector<unsigned char> ecSig, mlSig;
    CScript valid =
        SignHybridPair(key, verifyScript, txTo, 0, SIGHASH_ALL, ecSig, mlSig);
    BOOST_REQUIRE(!valid.empty());
    BOOST_REQUIRE(!ecSig.empty());
    BOOST_REQUIRE(!mlSig.empty());

    // Baseline: a valid pair is consumed by the VERIFY opcode and the
    // script continues to execute (OP_1 runs afterwards).
    BOOST_CHECK(VerifyScript(valid, verifyScript, txTo, 0, false, 0));

    // Negative: corrupting either signature abort the script in the
    // VERIFY failure path (nothing is pushed on failure).
    {
        std::vector<unsigned char> badEc = ecSig;
        BOOST_REQUIRE(badEc.size() > 2);
        badEc[badEc.size() / 2] ^= 0x01;
        CScript badScript;
        badScript << badEc << mlSig;
        BOOST_CHECK(!VerifyScript(badScript, verifyScript, txTo, 0, false, 0));
    }
    {
        std::vector<unsigned char> badMl = mlSig;
        BOOST_REQUIRE(badMl.size() > 2);
        badMl[badMl.size() / 2] ^= 0x01;
        CScript badScript;
        badScript << ecSig << badMl;
        BOOST_CHECK(!VerifyScript(badScript, verifyScript, txTo, 0, false, 0));
    }

    // Negative: the four-item stack guard. A scriptSig that only carries
    // one of the two signatures leaves three items once the scriptPubKey
    // pushes the public keys, which OP_CHECKHYBRIDSIGVERIFY rejects.
    {
        CScript singleSig;
        singleSig << ecSig;
        BOOST_CHECK(!VerifyScript(singleSig, verifyScript, txTo, 0, false, 0));
    }
}

BOOST_AUTO_TEST_CASE(ml_dsa_signer_serializer_edges)
{
    /*
     * Edge cases for the MLDSASigner private-key serializers.
     *
     * Three wire formats exist:
     *   v1: [alg] [pub_len:2] pub [priv_len:2] priv        (FromSerialized)
     *   v2: 'HYBK' ver alg flags [pub_len:2] pub [priv_len:2] priv
     *                                                    (FromSerializedV2)
     *   v3: 'HYBK' 3 'HYBS' 1 salt[16] nonce[12] ct tag[16]  (encrypted)
     *
     * The round-trips must reopen the exact same key material and the
     * parsers must reject truncated, oversized, mismatched, or
     * wrong-password payloads instead of half-parsing them.
     */

    std::unique_ptr<MLDSASigner> keyA = MLDSASigner::GenerateNew();
    BOOST_REQUIRE(keyA);

    const std::vector<unsigned char> pubA = keyA->GetPublicKey();
    BOOST_REQUIRE_EQUAL(pubA.size(), 1952U);

    std::vector<unsigned char> v1 = keyA->SerializePrivateKey();
    BOOST_REQUIRE_EQUAL(v1.size(), 5989U); // 1 + 2 + 1952 + 2 + 4032
    BOOST_REQUIRE_EQUAL(v1[0], (unsigned char)SigAlg::ML_DSA_65);

    // -- v1 round trip: reopened key signs/verifies identically ---------
    {
        std::unique_ptr<MLDSASigner> parsed = MLDSASigner::FromSerialized(v1);
        BOOST_REQUIRE(parsed);
        BOOST_CHECK(parsed->Algorithm() == SigAlg::ML_DSA_65);
        BOOST_CHECK(parsed->GetPublicKey() == pubA);
        BOOST_CHECK(parsed->SerializePrivateKey() == v1);

        const std::vector<unsigned char> msg =
            Bytes("v1 round trip");
        std::vector<unsigned char> sig;
        BOOST_CHECK(keyA->Sign(msg, sig));
        BOOST_REQUIRE(!sig.empty());
        BOOST_CHECK(parsed->Verify(msg, sig));

        std::vector<unsigned char> sig2;
        BOOST_CHECK(parsed->Sign(msg, sig2));
        BOOST_CHECK(keyA->Verify(msg, sig2));
    }

    // -- v2 round trip ------------------------------------------------
    {
        std::vector<unsigned char> v2 = MakeV2Record(v1);
        BOOST_REQUIRE_EQUAL(v2.size(), v1.size() + 6);
        BOOST_REQUIRE(std::equal(HYBRID_MAGIC, HYBRID_MAGIC + 4, v2.begin()));

        std::unique_ptr<MLDSASigner> parsed = MLDSASigner::FromSerializedV2(v2);
        BOOST_REQUIRE(parsed);
        BOOST_CHECK(parsed->GetPublicKey() == pubA);
        BOOST_CHECK(parsed->SerializePrivateKey() == v1);

        const std::vector<unsigned char> msg =
            Bytes("v2 round trip");
        std::vector<unsigned char> sig;
        BOOST_CHECK(keyA->Sign(msg, sig));
        BOOST_REQUIRE(!sig.empty());
        BOOST_CHECK(parsed->Verify(msg, sig));
    }

    // -- v3 encrypted round trip (and empty password) ------------------
    {
        const std::vector<unsigned char> pw =
            Bytes("correct horse battery staple");
        std::vector<unsigned char> enc = keyA->SerializePrivateKeyEncrypted(pw);
        BOOST_REQUIRE(!enc.empty());
        BOOST_REQUIRE_GE(enc.size(), 38U + 16U);
        BOOST_REQUIRE(std::equal(HYBRID_MAGIC, HYBRID_MAGIC + 4, enc.begin()));
        BOOST_CHECK_EQUAL(enc[4], HYBRID_VERSION_ENC);

        std::unique_ptr<MLDSASigner> parsed =
            MLDSASigner::FromEncryptedSerialized(pw, enc);
        BOOST_REQUIRE(parsed);
        BOOST_CHECK(parsed->GetPublicKey() == pubA);
        BOOST_CHECK(parsed->SerializePrivateKey() == v1);

        const std::vector<unsigned char> msg =
            Bytes("v3 round trip");
        std::vector<unsigned char> sig;
        BOOST_CHECK(keyA->Sign(msg, sig));
        BOOST_REQUIRE(!sig.empty());
        BOOST_CHECK(parsed->Verify(msg, sig));

        // The empty password is valid both ways.
        std::vector<unsigned char> encEmpty =
            keyA->SerializePrivateKeyEncrypted(std::vector<unsigned char>());
        BOOST_REQUIRE(!encEmpty.empty());
        std::unique_ptr<MLDSASigner> parsedEmpty =
            MLDSASigner::FromEncryptedSerialized(std::vector<unsigned char>(),
                                                 encEmpty);
        BOOST_REQUIRE(parsedEmpty);
        BOOST_CHECK(parsedEmpty->GetPublicKey() == pubA);
    }

    // -- v1 rejection cases --------------------------------------------
    {
        // Empty / too short to hold a header.
        BOOST_CHECK(!MLDSASigner::FromSerialized(std::vector<unsigned char>()));
        BOOST_CHECK(!MLDSASigner::FromSerialized(
            std::vector<unsigned char>(1, 0x02)));
        BOOST_CHECK(!MLDSASigner::FromSerialized(
            std::vector<unsigned char>{0x02, 0x07, 0xa0}));

        // Wrong algorithm byte (not ML_DSA_65).
        {
            std::vector<unsigned char> b = v1;
            b[0] = static_cast<unsigned char>(SigAlg::ECDSA_SECP256K1);
            BOOST_CHECK(!MLDSASigner::FromSerialized(b));
        }
        {
            std::vector<unsigned char> b = v1;
            b[0] = 0x00;
            BOOST_CHECK(!MLDSASigner::FromSerialized(b));
        }

        // Zero-length and over-size length fields.
        BOOST_CHECK(!MLDSASigner::FromSerialized(
            MakeV1Record(0, {}, 1, {0x01})));
        BOOST_CHECK(!MLDSASigner::FromSerialized(
            MakeV1Record(2049, {}, 1, {0x01})));
        BOOST_CHECK(!MLDSASigner::FromSerialized(
            MakeV1Record(1, {0x00}, 0, {})));
        BOOST_CHECK(!MLDSASigner::FromSerialized(
            MakeV1Record(1, {0x00}, 4097, {})));

        // A length at the accepted limit still passes only if the key
        // material verifies; garbage content must be rejected.
        {
            std::vector<unsigned char> pub(2048, 0), priv(4032, 0);
            BOOST_CHECK(!MLDSASigner::FromSerialized(
                MakeV1Record(2048, pub, 4032, priv)));
        }

        // Truncation inside the public key and inside the private key.
        {
            std::vector<unsigned char> b(v1.begin(), v1.begin() + 1000);
            BOOST_CHECK(!MLDSASigner::FromSerialized(b));
        }
        {
            std::vector<unsigned char> b = v1;
            b.resize(b.size() - 1);
            BOOST_CHECK(!MLDSASigner::FromSerialized(b));
        }

        // Trailing garbage after the private key.
        {
            std::vector<unsigned char> b = v1;
            b.push_back(0x00);
            BOOST_CHECK(!MLDSASigner::FromSerialized(b));
        }

        // A flipped byte inside the private key no longer derives the
        // matching public key.
        {
            std::vector<unsigned char> b = v1;
            b[b.size() / 2] ^= 0x01;
            BOOST_CHECK(!MLDSASigner::FromSerialized(b));
        }

        // The public key of a different key: the private key is intact
        // but no longer matches the embedded public key, so the record
        // is rejected.
        {
            std::unique_ptr<MLDSASigner> keyB = MLDSASigner::GenerateNew();
            BOOST_REQUIRE(keyB);
            const std::vector<unsigned char> pubB = keyB->GetPublicKey();
            BOOST_REQUIRE_EQUAL(pubB.size(), pubA.size());
            std::vector<unsigned char> b = v1;
            for (size_t i = 0; i < pubA.size(); ++i)
                b[3 + i] = pubB[i];
            BOOST_CHECK(!MLDSASigner::FromSerialized(b));
        }
    }

    // -- v2 rejection cases ---------------------------------------------
    {
        std::vector<unsigned char> v2 = MakeV2Record(v1);

        // Wrong magic.
        {
            std::vector<unsigned char> b = v2;
            b[3] = 'X';
            BOOST_CHECK(!MLDSASigner::FromSerializedV2(b));
        }
        // Wrong version: 1 (unknown) and 3 (reserved for encrypted).
        {
            std::vector<unsigned char> b = v2;
            b[4] = 1;
            BOOST_CHECK(!MLDSASigner::FromSerializedV2(b));
        }
        {
            std::vector<unsigned char> b = v2;
            b[4] = HYBRID_VERSION_ENC;
            BOOST_CHECK(!MLDSASigner::FromSerializedV2(b));
        }
        // Wrong algorithm byte.
        {
            std::vector<unsigned char> b = v2;
            b[5] = static_cast<unsigned char>(SigAlg::ECDSA_SECP256K1);
            BOOST_CHECK(!MLDSASigner::FromSerializedV2(b));
        }
        // Reserved flags must be zero.
        {
            std::vector<unsigned char> b = v2;
            b[6] = 0x01;
            BOOST_CHECK(!MLDSASigner::FromSerializedV2(b));
        }
        // Zero-length public key.
        {
            std::vector<unsigned char> b = v2;
            b[7] = 0x00;
            b[8] = 0x00;
            BOOST_CHECK(!MLDSASigner::FromSerializedV2(b));
        }
        // Truncated record (last private-key byte dropped).
        {
            std::vector<unsigned char> b(v2.begin(), v2.begin() + (v2.size() - 1));
            BOOST_CHECK(!MLDSASigner::FromSerializedV2(b));
        }
        // Trailing garbage.
        {
            std::vector<unsigned char> b = v2;
            b.push_back(0x00);
            BOOST_CHECK(!MLDSASigner::FromSerializedV2(b));
        }
    }

    // -- v3 rejection cases ---------------------------------------------
    {
        const std::vector<unsigned char> pw =
            Bytes("correct horse battery staple");
        const std::vector<unsigned char> wrongPw = Bytes("wrong password");
        std::vector<unsigned char> enc = keyA->SerializePrivateKeyEncrypted(pw);
        BOOST_REQUIRE(!enc.empty());

        // Wrong password: authentication tag fails.
        BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(wrongPw, enc));
        // Empty password cannot open a non-empty-password record.
        BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(
            std::vector<unsigned char>(), enc));

        // Empty input.
        BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(
            pw, std::vector<unsigned char>()));

        // Corrupt magic ('HYBK').
        {
            std::vector<unsigned char> b = enc;
            b[0] ^= 0x01;
            BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(pw, b));
        }
        // Outer version must be HYBRID_VERSION_ENC (3).
        {
            std::vector<unsigned char> b = enc;
            b[4] = HYBRID_VERSION;
            BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(pw, b));
        }
        {
            std::vector<unsigned char> b = enc;
            b[4] = 0x09;
            BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(pw, b));
        }
        // Inner hybrid-signature version must be 1.
        {
            std::vector<unsigned char> b = enc;
            b[9] = HYBRID_SIG_VERSION + 1;
            BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(pw, b));
        }
        // A flipped salt byte derives a different key -> auth failure.
        {
            std::vector<unsigned char> b = enc;
            b[13] ^= 0x01;
            BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(pw, b));
        }
        // A flipped nonce byte fails GCM decryption.
        {
            std::vector<unsigned char> b = enc;
            b[26] ^= 0x01;
            BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(pw, b));
        }
        // A flipped ciphertext byte fails the tag.
        {
            std::vector<unsigned char> b = enc;
            b[enc.size() / 2] ^= 0x01;
            BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(pw, b));
        }
        // A flipped authentication-tag byte fails GCM.
        {
            std::vector<unsigned char> b = enc;
            b[b.size() - 1] ^= 0x01;
            BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(pw, b));
        }
        // Truncation that shaves the tail tag, and a cut to exactly the
        // header+tag minimum.
        {
            std::vector<unsigned char> b(enc.begin(),
                                         enc.begin() + (enc.size() - 4));
            BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(pw, b));
        }
        {
            std::vector<unsigned char> b(enc.begin(), enc.begin() + 54);
            BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(pw, b));
        }
        {
            std::vector<unsigned char> b(enc.begin(), enc.begin() + 53);
            BOOST_CHECK(!MLDSASigner::FromEncryptedSerialized(pw, b));
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Hybrid message signatures (signmessage / verifymessage helpers)            */
/* ------------------------------------------------------------------------- */

// Offsets inside the v1 hybrid message signature container:
//   [0..3]   magic "HYBS"
//   [4]      version
//   [5..69]  ECDSA recoverable signature (65 bytes)
//   [70..102] ECDSA compressed pubkey (33 bytes)
//   [103..104] ML-DSA pubkey length (u16 BE)
//   [105..105+1952) ML-DSA pubkey
//   ...      ML-DSA sig length (u16 BE) + ML-DSA signature
static const size_t HYBMSG_MAGIC_END    = 4;
static const size_t HYBMSG_VER_OFF      = 4;
static const size_t HYBMSG_ECDSA_SIG    = 65;   // [5..69]
static const size_t HYBMSG_ECDSA_PUB    = 33;   // [70..102]
static const size_t HYBMSG_MLDSA_PUB_OFF = HYBMSG_MAGIC_END + 1 +
                                           HYBMSG_ECDSA_SIG + HYBMSG_ECDSA_PUB;

BOOST_AUTO_TEST_CASE(hybrid_message_sign_verify)
{
    // Round-trip: a valid hybrid message must sign and verify.
    CHybridKey hk;
    GenerateHybridKey(hk);

    const std::string msg = "The quick brown fox jumps over the lazy dog";

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(SignHybridMessage(hk, msg, sig));

    CHybridKeyID hybridID = hk.GetHybridID();

    // Minimum header layout sanity: ECDSA compact + pubkey + lengths.
    BOOST_REQUIRE(sig.size() > HYBMSG_MLDSA_PUB_OFF + 1952 + 2);
    BOOST_CHECK_EQUAL(std::string(sig.begin(), sig.begin() + 4), "HYBS");

    // Correct address verifies.
    BOOST_CHECK(VerifyHybridMessage(sig, hybridID, msg));

    // The hybrid address derived from the pubkeys rounds-trips through the
    // address encoding used by the RPCs.
    CCoinAddress address(hybridID);
    BOOST_REQUIRE(address.IsValid());
    CHybridKeyID parsedID;
    BOOST_REQUIRE(address.GetHybridKeyID(parsedID));
    BOOST_CHECK(parsedID == hybridID);
    BOOST_CHECK(VerifyHybridMessage(sig, parsedID, msg));
}

BOOST_AUTO_TEST_CASE(hybrid_message_verify_negatives)
{
    CHybridKey hk;
    GenerateHybridKey(hk);

    const std::string msg = "hybrid message negative tests";
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(SignHybridMessage(hk, msg, sig));

    CHybridKeyID hybridID = hk.GetHybridID();

    // An unrelated hybrid address must not verify.
    CHybridKey otherHk;
    GenerateHybridKey(otherHk);
    BOOST_CHECK(!VerifyHybridMessage(sig, otherHk.GetHybridID(), msg));

    // Tampered message.
    BOOST_CHECK(!VerifyHybridMessage(sig, hybridID, msg + "x"));
    BOOST_CHECK(!VerifyHybridMessage(sig, hybridID, ""));

    // A legacy (non-hybrid) signature fed to a hybrid address fails on the
    // magic check rather than parsing as a hybrid container.
    std::vector<unsigned char> legacyCompact(65, 0x00);
    legacyCompact[0] = 0x1f;
    BOOST_CHECK(!VerifyHybridMessage(legacyCompact, hybridID, msg));

    // Corrupt magic.
    {
        std::vector<unsigned char> b = sig;
        b[0] ^= 0x01;
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    // Unsupported version.
    {
        std::vector<unsigned char> b = sig;
        b[HYBMSG_VER_OFF] = 0x02;
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    // Corrupt a byte of the ECDSA recoverable signature (inside [5..69]).
    {
        std::vector<unsigned char> b = sig;
        b[HYBMSG_MAGIC_END + 1 + 32] ^= 0x01;
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    // Corrupt a byte of the embedded ECDSA public key.
    {
        std::vector<unsigned char> b = sig;
        b[HYBMSG_MAGIC_END + 1 + HYBMSG_ECDSA_SIG + 5] ^= 0x01;
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    // Corrupt a byte of the embedded ML-DSA public key.
    {
        std::vector<unsigned char> b = sig;
        b[HYBMSG_MLDSA_PUB_OFF + 2 + 1000] ^= 0x01;
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    // Corrupt a byte of the ML-DSA signature itself.
    {
        std::vector<unsigned char> b = sig;
        b[sig.size() - 100] ^= 0x01;
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    // Reject a noncanonical ML-DSA pubkey length: the address bind would be
    // structurally impossible, and the length must match ML-DSA-65.
    {
        std::vector<unsigned char> b = sig;
        b[HYBMSG_MLDSA_PUB_OFF] = 0x08;
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    {
        std::vector<unsigned char> b = sig;
        b[HYBMSG_MLDSA_PUB_OFF + 1] = 0x00;
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    // Truncation.
    {
        std::vector<unsigned char> b(sig.begin(),
                                     sig.begin() + (sig.size() - 32));
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    {
        std::vector<unsigned char> b(sig.begin(), sig.begin() + 100);
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    // Trailing garbage.
    {
        std::vector<unsigned char> b = sig;
        b.push_back(0x00);
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    // The ML-DSA signature length field must hold exactly the raw ML-DSA-65
    // size (parity with consensus VerifyMLDSA), not merely parse cleanly.
    const size_t mldsaSigLenOff = HYBMSG_MLDSA_PUB_OFF + 2 +
                                  ML_DSA_65_PUBKEY_SIZE;
    const size_t mldsaSigOff = mldsaSigLenOff + 2;
    {
        // One byte shorter than the real signature.
        std::vector<unsigned char> b = sig;
        const size_t shortLen = (sig.size() - mldsaSigOff) - 1;
        b[mldsaSigLenOff] = (shortLen >> 8) & 0xFF;
        b[mldsaSigLenOff + 1] = shortLen & 0xFF;
        b.erase(b.begin() + (mldsaSigOff + shortLen));
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    {
        // One byte longer than the real signature.
        std::vector<unsigned char> b = sig;
        const size_t longLen = (sig.size() - mldsaSigOff) + 1;
        b[mldsaSigLenOff] = (longLen >> 8) & 0xFF;
        b[mldsaSigLenOff + 1] = longLen & 0xFF;
        b.insert(b.begin() + (mldsaSigOff + longLen - 1), 0x00);
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    }
    // Degenerate / empty input.
    BOOST_CHECK(!VerifyHybridMessage(std::vector<unsigned char>(), hybridID, msg));
}

BOOST_AUTO_TEST_CASE(hybrid_message_malformed_matrix)
{
    // Systematic malformed-HYBS matrix over a known-good signature. Every
    // mutation must fail cleanly (no crash, no allocation blow-up) and be
    // rejected atomically: ParseHybridMessage never partially accepts or
    // partially populates its outputs, and VerifyHybridMessage returns false.
    CHybridKey hk;
    GenerateHybridKey(hk);
    const std::string msg = "hybs malformed matrix";

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(SignHybridMessage(hk, msg, sig));
    // Exact container size pin: 4 magic + 1 version + 65 ECDSA sig +
    // 33 ECDSA pub + 2 pub-len + 1952 ML-DSA pub + 2 sig-len + 3309 ML-DSA sig.
    BOOST_REQUIRE_EQUAL(sig.size(),
                        4u + 1u + 65u + ECDSA_PUBKEY_SIZE + 2u +
                            ML_DSA_65_PUBKEY_SIZE + 2u + (ML_DSA_65_SIG_SIZE - 1));

    CHybridKeyID hybridID = hk.GetHybridID();

    const auto expectReject = [&](const std::vector<unsigned char>& b) {
        std::vector<unsigned char> c, p, mp, ms;
        BOOST_CHECK(!ParseHybridMessage(b, c, p, mp, ms));
        // No partially accepted data: outputs are only filled on full success.
        BOOST_CHECK(c.empty() && p.empty() && mp.empty() && ms.empty());
        BOOST_CHECK(!VerifyHybridMessage(b, hybridID, msg));
    };

    // ---- Positive control ----
    {
        std::vector<unsigned char> c, p, mp, ms;
        BOOST_REQUIRE(ParseHybridMessage(sig, c, p, mp, ms));
        BOOST_CHECK_EQUAL(c.size(), 65u);
        BOOST_CHECK_EQUAL(p.size(), ECDSA_PUBKEY_SIZE);
        BOOST_CHECK_EQUAL(mp.size(), ML_DSA_65_PUBKEY_SIZE);
        BOOST_CHECK_EQUAL(ms.size(), ML_DSA_65_SIG_SIZE - 1);
    }

    // ---- Empty / degenerate inputs ----
    expectReject(std::vector<unsigned char>());
    expectReject(std::vector<unsigned char>(1, 0x00));
    expectReject(std::vector<unsigned char>(5, 0x00));    // right size, zeroed
    expectReject(std::vector<unsigned char>(100, 0x00));
    expectReject(std::vector<unsigned char>(65536, 0x00)); // large zero buffer

    // ---- Bad magic (every magic byte) ----
    for (size_t i = 0; i < 4; ++i) {
        std::vector<unsigned char> b = sig;
        b[i] = 0x00;
        expectReject(b);
    }

    // ---- Bad version (0, 2, 0xFF) ----
    for (unsigned char v : { (unsigned char)0x00, (unsigned char)0x02,
                             (unsigned char)0xFF }) {
        std::vector<unsigned char> b = sig;
        b[HYBMSG_VER_OFF] = v;
        expectReject(b);
    }

    // ---- Truncation at every byte boundary (includes every major field
    //      boundary: magic, version, ECDSA sig, ECDSA pub, ML-DSA pub len,
    //      ML-DSA pub, ML-DSA sig len, and every point inside the sig) ----
    for (size_t len = 0; len < sig.size() - 1; ++len)
        expectReject(std::vector<unsigned char>(sig.begin(), sig.begin() + len));

    // ---- ECDSA public key wrong length: there is no ECDSA length field, so
    //      a wrong size surfaces as cuts at/before the fixed 33-byte block ----
    for (size_t len : { 4u + 1u + 65u,           // ECDSA sig only
                        4u + 1u + 65u + 32u,     // ECDSA pub cut short
                        4u + 1u + 65u + 33u,     // pub ok, no lengths
                        4u + 1u + 65u + 33u + 2u })
        expectReject(std::vector<unsigned char>(sig.begin(), sig.begin() + len));

    // ---- ML-DSA public key length field: 0, 1, short-by-one (0x07A1),
    //      long-by-one (0x07A3), and maximum u16 (0xFFFF) ----
    for (uint16_t bad : { (uint16_t)0x0000, (uint16_t)0x0001, (uint16_t)0x07A1,
                          (uint16_t)0x07A3, (uint16_t)0xFFFF }) {
        std::vector<unsigned char> b = sig;
        b[HYBMSG_MLDSA_PUB_OFF]     = (unsigned char)(bad >> 8);
        b[HYBMSG_MLDSA_PUB_OFF + 1] = (unsigned char)(bad & 0xFF);
        expectReject(b);
    }

    // ---- ML-DSA signature length field: 0, 3308 (short), 3310 (long), and
    //      maximum u16 (0xFFFF). 0xFFFF must be rejected by the exact-length
    //      guard before any read or allocation for the claimed size. ----
    {
        const size_t sigLenOff =
            HYBMSG_MLDSA_PUB_OFF + 2 + ML_DSA_65_PUBKEY_SIZE;
        for (uint16_t bad : { (uint16_t)0x0000, (uint16_t)0x0CEC, // 3308
                              (uint16_t)0x0CEE, // 3310
                              (uint16_t)0xFFFF }) {
            std::vector<unsigned char> b = sig;
            b[sigLenOff]     = (unsigned char)(bad >> 8);
            b[sigLenOff + 1] = (unsigned char)(bad & 0xFF);
            expectReject(b);
        }
    }

    // ---- Trailing bytes after a complete, valid container ----
    {
        std::vector<unsigned char> b = sig;
        b.push_back(0x00);
        expectReject(b);
    }
    {
        std::vector<unsigned char> b = sig;
        b.push_back(0xFF);
        expectReject(b);
    }
    {
        std::vector<unsigned char> b = sig;
        b.insert(b.end(), { 0x00, 0x01, 0x02, 0x03 });
        expectReject(b);
    }
    {
        // A second magic trailer must also be rejected.
        std::vector<unsigned char> b = sig;
        b.insert(b.end(), { 'H', 'Y', 'B', 'S' });
        expectReject(b);
    }
}

// Forced (non-elided) CKey copy through a by-value helper parameter.
static CKey dispatchKey(CKey k) { return k; }

BOOST_AUTO_TEST_CASE(hybrid_message_encrypt_decrypt)
{
    // encryptmessage/decryptmessage operate with the ECDSA component of a
    // hybrid key (ECIES over secp256k1); the ML-DSA half is not involved in
    // confidentiality. Verify the round-trip with a plain in-memory key.
    CHybridKey hk;
    GenerateHybridKey(hk);

    const std::string secret = "quantum-safe greetings";
    std::vector<unsigned char> ciphertext;
    hk.secpPub.EncryptData(
        std::vector<unsigned char>(secret.begin(), secret.end()),
        ciphertext);
    BOOST_REQUIRE(!ciphertext.empty());

    CKey secp = hk.GetCKey();
    std::vector<unsigned char> plain;
    secp.DecryptData(ciphertext, plain);
    BOOST_CHECK_EQUAL(std::string(plain.begin(), plain.end()), secret);

    // A different hybrid key must not be able to decrypt.
    CHybridKey otherHk;
    GenerateHybridKey(otherHk);
    BOOST_CHECK_THROW(otherHk.GetCKey().DecryptData(ciphertext, plain),
                      key_error);

    // Tampered ciphertext (counter, tag, or payload) must not decrypt.
    std::vector<unsigned char> bad = ciphertext;
    bad[bad.size() / 2] ^= 0x01;
    BOOST_CHECK_THROW(secp.DecryptData(bad, plain), key_error);

    std::vector<unsigned char> badTag = ciphertext;
    badTag[badTag.size() - 1] ^= 0x01;
    BOOST_CHECK_THROW(secp.DecryptData(badTag, plain), key_error);

    // Regression: decryptmessage obtains its key as
    //     CKey key;  key = hk.GetCKey();
    // which is a COPY ASSIGNMENT. CKey used to have only implicit shallow
    // copies (it owns a raw EVP_PKEY* freed in its destructor), so the
    // temporary's destructor freed the shared PKEY and the destination hung
    // onto a dangling pointer - `key.DecryptData()` then hit a
    // use-after-free (segfault) in the daemon. Copy-init happens to be
    // elided by NRVO, which is why the simple `CKey secp = hk.GetCKey();`
    // above did not crash. Exercise the assignment and a forced genuine copy
    // (function argument) so both go through the refcount shared-PKEY
    // semantics.
    CKey keyByAssign;
    keyByAssign = hk.GetCKey();
    std::vector<unsigned char> plainAssign;
    keyByAssign.DecryptData(ciphertext, plainAssign);
    BOOST_CHECK_EQUAL(std::string(plainAssign.begin(), plainAssign.end()),
                      secret);

    CKey keyByCopy(keyByAssign);
    std::vector<unsigned char> plainCopy;
    keyByCopy.DecryptData(ciphertext, plainCopy);
    BOOST_CHECK_EQUAL(std::string(plainCopy.begin(), plainCopy.end()), secret);

    CKey keyByDispatch = dispatchKey(keyByAssign);
    std::vector<unsigned char> plainDispatch;
    keyByDispatch.DecryptData(ciphertext, plainDispatch);
    BOOST_CHECK_EQUAL(std::string(plainDispatch.begin(), plainDispatch.end()),
                      secret);
}

BOOST_AUTO_TEST_CASE(hybrid_key_export_import_roundtrip)
{
    // importhybridkey accepts exactly what dumphybridkey exports: the ECDSA
    // half as WIF and the ML-DSA-65 half as Base64-encoded DER. Exercise the
    // same two conversion pipelines plus the wallet load path (plaintext
    // at-rest record), and require the re-imported key to reproduce the
    // original hybrid identity and signing ability.
    CHybridKey hk;
    GenerateHybridKey(hk);
    BOOST_REQUIRE(hk.mldsaSigner);

    // ---- Export shape (mimics dumphybridkey) ----
    CKey key = hk.GetCKey();
    bool fCompressed = false;
    CSecret secret = key.GetSecret(fCompressed);
    std::string wif = CCoinSecret(secret, fCompressed).ToString();

    EVP_PKEY* pkey = hk.mldsaSigner->GetKey();
    BOOST_REQUIRE(pkey);
    unsigned char* buf = NULL;
    int len = i2d_PrivateKey(pkey, &buf);
    BOOST_REQUIRE(len > 0 && buf);
    std::vector<unsigned char> der(buf, buf + len);
    OPENSSL_free(buf);
    std::string derB64 = EncodeBase64(der.data(), der.size());

    // The PKCS#8 DER of an ML-DSA-65 private key (~4,098 bytes; expanded
    // 4,032-byte key plus header) is larger than the raw private-key size.
    // Pin this so importhybridkey's upper-bound guard can never shrink below
    // a valid export.
    BOOST_CHECK(der.size() > 4096);
    BOOST_CHECK(der.size() < 8192);

    // ---- Import shape (mimics importhybridkey) ----
    CCoinSecret vchSecret;
    BOOST_REQUIRE(vchSecret.SetString(wif));
    CSecret impSecret = vchSecret.GetSecret(fCompressed);
    CKey impKey;
    BOOST_REQUIRE(impKey.SetSecret(impSecret, fCompressed) && impKey.IsValid());

    bool fInvalid = false;
    std::vector<unsigned char> impDer =
        DecodeBase64(derB64.c_str(), &fInvalid);
    BOOST_REQUIRE(!fInvalid && !impDer.empty());
    const unsigned char* p = impDer.data();
    EVP_PKEY* impPkey = d2i_AutoPrivateKey(NULL, &p, impDer.size());
    BOOST_REQUIRE(impPkey);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_guard(
        impPkey, &EVP_PKEY_free);

    CHybridKey imported;
    imported.secpPriv    = impKey.GetPrivKey();
    imported.secpPub     = impKey.GetPubKey();
    imported.nCreateTime = GetTime();
    imported.mldsaAlg    = "p384_mldsa65";
    imported.mldsaSigner = std::make_unique<MLDSASigner>(pkey_guard.get());

    // The round-tripped key must validate and reproduce the original ID.
    BOOST_CHECK(ValidateHybridKey(imported));
    BOOST_CHECK(imported.GetHybridID() == hk.GetHybridID());

    // Signing with the re-imported key must still work.
    const std::string msg = "hybrid export/import round trip";
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(SignHybridMessage(imported, msg, sig));
    BOOST_CHECK(VerifyHybridMessage(sig, imported.GetHybridID(), msg));

    // It must load into a wallet exactly like a wallet-generated key.
    CWallet wallet;
    CHybridKeyDisk disk = CHybridKeyDisk::FromMemory(imported);
    BOOST_CHECK(disk.CheckChecksum());

    CKeyingMaterial vMasterKey; // plaintext records ignore the master key
    BOOST_REQUIRE(LoadHybridKey(&wallet, disk, vMasterKey));
    BOOST_CHECK(wallet.HaveHybridKey(imported.GetHybridID()));

    CHybridKey loaded;
    BOOST_REQUIRE(wallet.GetHybridKey(imported.GetHybridID(), loaded));
    BOOST_CHECK(loaded.GetHybridID() == hk.GetHybridID());
    BOOST_CHECK(loaded.secpPub == hk.secpPub);
    BOOST_REQUIRE(loaded.mldsaSigner);

    std::vector<unsigned char> sig2;
    BOOST_REQUIRE(SignHybridMessage(loaded, msg, sig2));
    BOOST_CHECK(VerifyHybridMessage(sig2, imported.GetHybridID(), msg));
}
