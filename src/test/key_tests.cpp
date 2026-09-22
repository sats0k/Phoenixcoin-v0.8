#include <boost/test/unit_test.hpp>

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "key.h"
#include "base58.h"
#include "uint256.h"
#include "util.h"
#include "keystore.h"
#include "script.h"
#include "main.h"

using namespace std;

static const string strSecret1  ("7ApCouohKXQW6VMvpM4iM4FCS7iN8SKVMTrnE7oVLTdS9dyA7yb");
static const string strSecret2  ("7C3kXiz1TjskaBpS9Vt3uAb5Jm2pUkwhW9wwgAoAgBdwb2FCLGH");
static const string strSecret1C ("UEKM8456xmCjREBNXyZPVXKfTrdaFpkc9KYicu2C4tXp11ohovtP");
static const string strSecret2C ("UKm98cJd32F1KUkMzWUKoFKQ1PM2ZWxRmgVWKtEmhwx3w51SKzUc");
static const CCoinAddress addr1 ("Puj5zta1iV8PTU6kg26uSbsN6mr3xSfmrt");
static const CCoinAddress addr2 ("PjMWANfUmJUanYyNhuYZRNDjvcsyMAfXy6");
static const CCoinAddress addr1C("Puj5zta1iV8PTU6kg26uSbsN6mr3xSfmrt");
static const CCoinAddress addr2C("PjMWANfUmJUanYyNhuYZRNDjvcsyMAfXy6");


static const string strAddressBad("1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF");


#ifdef KEY_TESTS_DUMPINFO
void dumpKeyInfo(uint256 privkey)
{
    CSecret secret;
    secret.resize(32);
    memcpy(&secret[0], &privkey, 32);
    vector<unsigned char> sec;
    sec.resize(32);
    memcpy(&sec[0], &secret[0], 32);
    printf("  * secret (hex): %s\n", HexStr(sec).c_str());

    for (int nCompressed=0; nCompressed<2; nCompressed++)
    {
        bool fCompressed = nCompressed == 1;
        printf("  * %s:\n", fCompressed ? "compressed" : "uncompressed");
        CCoinSecret bsecret;
        bsecret.SetSecret(secret, fCompressed);
        printf("    * secret (base58): %s\n", bsecret.ToString().c_str());
        CKey key;
        key.SetSecret(secret, fCompressed);
        vector<unsigned char> vchPubKey = key.GetPubKey();
        printf("    * pubkey (hex): %s\n", HexStr(vchPubKey).c_str());
        printf("    * address (base58): %s\n", CCoinAddress(vchPubKey).ToString().c_str());
    }
}
#endif


BOOST_AUTO_TEST_SUITE(key_tests)

BOOST_AUTO_TEST_CASE(key_test1)
{
    CCoinSecret bsecret1, bsecret2, bsecret1C, bsecret2C, baddress1;
    BOOST_CHECK( bsecret1.SetString (strSecret1));
    BOOST_CHECK( bsecret2.SetString (strSecret2));
    BOOST_CHECK( bsecret1C.SetString(strSecret1C));
    BOOST_CHECK( bsecret2C.SetString(strSecret2C));
    BOOST_CHECK(!baddress1.SetString(strAddressBad));

    bool fCompressed;
    CSecret secret1  = bsecret1.GetSecret (fCompressed);
    BOOST_CHECK(fCompressed == false);
    CSecret secret2  = bsecret2.GetSecret (fCompressed);
    BOOST_CHECK(fCompressed == false);
    CSecret secret1C = bsecret1C.GetSecret(fCompressed);
    BOOST_CHECK(fCompressed == true);
    CSecret secret2C = bsecret2C.GetSecret(fCompressed);
    BOOST_CHECK(fCompressed == true);

    BOOST_CHECK(secret1 == secret1C);
    BOOST_CHECK(secret2 == secret2C);

    CKey key1, key2, key1C, key2C;
    key1.SetSecret(secret1, false);
    key2.SetSecret(secret2, false);
    key1C.SetSecret(secret1, true);
    key2C.SetSecret(secret2, true);

    BOOST_CHECK(addr1.Get()  == CTxDestination(key1.GetPubKey().GetID()));
    BOOST_CHECK(addr2.Get()  == CTxDestination(key2.GetPubKey().GetID()));
    BOOST_CHECK(addr1C.Get() == CTxDestination(key1C.GetPubKey().GetID()));
    BOOST_CHECK(addr2C.Get() == CTxDestination(key2C.GetPubKey().GetID()));

    for (int n=0; n<16; n++)
    {
        string strMsg = strprintf("Very secret message %i: 11", n);
        uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

        // normal signatures

        vector<unsigned char> sign1, sign2, sign1C, sign2C;

        BOOST_CHECK(key1.Sign (hashMsg, sign1));
        BOOST_CHECK(key2.Sign (hashMsg, sign2));
        BOOST_CHECK(key1C.Sign(hashMsg, sign1C));
        BOOST_CHECK(key2C.Sign(hashMsg, sign2C));

        BOOST_CHECK( key1.Verify(hashMsg, sign1));
        BOOST_CHECK(!key1.Verify(hashMsg, sign2));
        BOOST_CHECK( key1.Verify(hashMsg, sign1C));
        BOOST_CHECK(!key1.Verify(hashMsg, sign2C));

        BOOST_CHECK(!key2.Verify(hashMsg, sign1));
        BOOST_CHECK( key2.Verify(hashMsg, sign2));
        BOOST_CHECK(!key2.Verify(hashMsg, sign1C));
        BOOST_CHECK( key2.Verify(hashMsg, sign2C));

        BOOST_CHECK( key1C.Verify(hashMsg, sign1));
        BOOST_CHECK(!key1C.Verify(hashMsg, sign2));
        BOOST_CHECK( key1C.Verify(hashMsg, sign1C));
        BOOST_CHECK(!key1C.Verify(hashMsg, sign2C));

        BOOST_CHECK(!key2C.Verify(hashMsg, sign1));
        BOOST_CHECK( key2C.Verify(hashMsg, sign2));
        BOOST_CHECK(!key2C.Verify(hashMsg, sign1C));
        BOOST_CHECK( key2C.Verify(hashMsg, sign2C));

        // compact signatures (with key recovery)

        vector<unsigned char> csign1, csign2, csign1C, csign2C;

        BOOST_CHECK(key1.SignCompact (hashMsg, csign1));
        BOOST_CHECK(key2.SignCompact (hashMsg, csign2));
        BOOST_CHECK(key1C.SignCompact(hashMsg, csign1C));
        BOOST_CHECK(key2C.SignCompact(hashMsg, csign2C));

        CKey rkey1, rkey2, rkey1C, rkey2C;

        BOOST_CHECK(rkey1.SetCompactSignature (hashMsg, csign1));
        BOOST_CHECK(rkey2.SetCompactSignature (hashMsg, csign2));
        BOOST_CHECK(rkey1C.SetCompactSignature(hashMsg, csign1C));
        BOOST_CHECK(rkey2C.SetCompactSignature(hashMsg, csign2C));


        BOOST_CHECK(rkey1.GetPubKey()  == key1.GetPubKey());
        BOOST_CHECK(rkey2.GetPubKey()  == key2.GetPubKey());
        BOOST_CHECK(rkey1C.GetPubKey() == key1C.GetPubKey());
        BOOST_CHECK(rkey2C.GetPubKey() == key2C.GetPubKey());
    }
}

BOOST_AUTO_TEST_CASE(key_copy_move_lifetime)
{
    // CKey owns a raw OpenSSL EVP_PKEY* freed in its destructor. Copy / move
    // must share that handle through refcounting (EVP_PKEY_up_ref) so no two
    // keys ever own the same pointer independently. The original regression:
    //      CKey key;  key = hk.GetCKey();
    // used an implicit shallow copy, the temporary's destructor freed the
    // PKEY, and `key` was left dangling - `key.DecryptData()` (ECIES via the
    // private PKEY) then read freed memory in the daemon.
    //
    // SignCompact() signs only from vchSecret, so it cannot alone detect a
    // freed PKEY; the ECIES decrypt probes are the meaningful lifetime
    // checks, since they exercise EVP_PKEY_derive on the shared handle.

    const string strMsg = "key copy/move lifetime";
    const uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

    // --- Copy constructor: copies share the PKEY and survive each other ------
    CKey a;
    a.MakeNewKey(true);
    const CPubKey pubA = a.GetPubKey();

    {
        CKey b(a);                    // copy construct
        BOOST_CHECK(b.GetPubKey() == pubA);
    }                                 // b dies: its dtor must only drop a ref

    // Several copes chained, then the middle ones destroyed.
    {
        CKey c1(a);
        CKey c2(c1);
    }                                 // c1, c2 destroyed
    vector<unsigned char> sigA;
    BOOST_CHECK(a.Sign(hashMsg, sigA));
    BOOST_CHECK(a.Verify(hashMsg, sigA));

    // --- Copy survives the source being reset mid-flight ----------------------
    {
        CKey copy1(a);
        CKey copy2(copy1);
        copy1.Reset();                // free one reference while copy2 holds one
        vector<unsigned char> sig2;
        BOOST_CHECK(copy2.Sign(hashMsg, sig2));
        BOOST_CHECK(a.Verify(hashMsg, sig2)); // refcount not corrupted
    }

    // --- Move constructor: source is left null, target owns the key ----------
    CKey m1;
    m1.MakeNewKey(true);
    const CPubKey pubM1 = m1.GetPubKey();
    {
        CKey m2(std::move(m1));
        BOOST_CHECK(m1.IsNull());
        BOOST_CHECK(m2.GetPubKey() == pubM1);
        vector<unsigned char> sigM;
        BOOST_CHECK(m2.Sign(hashMsg, sigM));
        BOOST_CHECK(m2.Verify(hashMsg, sigM));

        // A moved-from key is a valid null key: copying it is safe and null.
        CKey m3(m1);
        BOOST_CHECK(m3.IsNull());
        BOOST_CHECK(!m3.Sign(hashMsg, sigM)); // clean failure, no crash
    }
    BOOST_CHECK(m1.IsNull());         // still null after the receiver died

    // --- Move assignment into a null destination leaves the source null ------
    CKey m4;
    m4.MakeNewKey(true);
    const CPubKey pubM4 = m4.GetPubKey();
    {
        CKey m5;                      // null destination
        m5 = std::move(m4);
        BOOST_CHECK(m4.IsNull());
        BOOST_CHECK(m5.GetPubKey() == pubM4);
        vector<unsigned char> sigM5;
        BOOST_CHECK(m5.Sign(hashMsg, sigM5));
        BOOST_CHECK(m5.Verify(hashMsg, sigM5));
    }

    // --- Move assignment into a populated destination (swap semantics) -------
    // The moved-from object inherits whichever key the destination held, and
    // that key must remain valid and independent.
    CKey m6;
    m6.MakeNewKey(true);
    const CPubKey pubM6 = m6.GetPubKey();
    {
        CKey m7;
        m7.MakeNewKey(true);
        const CPubKey oldM7 = m7.GetPubKey();
        m7 = std::move(m6);           // m7 now holds m6's key
        BOOST_CHECK(m7.GetPubKey() == pubM6);
        BOOST_CHECK(m6.GetPubKey() == oldM7); // m6 inherited m7's old key
        vector<unsigned char> sig6, sig7;
        BOOST_CHECK(m6.Sign(hashMsg, sig6));
        BOOST_CHECK(m6.Verify(hashMsg, sig6));
        BOOST_CHECK(m7.Sign(hashMsg, sig7));
        BOOST_CHECK(m7.Verify(hashMsg, sig7));
    }

    // --- Self-assignment must not free the PKEY -------------------------------
    CKey s;
    s.MakeNewKey(true);
    const CPubKey pubS = s.GetPubKey();
    s = s;                            // copy self-assign
    BOOST_CHECK(s.GetPubKey() == pubS);
    s = std::move(s);                 // move self-assign
    BOOST_CHECK(s.GetPubKey() == pubS);
    vector<unsigned char> sigS;
    BOOST_CHECK(s.Sign(hashMsg, sigS));
    BOOST_CHECK(s.Verify(hashMsg, sigS));

    // --- Copy assignment replaces a populated destination ---------------------
    CKey d1;
    d1.MakeNewKey(true);
    {
        CKey d2;
        d2.MakeNewKey(true);
        BOOST_CHECK(d2.GetPubKey() != d1.GetPubKey());
        d2 = d1;
        BOOST_CHECK(d2.GetPubKey() == d1.GetPubKey());
        vector<unsigned char> sigD;
        BOOST_CHECK(d1.Sign(hashMsg, sigD));
        BOOST_CHECK(d2.Verify(hashMsg, sigD));
    }

    // --- swap() exchanges the full key state ----------------------------------
    {
        CKey w1;
        w1.MakeNewKey(true);
        CKey w2;
        w2.MakeNewKey(false);         // uncompressed, to check fCompressedPubKey
        const CPubKey pw1 = w1.GetPubKey();
        const CPubKey pw2 = w2.GetPubKey();
        BOOST_CHECK(w1.IsCompressed());
        BOOST_CHECK(!w2.IsCompressed());
        w1.swap(w2);
        BOOST_CHECK(w1.GetPubKey() == pw2);
        BOOST_CHECK(w2.GetPubKey() == pw1);
        BOOST_CHECK(!w1.IsCompressed());
        BOOST_CHECK(w2.IsCompressed());
        vector<unsigned char> sigW;
        BOOST_CHECK(w1.Sign(hashMsg, sigW));
        BOOST_CHECK(w1.Verify(hashMsg, sigW));
        // swap back and keep going
        w1.swap(w2);
        BOOST_CHECK(w1.GetPubKey() == pw1);
    }

    // --- Lifetime: ECIES decrypt through copes well after their sources die ---
    // Owners live in inner scopes so ONLY refcounting keeps the PKEY alive
    // once they return; decrypting must still succeed.
    vector<unsigned char> plaintext(64, 0xee);
    vector<unsigned char> ciphertext;
    {
        CKey owner;
        owner.MakeNewKey(true);
        owner.GetPubKey().EncryptData(plaintext, ciphertext);
        BOOST_REQUIRE(!ciphertext.empty());

        {
            // Share the live key through a const-ref (like hk.GetCKey()).
            const CKey& borrowed = owner;
            CKey k1(borrowed);            // copy ctor
            CKey k2;
            k2 = borrowed;                // copy assign
            CKey k3(std::move(k2));       // move ctor
            CKey k4;
            k4 = std::move(k3);           // move assign

            vector<unsigned char> out1, out4;
            BOOST_CHECK_NO_THROW(k1.DecryptData(ciphertext, out1));
            BOOST_CHECK(out1 == plaintext);
            BOOST_CHECK_NO_THROW(k4.DecryptData(ciphertext, out4));
            BOOST_CHECK(out4 == plaintext);
        }                                 // k1..k4 die, owner still alive
    }                                     // owner dies last

    // --- Exact decryptmessage pattern: by-value provider + copy assignment ---
    {
        struct EciesProvider {
            EciesProvider() { k.MakeNewKey(true); }
            CKey GetCKey() const { return k; } // returns by value, like CHybridKey
            CKey k;
        };

        vector<unsigned char> cipher;
        CKey key;
        {
            EciesProvider provider;
            // Encrypt to THIS provider's key, then hand that key out through
            // the regression statement and let the provider (and the by-value
            // temporary) die; only refcounting keeps the PKEY alive now.
            provider.k.GetPubKey().EncryptData(plaintext, cipher);
            BOOST_REQUIRE(!cipher.empty());
            key = provider.GetCKey();      // the regression statement
        }                                  // provider dies; key survives

        vector<unsigned char> out;
        BOOST_CHECK_NO_THROW(key.DecryptData(cipher, out));
        BOOST_CHECK(out == plaintext);
    }                                      // key dies last
}

namespace {

// Forced (non-elided) CKey copy through a by-value helper parameter, so the
// key-store hand-out is a genuine copy/move, never an elided construction.
CKey legacyDispatchKey(CKey k) { return k; }

// CKeyStore whose GetKey() rebuilds the stored secret into a fresh CKey and
// then churns that key through a chosen copy/move pathway before Sign1()
// ends up signing with it. This mirrors the real daemon signing path, where
// the signer's CKey is produced by copying/moving keys around; under the old
// shallow-copy CKey this churn double-frees the shared EVP_PKEY.
class ChurnKeyStore : public CBasicKeyStore
{
public:
    enum Mode {
        COPY_ASSIGN,     // keyOut = stored;              (daemon-path copy)
        COPY_FORCED,     // two-step copy, no elision
        MOVE_FROM_TEMP,  // move a copy out into keyOut
        MOVE_COPY,       // move, then move-assign out
        BY_VALUE_FORCED  // through the by-value dispatch helper
    };

    Mode mode;

    ChurnKeyStore() : mode(COPY_ASSIGN) {}

    bool GetKey(const CKeyID& address, CKey& keyOut) const
    {
        CKey stored;
        if (!CBasicKeyStore::GetKey(address, stored))
            return false;

        switch (mode) {
        case COPY_ASSIGN:
            keyOut = stored;
            break;
        case COPY_FORCED: {
            CKey tmp(stored);
            keyOut = tmp;
            break;
        }
        case MOVE_FROM_TEMP: {
            CKey tmp(stored);
            keyOut = std::move(tmp);
            break;
        }
        case MOVE_COPY: {
            CKey tmp(stored);
            CKey tmp2(std::move(tmp));
            keyOut = std::move(tmp2);
            break;
        }
        case BY_VALUE_FORCED:
            keyOut = legacyDispatchKey(stored);
            break;
        }
        return true;
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(key_copy_move_legacy_signing)
{
    // Legacy transaction signing fetches the signing key from a CKeyStore
    // through CKey copy/move operations (Sign1 -> keystore.GetKey). The store
    // persists only the secret; each GetKey() rebuilds a fresh CKey (and a
    // fresh EVP_PKEY) and hands it out via a chosen copy/move pathway. A
    // broken CKey lifetime (shallow copies freeing a shared EVP_PKEY twice)
    // double-frees here; correct copy/move/refcount semantics must produce a
    // valid signature that passes VerifySignature, and the signed legacy
    // transaction must round-trip through serialization.

    // The key itself lives (and dies) in an inner scope; the store keeps only
    // the secret, so ownership of the original CKey must not matter later.
    ChurnKeyStore keystore;
    CPubKey pub;
    {
        CKey key;
        key.MakeNewKey(true);
        pub = key.GetPubKey();
        BOOST_CHECK(keystore.AddKey(key));
    } // key destroyed; only its secret remains in the store

    // Funding transaction paying to a P2PKH and a P2PK output of that key.
    CScript scriptP2PKH;
    scriptP2PKH.SetDestination(pub.GetID());
    CScript scriptP2PK;
    scriptP2PK << pub << OP_CHECKSIG;

    CTransaction txFrom;
    txFrom.vout.resize(2);
    txFrom.vout[0].scriptPubKey = scriptP2PKH;
    txFrom.vout[1].scriptPubKey = scriptP2PK;
    BOOST_CHECK(txFrom.IsStandard());

    static const ChurnKeyStore::Mode modes[] = {
        ChurnKeyStore::COPY_ASSIGN,
        ChurnKeyStore::COPY_FORCED,
        ChurnKeyStore::MOVE_FROM_TEMP,
        ChurnKeyStore::MOVE_COPY,
        ChurnKeyStore::BY_VALUE_FORCED,
    };

    for (unsigned int nIn = 0; nIn < 2; ++nIn) {
        for (unsigned int m = 0; m < sizeof(modes) / sizeof(modes[0]); ++m) {
            keystore.mode = modes[m];

            CTransaction txTo;
            txTo.vin.resize(1);
            txTo.vout.resize(1);
            txTo.vin[0].prevout.n = nIn;
            txTo.vin[0].prevout.hash = txFrom.GetHash();
            txTo.vout[0].nValue = 1;
            txTo.vout[0].scriptPubKey.SetDestination(pub.GetID());

            BOOST_CHECK_MESSAGE(
                SignSignature(keystore, txFrom, txTo, 0),
                strprintf("SignSignature mode=%u nIn=%u", m, nIn));
            BOOST_CHECK(txTo.IsStandard());

            // The produced scriptSig must verify against the funding output.
            BOOST_CHECK_MESSAGE(
                VerifySignature(txFrom, txTo, 0, true, 0),
                strprintf("VerifySignature mode=%u nIn=%u", m, nIn));

            // The signed legacy transaction must round-trip through
            // serialization (network format) intact.
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << txTo;
            CTransaction txBack;
            ss >> txBack;
            BOOST_CHECK(txBack == txTo);
        }
    }

    // Sign-again stability: re-signing the same spend after the store has
    // handed the key out many times must keep working (refcounts balanced).
    keystore.mode = ChurnKeyStore::MOVE_COPY;
    for (int rep = 0; rep < 50; ++rep) {
        CTransaction txTo;
        txTo.vin.resize(1);
        txTo.vout.resize(1);
        txTo.vin[0].prevout.n = 0;
        txTo.vin[0].prevout.hash = txFrom.GetHash();
        txTo.vout[0].nValue = 1;
        BOOST_CHECK(SignSignature(keystore, txFrom, txTo, 0));
        BOOST_CHECK(VerifySignature(txFrom, txTo, 0, true, 0));
    }
}

BOOST_AUTO_TEST_SUITE_END()
