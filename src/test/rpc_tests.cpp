#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "base58.h"
#include "key.h"
#include "main.h"
#include "script.h"
#include "wallet.h"
#include "util.h"
#include "rpcmain.h"
#include "hs/wallethybrid.h"

extern CWallet *pwalletMain;

using namespace std;
using namespace json_spirit;

BOOST_AUTO_TEST_SUITE(rpc_tests)

static Array
createArgs(int nRequired, const char* address1=NULL, const char* address2=NULL)
{
    Array result;
    result.push_back(nRequired);
    Array addresses;
    if (address1) addresses.push_back(address1);
    if (address2) addresses.push_back(address2);
    result.push_back(addresses);
    return result;
}

BOOST_AUTO_TEST_CASE(rpc_addmultisig)
{
    rpcfn_type addmultisig = tableRPC["addmultisigaddress"]->actor;

    // old, 65-byte-long:
    const char address1Hex[] = "0434e3e09f49ea168c5bbf53f877ff4206923858aab7c7e1df25bc263978107c95e35065a27ef6f1b27222db0ec97e0e895eaca603d3ee0d4c060ce3d8a00286c8";
    // new, compressed:
    const char address2Hex[] = "0388c2037017c62240b6b72ac1a2a5f94da790596ebd06177c8572752922165cb4";

    Value v;
    CCoinAddress address;
    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(1, address1Hex, address2Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_NO_THROW(v = addmultisig(createArgs(2, address1Hex, address2Hex), false));
    address.SetString(v.get_str());
    BOOST_CHECK(address.IsValid() && address.IsScript());

    BOOST_CHECK_THROW(addmultisig(createArgs(0), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(1), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(2, address1Hex), false), runtime_error);

    BOOST_CHECK_THROW(addmultisig(createArgs(1, ""), false), runtime_error);
    BOOST_CHECK_THROW(addmultisig(createArgs(1, "NotAValidPubkey"), false), runtime_error);

    string short1(address1Hex, address1Hex+sizeof(address1Hex)-2); // last byte missing
    BOOST_CHECK_THROW(addmultisig(createArgs(2, short1.c_str()), false), runtime_error);

string short2(address1Hex+1, address1Hex+sizeof(address1Hex)); // first byte missing
    BOOST_CHECK_THROW(addmultisig(createArgs(1, short2.c_str()), false), runtime_error);
}

// signrawtransaction used to collapse four unrelated failures into a bare
// "complete": false. These pin each reason string, so a caller can tell a
// missing prevout apart from a signature this node simply cannot produce.
// The last case guards the opposite direction: a transaction another party
// already signed completely must still verify rather than be reported broken.

static CKey TestKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key;
}

static string TestPrivKey(const CKey& key)
{
    CCoinSecret secret;
    secret.SetSecret(key.GetPrivKey(), true);
    return secret.ToString();
}

static CScript P2PKScript(const CKey& key)
{
    CPubKey pub = key.GetPubKey();
    CScript script;
    script << pub.Raw() << OP_CHECKSIG;
    return script;
}

static Object PrevOutEntry(const uint256& hash, unsigned int n, const CScript& spk)
{
    Object entry;
    entry.push_back(Pair("txid", hash.GetHex()));
    entry.push_back(Pair("vout", (int64_t)n));
    entry.push_back(Pair("scriptPubKey", HexStr(spk.begin(), spk.end())));
    return entry;
}

static uint256 TestHash(unsigned int seed)
{
    uint256 hash;
    hash.begin()[0] = (unsigned char)seed;
    return hash;
}

// Builds a funding transaction so the prevout hash is well-formed, plus a spend
// of output 0 with the requested number of outputs. Zero outputs is the
// interesting case: SIGHASH_SINGLE then has nothing to commit to.
static void MakeSpend(uint256& fundingHash, CTransaction& spend, unsigned int nOutputs)
{
    CTransaction funding;
    funding.vin.resize(1);
    funding.vin[0].prevout.hash = TestHash(0xaa);
    funding.vin[0].prevout.n = 0;
    funding.vout.resize(1);
    funding.vout[0].nValue = 10 * COIN;
    fundingHash = funding.GetHash();

    spend.nVersion = 1;
    spend.vin.resize(1);
    spend.vin[0].prevout.hash = fundingHash;
    spend.vin[0].prevout.n = 0;
    spend.vout.resize(nOutputs);
    for (unsigned int i = 0; i < nOutputs; i++)
    {
        spend.vout[i].nValue = (10 - i) * COIN;
        spend.vout[i].scriptPubKey = P2PKScript(TestKey());
    }
}

static Value CallSignRawHex(const string& hex, const Array& prevtxs,
                            const Array& keys, const char* sighash)
{
    Array params;
    params.push_back(hex);
    params.push_back(prevtxs.empty() ? Value() : Value(prevtxs));
    // An empty array is array_type, not null_type, so passing [] would make the
    // RPC sign from its own empty keystore instead of pwalletMain.
    params.push_back(keys.empty() ? Value() : Value(keys));
    params.push_back(sighash ? Value(string(sighash)) : Value());
    rpcfn_type signraw = tableRPC["signrawtransaction"]->actor;
    return signraw(params, false);
}

static Value CallSignRaw(const CTransaction& spend, const Array& prevtxs,
                         const Array& keys, const char* sighash)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << spend;
    return CallSignRawHex(HexStr(ssTx.begin(), ssTx.end()), prevtxs, keys, sighash);
}

static CTransaction DecodeHexTx(const string& hex)
{
    vector<unsigned char> raw = ParseHex(hex);
    BOOST_REQUIRE(!raw.empty());
    CDataStream ssData(raw, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    ssData >> tx;
    return tx;
}

// signrawtransaction only reaches a hybrid keystore through pwalletMain, and
// CWallet exposes no AddHybridKey, so inject straight into its public map.
// Keys must be built and their IDs resolved before any move, since GetHybridID()
// throws once the key is moved from.
struct HybridSet
{
    std::vector<CHybridKey*> hks;
    std::vector<CHybridKeyID> ids;
    std::vector<CHybridPubKey> pubs;

    HybridSet(int n)
    {
        for (int i = 0; i < n; ++i) {
            CHybridKey* hk = new CHybridKey;
            GenerateHybridKey(*hk);
            ids.push_back(hk->GetHybridID());
            pubs.push_back(CHybridPubKey(hk->secpPub.Raw(), hk->mldsaSigner->GetPublicKey()));
            hks.push_back(hk);
        }
    }
};

static void AddHybridKeysToWallet(CWallet& wallet, HybridSet& set, int n, int first)
{
    for (int i = first; i < first + n; ++i)
        wallet.mapHybridKeys.emplace(set.ids[i], std::move(*set.hks[i]));
}

static CScript P2SHOf(const CScript& inner)
{
    CScript p2sh;
    p2sh << OP_HASH160 << inner.GetID() << OP_EQUAL;
    return p2sh;
}

// json_spirit's Object is a vector of pairs here, not a map, so members are
// looked up by scanning rather than with find().
static const Value* Member(const Object& obj, const string& name)
{
    for (size_t i = 0; i < obj.size(); i++)
        if (obj[i].name_ == name)
            return &obj[i].value_;
    return NULL;
}

static string ErrorReason(const Value& result, bool& fCompleteOut, bool& fHasErrorsOut)
{
    const Object& res = result.get_obj();
    const Value* complete = Member(res, "complete");
    BOOST_REQUIRE(complete != NULL);
    fCompleteOut = complete->get_bool();

    const Value* errors = Member(res, "errors");
    fHasErrorsOut = errors != NULL;
    if (errors == NULL)
        return string();
    const Array& arr = errors->get_array();
    if (arr.empty())
        return string();
    const Value* reason = Member(arr[0].get_obj(), "error");
    BOOST_REQUIRE(reason != NULL);
    return reason->get_str();
}

BOOST_AUTO_TEST_CASE(rpc_signrawtransaction_missing_prevout)
{
    uint256 fundingHash;
    CTransaction spend;
    MakeSpend(fundingHash, spend, 1);

    // No prevtxs supplied and the funding tx is not in this node's wallet or
    // mempool, so the prevout cannot be resolved at all.
    bool fComplete = true, fHasErrors = false;
    BOOST_CHECK_NO_THROW({
        string reason = ErrorReason(CallSignRaw(spend, Array(), Array(), NULL),
                                    fComplete, fHasErrors);
        BOOST_CHECK(!fComplete);
        BOOST_CHECK(fHasErrors);
        BOOST_CHECK_EQUAL(reason, "Input not found or already spent");
    });
}

BOOST_AUTO_TEST_CASE(rpc_signrawtransaction_no_signing_key)
{
    uint256 fundingHash;
    CTransaction spend;
    MakeSpend(fundingHash, spend, 1);

    // We hold the prevout's script but no key for it: prevout resolves, so the
    // failure is specifically that we cannot sign.
    Array prevtxs;
    prevtxs.push_back(PrevOutEntry(fundingHash, 0, P2PKScript(TestKey())));
    Array keys;
    keys.push_back(TestPrivKey(TestKey()));

    bool fComplete = true, fHasErrors = false;
    string reason = ErrorReason(CallSignRaw(spend, prevtxs, keys, NULL),
                                fComplete, fHasErrors);
    BOOST_CHECK(!fComplete);
    BOOST_CHECK(fHasErrors);
    BOOST_CHECK_EQUAL(reason, "Unable to sign input");
}

BOOST_AUTO_TEST_CASE(rpc_signrawtransaction_partial_multisig)
{
    // Bare multisig discards partial signatures, so the 2-of-3 that still says
    // "we signed something, more is needed" is the P2SH hybrid form the 2OF3
    // rig actually signs.
    HybridSet set(3);
    CScript inner = GetScriptForHybridMultisig(2, set.pubs);
    BOOST_REQUIRE(!inner.empty());
    CScript spk = P2SHOf(inner);

    uint256 fundingHash;
    CTransaction spend;
    MakeSpend(fundingHash, spend, 1);

    // Offer only one of the two required keys. We do produce a partial
    // signature, which must not read the same as having no usable key.
    AddHybridKeysToWallet(*pwalletMain, set, 1, 0);
    BOOST_REQUIRE(pwalletMain->AddCScript(inner));

    Array prevtxs;
    prevtxs.push_back(PrevOutEntry(fundingHash, 0, spk));

    bool fComplete = true, fHasErrors = false;
    string reason = ErrorReason(CallSignRaw(spend, prevtxs, Array(), NULL),
                                fComplete, fHasErrors);
    BOOST_CHECK(!fComplete);
    BOOST_CHECK(fHasErrors);
    BOOST_CHECK_EQUAL(reason, "Unable to sign input, script does not satisfy");
}

BOOST_AUTO_TEST_CASE(rpc_signrawtransaction_sighash_single_without_output)
{
    CKey own = TestKey();

    uint256 fundingHash;
    CTransaction spend;
    MakeSpend(fundingHash, spend, 0);

    // Hold the correct key, so signing would succeed; with SIGHASH_SINGLE and
    // no output at this index we decline on purpose, which is a different
    // condition from failing to sign and needs to read differently.
    Array prevtxs;
    prevtxs.push_back(PrevOutEntry(fundingHash, 0, P2PKScript(own)));
    Array keys;
    keys.push_back(TestPrivKey(own));

    bool fComplete = true, fHasErrors = false;
    string reason = ErrorReason(CallSignRaw(spend, prevtxs, keys, "SINGLE"),
                                fComplete, fHasErrors);
    BOOST_CHECK(!fComplete);
    BOOST_CHECK(fHasErrors);
    BOOST_CHECK_EQUAL(reason,
        "Unable to sign input, no corresponding output for SIGHASH_SINGLE");
}

BOOST_AUTO_TEST_CASE(rpc_signrawtransaction_already_fully_signed)
{
    HybridSet set(3);
    CScript inner = GetScriptForHybridMultisig(2, set.pubs);
    BOOST_REQUIRE(!inner.empty());
    CScript spk = P2SHOf(inner);

    uint256 fundingHash;
    CTransaction spend;
    MakeSpend(fundingHash, spend, 1);

    // Another party signs both required keys before handing us the hex, and we
    // hold none of theirs. Those signatures must survive our merge, so the
    // answer is complete with no errors rather than a bogus failure.
    AddHybridKeysToWallet(*pwalletMain, set, 2, 0);
    BOOST_REQUIRE(pwalletMain->AddCScript(inner));
    SignSignature(*pwalletMain, spk, spend, 0);
    BOOST_REQUIRE(VerifyScript(spend.vin[0].scriptSig, spk, spend, 0, true, 0));

    // Drop them again so the RPC truly holds none of the other party's keys.
    for (int i = 0; i < 2; ++i)
        pwalletMain->mapHybridKeys.erase(set.ids[i]);

    Array prevtxs;
    prevtxs.push_back(PrevOutEntry(fundingHash, 0, spk));

    bool fComplete = false, fHasErrors = false;
    string reason = ErrorReason(CallSignRaw(spend, prevtxs, Array(), NULL),
                                fComplete, fHasErrors);
    BOOST_CHECK(fComplete);
    BOOST_CHECK(!fHasErrors);
    BOOST_CHECK(reason.empty());
}

// The 2OF3 flow this patch exists to explain: a partial signature must survive
// and combine with a second one, and only a node that actually contributed to
// the script may be told "script does not satisfy".
//
// signrawtransaction always signs from pwalletMain, so two separate nodes
// cannot be simulated in one process. Instead the wallet gains the second key
// partway through, which exercises the same merge path: A's partial scriptSig
// has to survive and combine with B's to reach the threshold.
BOOST_AUTO_TEST_CASE(rpc_signrawtransaction_two_of_three_signing_sequence)
{
    HybridSet set(3);
    CScript inner = GetScriptForHybridMultisig(2, set.pubs);
    BOOST_REQUIRE(!inner.empty());
    CScript spk = P2SHOf(inner);

    uint256 fundingHash;
    CTransaction spend;
    MakeSpend(fundingHash, spend, 1);
    Array prevtxs;
    prevtxs.push_back(PrevOutEntry(fundingHash, 0, spk));
    BOOST_REQUIRE(pwalletMain->AddCScript(inner));

    // --- Signer A: wallet holds key 1 only, so it can contribute one of two. ---
    AddHybridKeysToWallet(*pwalletMain, set, 1, 1);
    Value resA = CallSignRaw(spend, prevtxs, Array(), NULL);
    bool fComplete = true, fHasErrors = false;
    string reasonA = ErrorReason(resA, fComplete, fHasErrors);
    BOOST_CHECK(!fComplete);
    BOOST_CHECK(fHasErrors);
    BOOST_CHECK_EQUAL(reasonA, "Unable to sign input, script does not satisfy");

    // A's signature must really be in the returned scriptSig, otherwise the
    // wording would be claiming work that never happened.
    string hexA = Member(resA.get_obj(), "hex")->get_str();
    CTransaction txA = DecodeHexTx(hexA);
    BOOST_REQUIRE(!txA.vin[0].scriptSig.empty());
    BOOST_CHECK(!VerifyScript(txA.vin[0].scriptSig, spk, txA, 0, true, 0));

    // --- Signer B: a second key joins, and A's transaction is re-submitted. ---
    AddHybridKeysToWallet(*pwalletMain, set, 1, 0);
    Value resB = CallSignRawHex(hexA, prevtxs, Array(), NULL);
    string reasonB = ErrorReason(resB, fComplete, fHasErrors);
    BOOST_CHECK(fComplete);
    BOOST_CHECK(!fHasErrors);
    BOOST_CHECK(reasonB.empty());
    CTransaction txB = DecodeHexTx(Member(resB.get_obj(), "hex")->get_str());
    BOOST_CHECK(VerifyScript(txB.vin[0].scriptSig, spk, txB, 0, true, 0));
}

// The same 2-of-3 spend, but this node holds none of the keys. It contributes
// nothing, so it must not be told the script is unsatisfiable.
BOOST_AUTO_TEST_CASE(rpc_signrawtransaction_two_of_three_with_no_key)
{
    HybridSet set(3);
    CScript inner = GetScriptForHybridMultisig(2, set.pubs);
    BOOST_REQUIRE(!inner.empty());
    CScript spk = P2SHOf(inner);

    uint256 fundingHash;
    CTransaction spend;
    MakeSpend(fundingHash, spend, 1);
    Array prevtxs;
    prevtxs.push_back(PrevOutEntry(fundingHash, 0, spk));
    // Register the redeem script so the prevout and script type resolve; only
    // the keys are missing, which is what must be reported.
    BOOST_REQUIRE(pwalletMain->AddCScript(inner));

    bool fComplete = true, fHasErrors = false;
    string reason = ErrorReason(CallSignRaw(spend, prevtxs, Array(), NULL),
                                fComplete, fHasErrors);
    BOOST_CHECK(!fComplete);
    BOOST_CHECK(fHasErrors);
    BOOST_CHECK_EQUAL(reason, "Unable to sign input");
}

BOOST_AUTO_TEST_SUITE_END()
