// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include <map>
#include <utility>
#include <set>

#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>

#include <openssl/evp.h>

#include "sync.h"
#include "bignum.h"
#include "keystore.h"
#include "key.h"
#include "util.h"
#include "main.h"
#include "script.h"
#include "hs/hybrid_script.h"
#include "hs/hybrid_verify.h"
#include "hs/wallethybrid.h"

using namespace std;
using namespace boost;

// ==================== Hybrid Helpers ====================

// Canonical sighash preimage construction
// This is the exact byte sequence that gets hashed for ECDSA verification
// and domain-separated for ML-DSA verification.
// Returns true on success, false on error (invalid nIn or SIGHASH_SINGLE index out of range)
bool ConstructSignatureHashPreimage(
    const CScript& scriptCode,
    const CTransaction& txTo,
    unsigned int nIn,
    int nHashType,
    std::vector<unsigned char>& preimageOut)
{

    if(nIn >= txTo.vin.size())
        return false;  // Error: invalid input index

    CScript scriptCodeTmp = scriptCode;
    CTransaction txTmp(txTo);

    // Remove codeseparators
    scriptCodeTmp.FindAndDelete(CScript(OP_CODESEPARATOR));

    // Blank out other inputs' signatures
    for(unsigned int i = 0; i < txTmp.vin.size(); i++)
        txTmp.vin[i].scriptSig = CScript();
    txTmp.vin[nIn].scriptSig = scriptCodeTmp;

    // Blank out some of the outputs based on sighash type
    if((nHashType & 0x1f) == SIGHASH_NONE) {
        txTmp.vout.clear();
        for(unsigned int i = 0; i < txTmp.vin.size(); i++)
            if(i != nIn)
                txTmp.vin[i].nSequence = 0;
    } else if((nHashType & 0x1f) == SIGHASH_SINGLE) {
        unsigned int nOut = nIn;
        if(nOut >= txTmp.vout.size())
            return false;  // Error: index out of range
        txTmp.vout.resize(nOut+1);
        for(unsigned int i = 0; i < nOut; i++)
            txTmp.vout[i].SetNull();
        for(unsigned int i = 0; i < txTmp.vin.size(); i++)
            if(i != nIn)
                txTmp.vin[i].nSequence = 0;
    }

    // Blank out other inputs completely for SIGHASH_ANYONECANPAY
    if(nHashType & SIGHASH_ANYONECANPAY) {
        txTmp.vin[0] = txTmp.vin[nIn];
        txTmp.vin.resize(1);
    }

    // Serialize the preimage
    CDataStream ss(SER_GETHASH, 0);
    ss.reserve(10000);
    ss << txTmp << nHashType;
    preimageOut.assign(ss.begin(), ss.end());
    return true;
}

// -------------------- Hybrid-compatible CheckSig --------------------
bool CheckSig(const std::vector<unsigned char>& vchSig,
              const std::vector<unsigned char>& vchPubKey,
              const CScript& scriptCode,
              const CTransaction& txTo,
              unsigned int nIn,
              int nHashType,
              const uint256* precomputedSighash);

typedef vector<uchar> valtype;
static const valtype vchFalse(0);
static const valtype vchZero(0);
static const valtype vchTrue(1, 1);
static const CBigNum bnZero(0);
static const CBigNum bnOne(1);
static const CBigNum bnFalse(0);
static const CBigNum bnTrue(1);
static const size_t nMaxNumSize = 4;

CBigNum CastToBigNum(const valtype& vch) {
    if(vch.size() > nMaxNumSize)
        throw runtime_error("CastToBigNum() : overflow");
    // Get rid of extra leading zeros
    return CBigNum(CBigNum(vch).getvch());
}

bool CastToBool(const valtype& vch) {
    for(unsigned int i = 0; i < vch.size(); i++) {
        if(vch[i] != 0) {
            // Can be negative zero
            if(i == vch.size()-1 && vch[i] == 0x80)
                return(false);
            return(true);
        }
    }
    return(false);
}

//
// Script is a stack machine (like Forth) that evaluates a predicate
// returning a bool indicating valid or not.  There are no loops.
//
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))
static inline void popstack(vector<valtype>& stack)
{
    stack.pop_back();
}

const char* GetTxnOutputType(txnouttype t) {
    switch(t) {
    case TX_NONSTANDARD:
        return "nonstandard";
    case TX_PUBKEY:
        return "pubkey";
    case TX_PUBKEYHASH:
        return "pubkeyhash";
    case TX_SCRIPTHASH:
        return "scripthash";
    case TX_MULTISIG:
        return "multisig";
    case TX_HYBRID_PUBKEY:
        return "hybrid_pubkey";
    case TX_HYBRID_PUBKEYHASH:
        return "hybrid_pubkeyhash";
    case TX_HYBRID_MULTISIG:
        return "hybrid_multisig";
    }
    return NULL;
}

const char* GetOpName(opcodetype opcode) {
    switch(opcode) {
    // push value
    case OP_0                      :
        return "0";
    case OP_PUSHDATA1              :
        return "OP_PUSHDATA1";
    case OP_PUSHDATA2              :
        return "OP_PUSHDATA2";
    case OP_PUSHDATA4              :
        return "OP_PUSHDATA4";
    case OP_1NEGATE                :
        return "-1";
    case OP_RESERVED               :
        return "OP_RESERVED";
    case OP_1                      :
        return "1";
    case OP_2                      :
        return "2";
    case OP_3                      :
        return "3";
    case OP_4                      :
        return "4";
    case OP_5                      :
        return "5";
    case OP_6                      :
        return "6";
    case OP_7                      :
        return "7";
    case OP_8                      :
        return "8";
    case OP_9                      :
        return "9";
    case OP_10                     :
        return "10";
    case OP_11                     :
        return "11";
    case OP_12                     :
        return "12";
    case OP_13                     :
        return "13";
    case OP_14                     :
        return "14";
    case OP_15                     :
        return "15";
    case OP_16                     :
        return "16";
    // control
    case OP_NOP                    :
        return "OP_NOP";
    case OP_VER                    :
        return "OP_VER";
    case OP_IF                     :
        return "OP_IF";
    case OP_NOTIF                  :
        return "OP_NOTIF";
    case OP_VERIF                  :
        return "OP_VERIF";
    case OP_VERNOTIF               :
        return "OP_VERNOTIF";
    case OP_ELSE                   :
        return "OP_ELSE";
    case OP_ENDIF                  :
        return "OP_ENDIF";
    case OP_VERIFY                 :
        return "OP_VERIFY";
    case OP_RETURN                 :
        return "OP_RETURN";
    // stack ops
    case OP_TOALTSTACK             :
        return "OP_TOALTSTACK";
    case OP_FROMALTSTACK           :
        return "OP_FROMALTSTACK";
    case OP_2DROP                  :
        return "OP_2DROP";
    case OP_2DUP                   :
        return "OP_2DUP";
    case OP_3DUP                   :
        return "OP_3DUP";
    case OP_2OVER                  :
        return "OP_2OVER";
    case OP_2ROT                   :
        return "OP_2ROT";
    case OP_2SWAP                  :
        return "OP_2SWAP";
    case OP_IFDUP                  :
        return "OP_IFDUP";
    case OP_DEPTH                  :
        return "OP_DEPTH";
    case OP_DROP                   :
        return "OP_DROP";
    case OP_DUP                    :
        return "OP_DUP";
    case OP_NIP                    :
        return "OP_NIP";
    case OP_OVER                   :
        return "OP_OVER";
    case OP_PICK                   :
        return "OP_PICK";
    case OP_ROLL                   :
        return "OP_ROLL";
    case OP_ROT                    :
        return "OP_ROT";
    case OP_SWAP                   :
        return "OP_SWAP";
    case OP_TUCK                   :
        return "OP_TUCK";
    // splice ops
    case OP_CAT                    :
        return "OP_CAT";
    case OP_SUBSTR                 :
        return "OP_SUBSTR";
    case OP_LEFT                   :
        return "OP_LEFT";
    case OP_RIGHT                  :
        return "OP_RIGHT";
    case OP_SIZE                   :
        return "OP_SIZE";
    // bit logic
    case OP_INVERT                 :
        return "OP_INVERT";
    case OP_AND                    :
        return "OP_AND";
    case OP_OR                     :
        return "OP_OR";
    case OP_XOR                    :
        return "OP_XOR";
    case OP_EQUAL                  :
        return "OP_EQUAL";
    case OP_EQUALVERIFY            :
        return "OP_EQUALVERIFY";
    case OP_RESERVED1              :
        return "OP_RESERVED1";
    case OP_RESERVED2              :
        return "OP_RESERVED2";
    // numeric
    case OP_1ADD                   :
        return "OP_1ADD";
    case OP_1SUB                   :
        return "OP_1SUB";
    case OP_2MUL                   :
        return "OP_2MUL";
    case OP_2DIV                   :
        return "OP_2DIV";
    case OP_NEGATE                 :
        return "OP_NEGATE";
    case OP_ABS                    :
        return "OP_ABS";
    case OP_NOT                    :
        return "OP_NOT";
    case OP_0NOTEQUAL              :
        return "OP_0NOTEQUAL";
    case OP_ADD                    :
        return "OP_ADD";
    case OP_SUB                    :
        return "OP_SUB";
    case OP_MUL                    :
        return "OP_MUL";
    case OP_DIV                    :
        return "OP_DIV";
    case OP_MOD                    :
        return "OP_MOD";
    case OP_LSHIFT                 :
        return "OP_LSHIFT";
    case OP_RSHIFT                 :
        return "OP_RSHIFT";
    case OP_BOOLAND                :
        return "OP_BOOLAND";
    case OP_BOOLOR                 :
        return "OP_BOOLOR";
    case OP_NUMEQUAL               :
        return "OP_NUMEQUAL";
    case OP_NUMEQUALVERIFY         :
        return "OP_NUMEQUALVERIFY";
    case OP_NUMNOTEQUAL            :
        return "OP_NUMNOTEQUAL";
    case OP_LESSTHAN               :
        return "OP_LESSTHAN";
    case OP_GREATERTHAN            :
        return "OP_GREATERTHAN";
    case OP_LESSTHANOREQUAL        :
        return "OP_LESSTHANOREQUAL";
    case OP_GREATERTHANOREQUAL     :
        return "OP_GREATERTHANOREQUAL";
    case OP_MIN                    :
        return "OP_MIN";
    case OP_MAX                    :
        return "OP_MAX";
    case OP_WITHIN                 :
        return "OP_WITHIN";
    // crypto
    case OP_RIPEMD160              :
        return "OP_RIPEMD160";
    case OP_SHA1                   :
        return "OP_SHA1";
    case OP_SHA256                 :
        return "OP_SHA256";
    case OP_HASH160                :
        return "OP_HASH160";
    case OP_HASH256                :
        return "OP_HASH256";
    case OP_CODESEPARATOR          :
        return "OP_CODESEPARATOR";
    case OP_CHECKSIG               :
        return "OP_CHECKSIG";
    case OP_CHECKSIGVERIFY         :
        return "OP_CHECKSIGVERIFY";
    case OP_CHECKMULTISIG          :
        return "OP_CHECKMULTISIG";
    case OP_CHECKMULTISIGVERIFY    :
        return "OP_CHECKMULTISIGVERIFY";
    // Hybrid signature operations (Post-Quantum)
    case OP_CHECKHYBRIDSIG         :
        return "OP_CHECKHYBRIDSIG";
    case OP_CHECKHYBRIDSIGVERIFY   :
        return "OP_CHECKHYBRIDSIGVERIFY";
    case OP_CHECKMULTIHYBRIDSIG    :
        return "OP_CHECKMULTIHYBRIDSIG";
    case OP_HASHHYBRID160:
        return "OP_HASHHYBRID160";
    case OP_DUPHYBRID:
        return "OP_DUPHYBRID";
    // expanson
    case OP_NOP1                   :
        return "OP_NOP1";
    case OP_NOP2                   :
        return "OP_NOP2";
    case OP_NOP3                   :
        return "OP_NOP3";
    case OP_NOP4                   :
        return "OP_NOP4";
    case OP_NOP5                   :
        return "OP_NOP5";
    case OP_NOP6                   :
        return "OP_NOP6";
    case OP_NOP7                   :
        return "OP_NOP7";
    case OP_NOP8                   :
        return "OP_NOP8";
    case OP_NOP9                   :
        return "OP_NOP9";
    case OP_NOP10                  :
        return "OP_NOP10";
    // template matching params
    case OP_PUBKEYHASH             :
        return "OP_PUBKEYHASH";
    case OP_PUBKEY                 :
        return "OP_PUBKEY";
    case OP_INVALIDOPCODE          :
        return "OP_INVALIDOPCODE";
    default:
        return "OP_UNKNOWN";
    }
}

bool EvalScript(vector<vector<unsigned char> >& stack, const CScript& script, const CTransaction& txTo, unsigned int nIn, int nHashType) {
    CAutoBN_CTX pctx;
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    vector<bool> vfExec;
    vector<valtype> altstack;
    if(script.size() > MAX_SCRIPT_SIZE)
        return(false);
    int nOpCount = 0;
    try {
        while(pc < pend) {
            bool fExec = !count(vfExec.begin(), vfExec.end(), false);
            //
            // Read instruction
            //
            if(!script.GetOp(pc, opcode, vchPushValue))
                return(false);
            if(vchPushValue.size() > MAX_SCRIPT_ELEMENT_SIZE)
                return(false);
            if(opcode > OP_16 && ++nOpCount > 201)
                return(false);
            if(opcode == OP_CAT ||
                    opcode == OP_SUBSTR ||
                    opcode == OP_LEFT ||
                    opcode == OP_RIGHT ||
                    opcode == OP_INVERT ||
                    opcode == OP_AND ||
                    opcode == OP_OR ||
                    opcode == OP_XOR ||
                    opcode == OP_2MUL ||
                    opcode == OP_2DIV ||
                    opcode == OP_MUL ||
                    opcode == OP_DIV ||
                    opcode == OP_MOD ||
                    opcode == OP_LSHIFT ||
                    opcode == OP_RSHIFT)
                return(false);
            if(fExec && 0 <= opcode && opcode <= OP_PUSHDATA4)
                stack.push_back(vchPushValue);
            else if(fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
                switch(opcode) {
                //
                // Push value
                //
                case OP_1NEGATE:
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16: {
                    // ( -- value)
                    CBigNum bn((int)opcode - (int)(OP_1 - 1));
                    stack.push_back(bn.getvch());
                }
                break;
                //
                // Control
                //
                case OP_NOP:
                case OP_NOP1:
                case OP_NOP2:
                case OP_NOP3:
                case OP_NOP4:
                case OP_NOP5:
                case OP_NOP6:
                case OP_NOP7:
                case OP_NOP8:
                case OP_NOP9:
                case OP_NOP10:
                    break;
                case OP_IF:
                case OP_NOTIF: {
                    // <expression> if [statements] [else [statements]] endif
                    bool fValue = false;
                    if(fExec) {
                        if(stack.size() < 1)
                            return(false);
                        valtype& vch = stacktop(-1);
                        fValue = CastToBool(vch);
                        if(opcode == OP_NOTIF)
                            fValue = !fValue;
                        popstack(stack);
                    }
                    vfExec.push_back(fValue);
                }
                break;
                case OP_ELSE: {
                    if(vfExec.empty())
                        return(false);
                    vfExec.back() = !vfExec.back();
                }
                break;
                case OP_ENDIF: {
                    if(vfExec.empty())
                        return(false);
                    vfExec.pop_back();
                }
                break;
                case OP_VERIFY: {
                    // (true -- ) or
                    // (false -- false) and return
                    if(stack.size() < 1)
                        return(false);
                    bool fValue = CastToBool(stacktop(-1));
                    if(fValue)
                        popstack(stack);
                    else
                        return(false);
                }
                break;
                case OP_RETURN: {
                    return(false);
                }
                break;
                //
                // Stack ops
                //
                case OP_TOALTSTACK: {
                    if(stack.size() < 1)
                        return(false);
                    altstack.push_back(stacktop(-1));
                    popstack(stack);
                }
                break;
                case OP_FROMALTSTACK: {
                    if(altstack.size() < 1)
                        return(false);
                    stack.push_back(altstacktop(-1));
                    popstack(altstack);
                }
                break;
                case OP_2DROP: {
                    // (x1 x2 -- )
                    if(stack.size() < 2)
                        return(false);
                    popstack(stack);
                    popstack(stack);
                }
                break;
                case OP_2DUP: {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if(stack.size() < 2)
                        return(false);
                    valtype vch1 = stacktop(-2);
                    valtype vch2 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;
                case OP_3DUP: {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if(stack.size() < 3)
                        return(false);
                    valtype vch1 = stacktop(-3);
                    valtype vch2 = stacktop(-2);
                    valtype vch3 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                    stack.push_back(vch3);
                }
                break;
                case OP_2OVER: {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if(stack.size() < 4)
                        return(false);
                    valtype vch1 = stacktop(-4);
                    valtype vch2 = stacktop(-3);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;
                case OP_2ROT: {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if(stack.size() < 6)
                        return(false);
                    valtype vch1 = stacktop(-6);
                    valtype vch2 = stacktop(-5);
                    stack.erase(stack.end()-6, stack.end()-4);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;
                case OP_2SWAP: {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if(stack.size() < 4)
                        return(false);
                    swap(stacktop(-4), stacktop(-2));
                    swap(stacktop(-3), stacktop(-1));
                }
                break;
                case OP_IFDUP: {
                    // (x - 0 | x x)
                    if(stack.size() < 1)
                        return(false);
                    valtype vch = stacktop(-1);
                    if(CastToBool(vch))
                        stack.push_back(vch);
                }
                break;
                case OP_DEPTH: {
                    // -- stacksize
                    CBigNum bn((int64)stack.size());
                    stack.push_back(bn.getvch());
                }
                break;
                case OP_DROP: {
                    // (x -- )
                    if(stack.size() < 1)
                        return(false);
                    popstack(stack);
                }
                break;
                case OP_DUPHYBRID:
                {
                    if (stack.size() < 4)
                        return false;

                    valtype pubEC = stacktop(-2);
                    valtype pubML = stacktop(-1);

                    stack.push_back(pubEC);
                    stack.push_back(pubML);
                }
                break;
                case OP_DUP: {
                    // (x -- x x)
                    if(stack.size() < 1)
                        return(false);
                    valtype vch = stacktop(-1);
                    stack.push_back(vch);
                }
                break;
                case OP_NIP: {
                    // (x1 x2 -- x2)
                    if(stack.size() < 2)
                        return(false);
                    stack.erase(stack.end() - 2);
                }
                break;
                case OP_OVER: {
                    // (x1 x2 -- x1 x2 x1)
                    if(stack.size() < 2)
                        return(false);
                    valtype vch = stacktop(-2);
                    stack.push_back(vch);
                }
                break;
                case OP_PICK:
                case OP_ROLL: {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if(stack.size() < 2)
                        return(false);
                    int n = CastToBigNum(stacktop(-1)).getint();
                    popstack(stack);
                    if(n < 0 || n >= (int)stack.size())
                        return(false);
                    valtype vch = stacktop(-n-1);
                    if(opcode == OP_ROLL)
                        stack.erase(stack.end()-n-1);
                    stack.push_back(vch);
                }
                break;
                case OP_ROT: {
                    // (x1 x2 x3 -- x2 x3 x1)
                    //  x2 x1 x3  after first swap
                    //  x2 x3 x1  after second swap
                    if(stack.size() < 3)
                        return(false);
                    swap(stacktop(-3), stacktop(-2));
                    swap(stacktop(-2), stacktop(-1));
                }
                break;
                case OP_SWAP: {
                    // (x1 x2 -- x2 x1)
                    if(stack.size() < 2)
                        return(false);
                    swap(stacktop(-2), stacktop(-1));
                }
                break;
                case OP_TUCK: {
                    // (x1 x2 -- x2 x1 x2)
                    if(stack.size() < 2)
                        return(false);
                    valtype vch = stacktop(-1);
                    stack.insert(stack.end()-2, vch);
                }
                break;
                //
                // Splice ops
                //
                case OP_SIZE: {
                    // (in -- in size)
                    if(stack.size() < 1)
                        return(false);
                    CBigNum bn((int64)stacktop(-1).size());
                    stack.push_back(bn.getvch());
                }
                break;
                //
                // Bitwise logic
                //
                case OP_EQUAL:
                case OP_EQUALVERIFY:
                    //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                {
                    // (x1 x2 - bool)
                    if(stack.size() < 2)
                        return(false);
                    valtype& vch1 = stacktop(-2);
                    valtype& vch2 = stacktop(-1);
                    bool fEqual = (vch1 == vch2);
                    // OP_NOTEQUAL is disabled because it would be too easy to say
                    // something like n != 1 and have some wiseguy pass in 1 with extra
                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                    //if (opcode == OP_NOTEQUAL)
                    //    fEqual = !fEqual;
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fEqual ? vchTrue : vchFalse);
                    if(opcode == OP_EQUALVERIFY) {
                        if(fEqual)
                            popstack(stack);
                        else
                            return(false);
                    }
                }
                break;
                //
                // Numeric
                //
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL: {
                    // (in -- out)
                    if(stack.size() < 1)
                        return(false);
                    CBigNum bn = CastToBigNum(stacktop(-1));
                    switch(opcode) {
                    case OP_1ADD:
                        bn += bnOne;
                        break;
                    case OP_1SUB:
                        bn -= bnOne;
                        break;
                    case OP_NEGATE:
                        bn = -bn;
                        break;
                    case OP_ABS:
                        if(bn < bnZero) bn = -bn;
                        break;
                    case OP_NOT:
                        bn = (bn == bnZero);
                        break;
                    case OP_0NOTEQUAL:
                        bn = (bn != bnZero);
                        break;
                    default:
                        assert(!"invalid opcode");
                        break;
                    }
                    popstack(stack);
                    stack.push_back(bn.getvch());
                }
                break;
                case OP_ADD:
                case OP_SUB:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX: {
                    // (x1 x2 -- out)
                    if(stack.size() < 2)
                        return(false);
                    CBigNum bn1 = CastToBigNum(stacktop(-2));
                    CBigNum bn2 = CastToBigNum(stacktop(-1));
                    CBigNum bn;
                    switch(opcode) {
                    case OP_ADD:
                        bn = bn1 + bn2;
                        break;
                    case OP_SUB:
                        bn = bn1 - bn2;
                        break;
                    case OP_BOOLAND:
                        bn = (bn1 != bnZero && bn2 != bnZero);
                        break;
                    case OP_BOOLOR:
                        bn = (bn1 != bnZero || bn2 != bnZero);
                        break;
                    case OP_NUMEQUAL:
                        bn = (bn1 == bn2);
                        break;
                    case OP_NUMEQUALVERIFY:
                        bn = (bn1 == bn2);
                        break;
                    case OP_NUMNOTEQUAL:
                        bn = (bn1 != bn2);
                        break;
                    case OP_LESSTHAN:
                        bn = (bn1 < bn2);
                        break;
                    case OP_GREATERTHAN:
                        bn = (bn1 > bn2);
                        break;
                    case OP_LESSTHANOREQUAL:
                        bn = (bn1 <= bn2);
                        break;
                    case OP_GREATERTHANOREQUAL:
                        bn = (bn1 >= bn2);
                        break;
                    case OP_MIN:
                        bn = (bn1 < bn2 ? bn1 : bn2);
                        break;
                    case OP_MAX:
                        bn = (bn1 > bn2 ? bn1 : bn2);
                        break;
                    default:
                        assert(!"invalid opcode");
                        break;
                    }
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(bn.getvch());
                    if(opcode == OP_NUMEQUALVERIFY) {
                        if(CastToBool(stacktop(-1)))
                            popstack(stack);
                        else
                            return(false);
                    }
                }
                break;
                case OP_WITHIN: {
                    // (x min max -- out)
                    if(stack.size() < 3)
                        return(false);
                    CBigNum bn1 = CastToBigNum(stacktop(-3));
                    CBigNum bn2 = CastToBigNum(stacktop(-2));
                    CBigNum bn3 = CastToBigNum(stacktop(-1));
                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fValue ? vchTrue : vchFalse);
                }
                break;
                case OP_HASHHYBRID160:
                {
                    //
                    // Stack:
                    //
                    // ...
                    // sigEC
                    // sigML
                    // pubEC
                    // pubML
                    //
                    // ->
                    //
                    // ...
                    // sigEC
                    // sigML
                    // Hash160(pubEC || pubML)
                    //

                    if (stack.size() < 4)
                        return false;

                    valtype& vchPubML = stacktop(-1);
                    valtype& vchPubEC = stacktop(-2);

                    std::vector<unsigned char> blob;
                    blob.reserve(vchPubEC.size() + vchPubML.size());

                    blob.insert(blob.end(), vchPubEC.begin(), vchPubEC.end());
                    blob.insert(blob.end(), vchPubML.begin(), vchPubML.end());

                    uint160 hash = Hash160(blob);

                    popstack(stack); // Remove ML-DSA public key
                    popstack(stack); // Remove ECDSA public key

                    stack.push_back(std::vector<unsigned char>(hash.begin(), hash.end()));
                }
                break;
                //
                // Crypto
                //
                case OP_RIPEMD160:
                case OP_SHA1:
                case OP_SHA256:
                case OP_HASH160:
                case OP_HASH256: {
                    // (in -- hash)
                    if(stack.size() < 1)
                        return(false);
                    valtype& vch = stacktop(-1);
                    valtype vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                    if(opcode == OP_RIPEMD160) {
                        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                        if(!ctx)
                            return false;
                        const EVP_MD* md = EVP_ripemd160();

                        if(1 != EVP_DigestInit_ex(ctx, md, NULL)) {
                            EVP_MD_CTX_free(ctx);
                            return false;
                        }
                        if(1 != EVP_DigestUpdate(ctx, &vch[0], vch.size())) {
                            EVP_MD_CTX_free(ctx);
                            return false;
                        }
                        unsigned int hash_len = 0;
                       if(1 != EVP_DigestFinal_ex(ctx, &vchHash[0], &hash_len)) {
                           EVP_MD_CTX_free(ctx);
                           return false;
                       }
                       EVP_MD_CTX_free(ctx);
                    }
                    else if(opcode == OP_SHA1)
                        SHA1(&vch[0], vch.size(), &vchHash[0]);
                    else if(opcode == OP_SHA256)
                        SHA256(&vch[0], vch.size(), &vchHash[0]);
                    else if(opcode == OP_HASH160) {
                        uint160 hash160 = Hash160(vch);
                        memcpy(&vchHash[0], &hash160, sizeof(hash160));
                    } else if(opcode == OP_HASH256) {
                        uint256 hash = Hash(vch.begin(), vch.end());
                        memcpy(&vchHash[0], &hash, sizeof(hash));
                    }
                    popstack(stack);
                    stack.push_back(vchHash);
                }
                break;
                case OP_CODESEPARATOR: {
                    // Hash starts after the code separator
                    pbegincodehash = pc;
                }
                break;
                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY: {
                    // (sig pubkey -- bool)
                    if(stack.size() < 2)
                        return(false);
                    valtype& vchSig    = stacktop(-2);
                    valtype& vchPubKey = stacktop(-1);
                    ////// debug print
                    //PrintHex(vchSig.begin(), vchSig.end(), "sig: %s\n");
                    //PrintHex(vchPubKey.begin(), vchPubKey.end(), "pubkey: %s\n");
                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);
                    // Drop the signature, since there's no way for a signature to sign itself
                    scriptCode.FindAndDelete(CScript(vchSig));
                    bool fSuccess = CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                    if(opcode == OP_CHECKSIGVERIFY) {
                        if(fSuccess)
                            popstack(stack);
                        else
                            return(false);
                    }
                }
                break;
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY: {
                    // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
                    int i = 1;
                    if((int)stack.size() < i)
                        return(false);
                    int nKeysCount = CastToBigNum(stacktop(-i)).getint();
                    if(nKeysCount < 0 || nKeysCount > 20)
                        return(false);
                    nOpCount += nKeysCount;
                    if(nOpCount > 201)
                        return(false);
                    int ikey = ++i;
                    i += nKeysCount;
                    if((int)stack.size() < i)
                        return(false);
                    int nSigsCount = CastToBigNum(stacktop(-i)).getint();
                    if(nSigsCount < 0 || nSigsCount > nKeysCount)
                        return(false);
                    int isig = ++i;
                    i += nSigsCount;
                    if((int)stack.size() < i)
                        return(false);
                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);
                    // Drop the signatures, since there's no way for a signature to sign itself
                    for(int k = 0; k < nSigsCount; k++) {
                        valtype& vchSig = stacktop(-isig-k);
                        scriptCode.FindAndDelete(CScript(vchSig));
                    }
                    bool fSuccess = true;
                    while(fSuccess && nSigsCount > 0) {
                        valtype& vchSig    = stacktop(-isig);
                        valtype& vchPubKey = stacktop(-ikey);
                        // Check signature
                        if(CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType)) {
                            isig++;
                            nSigsCount--;
                        }
                        ikey++;
                        nKeysCount--;
                        // If there are more signatures left than keys left,
                        // then too many signatures have failed
                        if(nSigsCount > nKeysCount)
                            fSuccess = false;
                    }
                    while(i-- > 0)
                        popstack(stack);
                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                    if(opcode == OP_CHECKMULTISIGVERIFY) {
                        if(fSuccess)
                            popstack(stack);
                        else
                            return(false);
                    }
                }
                break;
                case OP_CHECKHYBRIDSIG:
                case OP_CHECKHYBRIDSIGVERIFY: {

                    if(stack.size() < 4) {
                        return(false);
                    }

                    valtype& vchPubKeyML = stacktop(-1);
                    valtype& vchPubKeyEC = stacktop(-2);
                    valtype& vchSigML    = stacktop(-3);
                    valtype& vchSigEC    = stacktop(-4);

                    CScript scriptCode(pbegincodehash, pend);
                    scriptCode.FindAndDelete(CScript(vchSigEC));
                    scriptCode.FindAndDelete(CScript(vchSigML));

                    // Use the new hybrid verification implementation
                    bool fSuccess = VerifyHybridSignature(
                        vchSigEC,
                        vchSigML,
                        vchPubKeyEC,
                        vchPubKeyML,
                        scriptCode,
                        txTo,
                        nIn,
                        nHashType
                    );

                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);

                    stack.push_back(fSuccess ? vchTrue : vchFalse);

                    if(opcode == OP_CHECKHYBRIDSIGVERIFY) {
                        if(fSuccess)
                            popstack(stack);
                        else
                            return(false);
                    }
                }
                break;

                case OP_CHECKMULTIHYBRIDSIG: {
                    // Stack layout:
                    // [sigEC1 sigML1 ... sigECm sigMLm] m
                    // [pubEC1 pubML1 ... pubECn pubMLn] n

                    int i = 1;
                    if ((int)stack.size() < i)
                        return(false);

                    // --- n (pubkeys) ---
                    int nKeysCount = CastToBigNum(stacktop(-i)).getint();
                    if (nKeysCount < 0 || nKeysCount > 20)
                        return(false);

                    nOpCount += nKeysCount;
                    if (nOpCount > 201)
                        return(false);

                    int ikey = ++i;
                    i += nKeysCount * 2;

                    if ((int)stack.size() < i)
                        return(false);

                    // --- m (signatures) ---
                    int nSigsCount = CastToBigNum(stacktop(-i)).getint();
                    if (nSigsCount < 0 || nSigsCount > nKeysCount)
                        return(false);

                    int isig = i + 1;
                    i += nSigsCount * 2;

                    if ((int)stack.size() < i)
                        return(false);

                    // --- Build scriptCode ---
                    CScript scriptCode(pbegincodehash, pend);

                    for (int k = 0; k < nSigsCount; k++) {
                        valtype& vchSigEC =
                            stacktop(-isig - (k * 2) - 1);
                        valtype& vchSigML =
                            stacktop(-isig - (k * 2));

                        if (vchSigEC.empty() || vchSigML.empty())
                            return(false);

                        scriptCode.FindAndDelete(CScript(vchSigEC));
                        scriptCode.FindAndDelete(CScript(vchSigML));
                    }

                    /*
                     * Every hybrid signature pair must use the same
                     * transaction sighash type.
                     *
                     * The sighash type is carried by the final byte of
                     * both the ECDSA and ML-DSA signatures.
                     *
                     * Do NOT calculate the sighash using nHashType here
                     * when nHashType == 0.  In that case the signature
                     * itself supplies the sighash type.
                     */
                    int sigHashType = 0;

                    if (nSigsCount > 0) {
                        valtype& firstSigEC =
                            stacktop(-isig - 1);
                        valtype& firstSigML =
                            stacktop(-isig);

                        sigHashType = firstSigEC.back();

                        if ((int)firstSigML.back() != sigHashType)
                            return(false);

                        if (nHashType != 0 &&
                            sigHashType != nHashType)
                            return(false);

                        for (int k = 1; k < nSigsCount; k++) {
                            valtype& vchSigEC =
                                stacktop(-isig - (k * 2) - 1);
                            valtype& vchSigML =
                                stacktop(-isig - (k * 2));

                            if ((int)vchSigEC.back() != sigHashType ||
                                (int)vchSigML.back() != sigHashType)
                                return(false);
                        }
                    } else {
                        /*
                         * A 0-of-N multisig does not have a signature from
                         * which to derive a sighash type.  There is nothing
                         * to verify, so preserve the normal multisig
                         * semantics.
                         */
                        while (i-- > 0)
                            popstack(stack);

                        stack.push_back(vchTrue);
                        break;
                    }

                    // --- Compute the sighash using the signature's type ---
                    uint256 sighash =
                        SignatureHash(scriptCode, txTo, nIn, sigHashType);

                    // Construct canonical preimage for ML-DSA domain separation
                    std::vector<unsigned char> sighash_preimage;
                    if (!ConstructSignatureHashPreimage(scriptCode, txTo, nIn,
                                                        sigHashType,
                                                        sighash_preimage))
                        return false;

                    std::vector<unsigned char> hybridMsg =
                        BuildHybridMessage(sighash_preimage);

                    // --- Two-pointer matching ---
                    int sigIndex = 0;
                    int keyIndex = 0;

                    bool fSuccess = true;

                    while (sigIndex < nSigsCount &&
                           keyIndex < nKeysCount) {

                        valtype& vchSigEC =
                            stacktop(-isig - (sigIndex * 2) - 1);
                        valtype& vchSigML =
                            stacktop(-isig - (sigIndex * 2));

                        valtype& vchPubKeyEC =
                            stacktop(-ikey - (keyIndex * 2) - 1);
                        valtype& vchPubKeyML =
                            stacktop(-ikey - (keyIndex * 2));

                        /*
                         * Both components must verify against exactly the
                         * same transaction sighash.
                         */
                        bool match =
                            CheckSig(
                                vchSigEC,
                                vchPubKeyEC,
                                scriptCode,
                                txTo,
                                nIn,
                                sigHashType,
                                &sighash
                            ) &&
                            VerifyMLDSA(
                                std::vector<unsigned char>(
                                    vchSigML.begin(),
                                    vchSigML.end() - 1
                                ),
                                vchPubKeyML,
                                hybridMsg
                            );
                        if (match)
                            sigIndex++;

                        keyIndex++;
                    }

                    // All required signatures must have matched.
                    if (sigIndex != nSigsCount)
                        fSuccess = false;

                    // --- Clean stack ---
                    while (i-- > 0)
                        popstack(stack);

                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                }
                break;
                default:
                    return(false);
                }
            // Size limits
            if(stack.size() + altstack.size() > 1000)
                return(false);
        }
    } catch(...) {
        return(false);
    }
    if(!vfExec.empty())
        return(false);
    return(true);
}

uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo,
                      unsigned int nIn, int nHashType) {
    std::vector<unsigned char> preimage;
    if (!ConstructSignatureHashPreimage(scriptCode, txTo, nIn, nHashType,
                                        preimage)) {
        printf("ERROR: SignatureHash() : invalid parameters\n");
        return 1;
    }

    return Hash(preimage.begin(), preimage.end());
}

// Valid signature cache, to avoid doing expensive ECDSA signature checking
// twice for every transaction (once when accepted into memory pool, and
// again when accepted into the block chain)

class CSignatureCache {
  private:
    // sigdata_type is (signature hash, signature, public key):
    typedef boost::tuple<uint256, std::vector<unsigned char>, std::vector<unsigned char> > sigdata_type;
    std::set< sigdata_type> setValid;
    CCriticalSection cs_sigcache;

  public:
    bool
    Get(uint256 hash, const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& pubKey) {
        LOCK(cs_sigcache);
        sigdata_type k(hash, vchSig, pubKey);
        std::set<sigdata_type>::iterator mi = setValid.find(k);
        if(mi != setValid.end())
            return(true);
        return(false);
    }

    void Set(uint256 hash, const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& pubKey) {
        // DoS prevention: limit cache size to less than 10MB
        // (~200 bytes per cache entry times 50,000 entries)
        // Since there are a maximum of 20,000 signature operations per block
        // 50,000 is a reasonable default.
        int64 nMaxCacheSize = GetArg("-maxsigcachesize", 50000);
        if(nMaxCacheSize <= 0) return;
        LOCK(cs_sigcache);
        while(static_cast<int64>(setValid.size()) > nMaxCacheSize) {
            // Evict a random entry. Random because that helps
            // foil would-be DoS attackers who might try to pre-generate
            // and re-use a set of valid signatures just-slightly-greater
            // than our cache size.
            uint256 randomHash = GetRandHash();
            std::vector<unsigned char> unused;
            std::set<sigdata_type>::iterator it =
                setValid.lower_bound(sigdata_type(randomHash, unused, unused));
            if(it == setValid.end())
                it = setValid.begin();
            setValid.erase(*it);
        }
        sigdata_type k(hash, vchSig, pubKey);
        setValid.insert(k);
    }
};

// ==================== Hybrid-Compatible CheckSig ====================

bool CheckSig(const std::vector<unsigned char>& vchSig,
              const std::vector<unsigned char>& vchPubKey,
              const CScript& scriptCode,
              const CTransaction& txTo,
              unsigned int nIn,
              int nHashType,
              const uint256* precomputedSighash)
{
    static CSignatureCache signatureCache;

    if (vchSig.empty()) return false;

    // Signature always ends with the sighash type.
    int sigHashType = nHashType ? nHashType : vchSig.back();

    if (sigHashType != (int)vchSig.back())
        return false;

    // Remove sighash byte.
    std::vector<unsigned char> sig(vchSig.begin(), vchSig.end() - 1);

    // A minimal DER-encoded ECDSA signature is 8 bytes.
    if (sig.size() < 8)
        return false;

    // Compute transaction sighash unless the caller already has it.
    uint256 sighash;
    if (precomputedSighash)
        sighash = *precomputedSighash;
    else
        sighash = SignatureHash(scriptCode, txTo, nIn, sigHashType);

    // Signature cache.
    if (signatureCache.Get(sighash, sig, vchPubKey))
        return true;

    // Load public key.
    CKey key;
    if (!key.SetPubKey(vchPubKey))
        return false;

    // Verify ECDSA signature.
    if (!key.Verify(sighash, sig))
        return false;

    // Cache successful verification.
    signatureCache.Set(sighash, sig, vchPubKey);

    return true;
}

//
// Return public keys or hashes from scriptPubKey, for 'standard' transaction types.
//
bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, vector<vector<unsigned char> >& vSolutionsRet) {
    //
    // Hybrid pay-to-pubkey:
    //
    //   <ecdsa-pubkey>
    //   <mldsa-pubkey>
    //   OP_CHECKHYBRIDSIG
    //
    {
        opcodetype op1, op2, op3;

        std::vector<unsigned char> ecdsaPub;
        std::vector<unsigned char> mldsaPub;

        CScript::const_iterator pc = scriptPubKey.begin();

        if (scriptPubKey.GetOp(pc, op1, ecdsaPub) &&
            scriptPubKey.GetOp(pc, op2, mldsaPub) &&
            scriptPubKey.GetOp(pc, op3) &&
            pc == scriptPubKey.end())
        {
            if (op3 == OP_CHECKHYBRIDSIG &&
                ecdsaPub.size() >= 33 &&
                ecdsaPub.size() <= 120)
            {
                typeRet = TX_HYBRID_PUBKEY;
                vSolutionsRet.clear();
                vSolutionsRet.push_back(ecdsaPub);
                vSolutionsRet.push_back(mldsaPub);

                return true;
            }
        }
    }

    {
        CScript::const_iterator pc = scriptPubKey.begin();

        opcodetype opcode;
        std::vector<unsigned char> hash;

        if (scriptPubKey.GetOp(pc, opcode) &&
            opcode == OP_DUPHYBRID &&
            scriptPubKey.GetOp(pc, opcode) &&
            opcode == OP_HASHHYBRID160 &&
            scriptPubKey.GetOp(pc, opcode, hash) &&
            hash.size() == 20 &&
            scriptPubKey.GetOp(pc, opcode) &&
            opcode == OP_EQUALVERIFY &&
            scriptPubKey.GetOp(pc, opcode) &&
            opcode == OP_CHECKHYBRIDSIG &&
            pc == scriptPubKey.end())
        {
            typeRet = TX_HYBRID_PUBKEYHASH;
            vSolutionsRet.clear();
            vSolutionsRet.push_back(hash);

            return true;
        }
    }

    {
        // Hybrid pay-to-hybrid-multisig:
        //
        //   OP_<m> <pubEC1> <pubML1> ... <pubECN> <pubMLN> OP_<n> OP_CHECKMULTIHYBRIDSIG
        //
        // Each hybrid key is two separate pushes (ECDSA then ML-DSA), matching
        // the OP_CHECKMULTIHYBRIDSIG verifier's stack layout.
        CScript::const_iterator pc = scriptPubKey.begin();
        opcodetype opcode;
        std::vector<unsigned char> vch;

        // m
        if (scriptPubKey.GetOp(pc, opcode) &&
            (opcode == OP_0 || (opcode >= OP_1 && opcode <= OP_16))) {
            int m = CScript::DecodeOP_N(opcode);

            // pubkey pairs: <pubEC> <pubML> ...
            bool fKeys = true;
            std::vector<std::vector<unsigned char> > keys;
            while (fKeys && scriptPubKey.GetOp(pc, opcode, vch)) {
                if (vch.size() >= 33 && vch.size() <= 120) {
                    keys.push_back(vch);
                    if (!scriptPubKey.GetOp(pc, opcode, vch) ||
                        vch.size() != ML_DSA_65_PUBKEY_SIZE) {
                        fKeys = false;
                        break;
                    }
                    keys.push_back(vch);
                } else if (opcode >= OP_1 && opcode <= OP_16) {
                    fKeys = false;   // reached n
                } else {
                    fKeys = false;
                    keys.clear();
                    break;
                }
            }

            int n = 0;
            if (!fKeys && opcode >= OP_1 && opcode <= OP_16)
                n = CScript::DecodeOP_N(opcode);
            if (n >= 1 && keys.size() % 2 == 0 &&
                keys.size() / 2 == (size_t)n &&
                scriptPubKey.GetOp(pc, opcode) &&
                opcode == OP_CHECKMULTIHYBRIDSIG &&
                pc == scriptPubKey.end() &&
                m >= 1 && m <= n) {
                typeRet = TX_HYBRID_MULTISIG;
                vSolutionsRet.clear();
                vSolutionsRet.push_back(valtype(1, (unsigned char)m));
                vSolutionsRet.insert(vSolutionsRet.end(),
                                     keys.begin(), keys.end());
                vSolutionsRet.push_back(valtype(1, (unsigned char)n));
                return true;
            }
        }
    }

    // Templates
    static map<txnouttype, CScript> mTemplates;
    if(mTemplates.empty()) {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplates.insert(make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));
        // Bitcoin address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));
        // Sender provides N pubkeys, receivers provides M signatures
        mTemplates.insert(make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));
    }
    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if(scriptPubKey.IsPayToScriptHash()) {
        typeRet = TX_SCRIPTHASH;
        vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return(true);
    }
    // Scan templates
    const CScript& script1 = scriptPubKey;
    BOOST_FOREACH(const PAIRTYPE(txnouttype, CScript)& tplate, mTemplates) {
        const CScript& script2 = tplate.second;
        vSolutionsRet.clear();
        opcodetype opcode1, opcode2;
        vector<unsigned char> vch1, vch2;
        // Compare
        CScript::const_iterator pc1 = script1.begin();
        CScript::const_iterator pc2 = script2.begin();
        while(true) {
            if(pc1 == script1.end() && pc2 == script2.end()) {
                // Found a match
                typeRet = tplate.first;
                if(typeRet == TX_MULTISIG) {
                    // Additional checks for TX_MULTISIG:
                    unsigned char m = vSolutionsRet.front()[0];
                    unsigned char n = vSolutionsRet.back()[0];
                    if(m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
                        return(false);
                }
                return(true);
            }
            if(!script1.GetOp(pc1, opcode1, vch1))
                break;
            if(!script2.GetOp(pc2, opcode2, vch2))
                break;
            // Template matching opcodes:
            if(opcode2 == OP_PUBKEYS) {
                while(vch1.size() >= 33 && vch1.size() <= 120) {
                    vSolutionsRet.push_back(vch1);
                    if(!script1.GetOp(pc1, opcode1, vch1))
                        break;
                }
                if(!script2.GetOp(pc2, opcode2, vch2))
                    break;
                // Normal situation is to fall through
                // to other if/else statements
            }
            if(opcode2 == OP_PUBKEY) {
                if(vch1.size() < 33 || vch1.size() > 120)
                    break;
                vSolutionsRet.push_back(vch1);
            } else if(opcode2 == OP_PUBKEYHASH) {
                if(vch1.size() != sizeof(uint160))
                    break;
                vSolutionsRet.push_back(vch1);
            } else if(opcode2 == OP_SMALLINTEGER) {
                // Single-byte small integer pushed onto vSolutions
                if(opcode1 == OP_0 ||
                        (opcode1 >= OP_1 && opcode1 <= OP_16)) {
                    char n = (char)CScript::DecodeOP_N(opcode1);
                    vSolutionsRet.push_back(valtype(1, n));
                } else
                    break;
            } else if(opcode1 != opcode2 || vch1 != vch2) {
                // Others must match exactly
                break;
            }
        }
    }
    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return(false);
}

bool Sign1(const CKeyID& address, const CKeyStore& keystore, uint256 hash, int nHashType, CScript& scriptSigRet) {
    CKey key;
    if(!keystore.GetKey(address, key))
        return(false);
    vector<unsigned char> vchSig;
    if(!key.Sign(hash, vchSig))
        return(false);
    vchSig.push_back((unsigned char)nHashType);
    scriptSigRet << vchSig;
    return(true);
}

bool SignN(const vector<valtype>& multisigdata, const CKeyStore& keystore, uint256 hash, int nHashType, CScript& scriptSigRet) {
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    for(unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++) {
        const valtype& pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if(Sign1(keyID, keystore, hash, nHashType, scriptSigRet))
            ++nSigned;
    }
    return nSigned==nRequired;
}

//
// Sign scriptPubKey with private keys stored in keystore, given transaction hash and hash type.
// Signatures are returned in scriptSigRet (or returns false if scriptPubKey can't be signed),
// unless whichTypeRet is TX_SCRIPTHASH, in which case scriptSigRet is the redemption script.
// Returns false if scriptPubKey could not be completely satisfied.
//
bool Solver(const CKeyStore& keystore, const CScript& scriptPubKey, uint256 hash, int nHashType,
            CScript& scriptSigRet, txnouttype& whichTypeRet) {
    scriptSigRet.clear();
    vector<valtype> vSolutions;
    if(!Solver(scriptPubKey, whichTypeRet, vSolutions))
        return(false);
    CKeyID keyID;
    switch(whichTypeRet) {
    case TX_NONSTANDARD:
        return(false);
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        return Sign1(keyID, keystore, hash, nHashType, scriptSigRet);
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if(!Sign1(keyID, keystore, hash, nHashType, scriptSigRet))
            return(false);
        else {
            CPubKey vch;
            keystore.GetPubKey(keyID, vch);
            scriptSigRet << vch;
        }
        return(true);
    case TX_SCRIPTHASH:
        return keystore.GetCScript(uint160(vSolutions[0]), scriptSigRet);
    case TX_MULTISIG:
        scriptSigRet << OP_0; // workaround CHECKMULTISIG bug
        return (SignN(vSolutions, keystore, hash, nHashType, scriptSigRet));

    case TX_HYBRID_PUBKEY:
    case TX_HYBRID_PUBKEYHASH:
    case TX_HYBRID_MULTISIG:
    {
        // Hybrid signing needs access to both the transaction and input index
        // (the ML-DSA signature is over the signature-hash preimage), which are
        // not available to this overload. Hybrid scripts are signed by
        // SignHybridTx(), reached from the SignSignature() wrapper below.
        return false;
    }
    }
    return(false);
}

int ScriptSigArgsExpected(txnouttype t, const std::vector<std::vector<unsigned char> >& vSolutions) {
    switch(t) {
    case TX_NONSTANDARD:
        return -1;
    case TX_PUBKEY:
        return 1;
    case TX_PUBKEYHASH:
        return 2;
    case TX_MULTISIG:
        if(vSolutions.size() < 1 || vSolutions[0].size() < 1)
            return -1;
        return vSolutions[0][0] + 1;
    case TX_SCRIPTHASH:
        return 1; // doesn't include args needed by the script
    case TX_HYBRID_PUBKEY:
        return 2;
    case TX_HYBRID_PUBKEYHASH:
        return 4;
    case TX_HYBRID_MULTISIG:
        if(vSolutions.size() < 1 || vSolutions[0].size() < 1)
            return -1;
        // Each hybrid signature is a two-element stack item (sigEC, sigML).
        return vSolutions[0][0] * 2;
    }
    return -1;
}

bool IsStandard(const CScript& scriptPubKey) {
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    if(!Solver(scriptPubKey, whichType, vSolutions))
        return(false);
    if(whichType == TX_MULTISIG) {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Support up to x-of-3 multisig txns as standard
        if(n < 1 || n > 3)
            return(false);
        if(m < 1 || m > n)
            return(false);
    }
    if(whichType == TX_HYBRID_MULTISIG) {
        unsigned char m = vSolutions.front()[0];
        unsigned char n = vSolutions.back()[0];
        // Keep parity with regular multisig: up to x-of-3.
        // Each key is two pushes, so a full N-of-N is already large.
        if(n < 1 || n > 3)
            return(false);
        if(m < 1 || m > n)
            return(false);
    }

    return whichType != TX_NONSTANDARD;
}

unsigned int HaveKeys(const vector<valtype>& pubkeys, const CKeyStore& keystore) {
    unsigned int nResult = 0;
    BOOST_FOREACH(const valtype& pubkey, pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if(keystore.HaveKey(keyID))
            ++nResult;
    }
    return nResult;
}

class CKeyStoreIsMineVisitor : public boost::static_visitor<bool> {
private:
    const CKeyStore *keystore;

public:
    CKeyStoreIsMineVisitor(const CKeyStore *keystoreIn) : keystore(keystoreIn) { }
    bool operator()(const CNoDestination &/*dest*/) const { return(false); }
    bool operator()(const CKeyID &keyID) const { return(keystore->HaveKey(keyID)); }
    bool operator()(const CScriptID &scriptID) const { return(keystore->HaveCScript(scriptID)); }
    bool operator()(const CHybridKeyID &keyID) const{
        return keystore->HaveHybridKey(keyID);
    }
};

isminetype IsMine(const CKeyStore &keystore, const CScript &scriptPubKey) {
    vector<valtype> vSolutions;
    txnouttype whichType;

    if(!Solver(scriptPubKey, whichType, vSolutions)) {
        if(keystore.HaveWatchOnly(scriptPubKey))
          return(MINE_WATCH_ONLY);
        return(MINE_NO);
    }

    CKeyID keyID;
    switch(whichType) {

        case(TX_NONSTANDARD):
            break;

        case(TX_PUBKEY):
            keyID = CPubKey(vSolutions[0]).GetID();
            if(keystore.HaveKey(keyID))
              return(MINE_SPENDABLE);
            break;

        case(TX_PUBKEYHASH):
            keyID = CKeyID(uint160(vSolutions[0]));
            if(keystore.HaveKey(keyID))
              return(MINE_SPENDABLE);
            break;

        case(TX_SCRIPTHASH): {
            CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
            CScript subscript;

            if(keystore.GetCScript(scriptID, subscript)) {
                isminetype ret;
                ret = IsMine(keystore, subscript);
                if(ret == MINE_SPENDABLE)
                  return(ret);
            }
            break;
        }

        case(TX_MULTISIG): {
            /* Only consider transactions "mine" if we own ALL the
             * keys involved. multi-signature transactions that are
             * partially owned (somebody else has a key that can spend
             * them) enable spend-out-from-under-you attacks, especially
             * in shared-wallet situations. */
            vector<valtype> keys(vSolutions.begin() + 1, vSolutions.begin() + vSolutions.size() - 1);
            if(HaveKeys(keys, keystore) == keys.size())
              return(MINE_SPENDABLE);
            break;
        }

        case TX_HYBRID_PUBKEY: {
            if (vSolutions.size() != 2)
                return MINE_NO;

            CPubKey ecdsaPub(vSolutions[0]);

            if (!keystore.IsLocked() &&
                keystore.HaveHybridKeyByLegacyID(ecdsaPub.GetID()))
                return MINE_SPENDABLE;

            break;
        }

        case TX_HYBRID_PUBKEYHASH: {
            uint160 hash(vSolutions[0]);

            if (!keystore.IsLocked() &&
                keystore.HaveHybridKeyByHash(hash))
                return MINE_SPENDABLE;

            break;
        }

        case TX_HYBRID_MULTISIG: {
            if (vSolutions.size() < 3 || vSolutions[0].size() != 1)
                return MINE_NO;

            int nN = vSolutions[vSolutions.size() - 1][0];
            if (nN < 1 || vSolutions.size() != 2 + (size_t)nN * 2)
                return MINE_NO;

            bool fAll = true;
            for (int i = 0; i < nN && fAll; ++i) {
                CPubKey ecdsaPub(vSolutions[1 + i * 2]);
                if (!keystore.HaveHybridKeyByLegacyID(ecdsaPub.GetID()))
                    fAll = false;
            }

            if (!keystore.IsLocked() && fAll)
                return MINE_SPENDABLE;
            break;
        }
    }

    if(keystore.HaveWatchOnly(scriptPubKey))
      return(MINE_WATCH_ONLY);

    return(MINE_NO);
}

isminetype IsMine(const CKeyStore &keystore, const CTxDestination &dest) {
    CScript script;

    script.SetDestination(dest);
    return(IsMine(keystore, script));
}

class CAffectedKeysVisitor : public boost::static_visitor<void> {

private:
    const CKeyStore &keystore;
    std::vector<CKeyID> &vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector<CKeyID> &vKeysIn) :
      keystore(keystoreIn), vKeys(vKeysIn) { }

    void Process(const CScript &script) {
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if(ExtractDestinations(script, type, vDest, nRequired)) {
            BOOST_FOREACH(const CTxDestination &dest, vDest)
              boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID &keyId) {
        if(keystore.HaveKey(keyId))
          vKeys.push_back(keyId);
    }

    void operator()(const CHybridKeyID& keyId) const
    {
        if (keystore.HaveHybridKey(keyId))
        {
            CHybridKey hybridKey;
            if (keystore.GetHybridKeyByHash(uint160(keyId), hybridKey))
                vKeys.push_back(hybridKey.GetKeyID());
        }
    }

    void operator()(const CScriptID &scriptId) {
        CScript script;
        if(keystore.GetCScript(scriptId, script))
          Process(script);
    }

    void operator()(const CNoDestination &/*none*/) { }
};

void ExtractAffectedKeys(const CKeyStore &keystore, const CScript &scriptPubKey,
  std::vector<CKeyID> &vKeys) {
    CAffectedKeysVisitor(keystore, vKeys).Process(scriptPubKey);
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet) {
    vector<valtype> vSolutions;
    txnouttype whichType;

    if (!Solver(scriptPubKey, whichType, vSolutions))
        return false;

    switch (whichType)
    {
        case TX_PUBKEY:
            addressRet = CPubKey(vSolutions[0]).GetID();
            return true;

        case TX_PUBKEYHASH:
            addressRet = CKeyID(uint160(vSolutions[0]));
            return true;

        case TX_SCRIPTHASH:
            addressRet = CScriptID(uint160(vSolutions[0]));
            return true;

        case TX_HYBRID_PUBKEYHASH:
            addressRet = CHybridKeyID(uint160(vSolutions[0]));
            return true;
        default:
            return false;
    }
}

bool ExtractDestinations(const CScript& scriptPubKey,
                         txnouttype& type,
                         std::vector<CTxDestination>& addressRet,
                         int& nRequired)
{
    addressRet.clear();
    nRequired = 0;

    std::vector<std::vector<unsigned char> > vSolutions;

    if (!Solver(scriptPubKey, type, vSolutions))
        return false;

    switch (type)
    {
        case TX_PUBKEY:
        {
            CPubKey pubKey(vSolutions[0]);
            addressRet.push_back(pubKey.GetID());
            nRequired = 1;
            return true;
        }

        case TX_PUBKEYHASH:
        {
            addressRet.push_back(CKeyID(uint160(vSolutions[0])));
            nRequired = 1;
            return true;
        }

        case TX_SCRIPTHASH:
        {
            addressRet.push_back(CScriptID(uint160(vSolutions[0])));
            nRequired = 1;
            return true;
        }

        case TX_HYBRID_PUBKEY:
        {
            if (vSolutions.size() != 2)
                return false;

            std::vector<unsigned char> blob;
            blob.reserve(vSolutions[0].size() + vSolutions[1].size());

            blob.insert(blob.end(),
                        vSolutions[0].begin(),
                        vSolutions[0].end());

            blob.insert(blob.end(),
                        vSolutions[1].begin(),
                        vSolutions[1].end());

            addressRet.push_back(CHybridKeyID(Hash160(blob)));

            nRequired = 1;
            return true;
        }

        case TX_HYBRID_PUBKEYHASH:
        {
            if (vSolutions.size() != 1)
                return false;

            addressRet.push_back(CHybridKeyID(uint160(vSolutions[0])));
            nRequired = 1;
            return true;
        }

        case TX_MULTISIG:
        {
            nRequired = vSolutions.front()[0];

            for (unsigned int i = 1; i + 1 < vSolutions.size(); i++)
            {
                CPubKey pubKey(vSolutions[i]);
                addressRet.push_back(pubKey.GetID());
            }

            return true;
        }

        default:
            return false;
    }
}

bool VerifyScript(
    const CScript& scriptSig,
    const CScript& scriptPubKey,
    const CTransaction& txTo,
    unsigned int nIn,
    bool fValidatePayToScriptHash,
    int nHashType
) {
    vector<vector<unsigned char>> stack, stackCopy;

    // Step 1: Evaluate scriptSig
    if (!EvalScript(stack, scriptSig, txTo, nIn, nHashType))
        return false;

    if (fValidatePayToScriptHash)
        stackCopy = stack;

    // Step 2: Evaluate scriptPubKey
    if (!EvalScript(stack, scriptPubKey, txTo, nIn, nHashType))
        return false;

    if (stack.empty() || !CastToBool(stack.back()))
        return false;

    // Step 3: P2SH validation
    if (fValidatePayToScriptHash && scriptPubKey.IsPayToScriptHash()) {
        if (!scriptSig.IsPushOnly())
            return false;

        const valtype& pubKeySerialized = stackCopy.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stackCopy);
        if (!EvalScript(stackCopy, pubKey2, txTo, nIn, nHashType))
            return false;
        if (stackCopy.empty() || !CastToBool(stackCopy.back()))
            return false;
    }

    return true;
}

// Helper function for hybrid transaction signing
bool SignHybridTx(const CKeyStore& keystore, const CScript& scriptPubKey,
                  CTransaction& txTo, unsigned int nIn, int nHashType,
                  CScript& scriptSigRet)
{
    vector<vector<unsigned char> > solutions;
    txnouttype scriptType;

    if (!Solver(scriptPubKey, scriptType, solutions))
        return false;

    CScript scriptCode(scriptPubKey);
    uint256 sighash = SignatureHash(scriptCode, txTo, nIn, nHashType);

    std::vector<unsigned char> hybridMsg;

    std::vector<unsigned char> sighash_preimage;
    if (!ConstructSignatureHashPreimage(scriptCode, txTo, nIn, nHashType,
                                        sighash_preimage))
    return false;

    hybridMsg = BuildHybridMessage(sighash_preimage);

    if (scriptType == TX_HYBRID_PUBKEY)
    {
        CPubKey ecdsaPubKey(solutions[0]);
        CKeyID keyID = ecdsaPubKey.GetID();

        CHybridKey hybridKey;
        if (!keystore.GetHybridKeyByLegacyID(keyID, hybridKey))
            return false;

        CKey ecdsaKey = hybridKey.GetCKey();

        std::vector<unsigned char> ecdsaSig;
        if (!ecdsaKey.Sign(sighash, ecdsaSig))
            return false;
        ecdsaSig.push_back((unsigned char)nHashType);

        std::vector<unsigned char> mldsaSig;
        if (!hybridKey.mldsaSigner ||
            !hybridKey.mldsaSigner->Sign(hybridMsg, mldsaSig))
            return false;
        mldsaSig.push_back((unsigned char)nHashType);

        scriptSigRet << ecdsaSig << mldsaSig;
        return true;
    }
    else if (scriptType == TX_HYBRID_PUBKEYHASH)
    {
        if (solutions[0].size() < 20)
            return false;

        std::vector<unsigned char> hashBytes(solutions[0].begin(),
                                             solutions[0].begin() + 20);
        uint160 keyHash160;
        std::reverse(hashBytes.begin(), hashBytes.end());
        keyHash160.SetHex(HexStr(hashBytes));

        CHybridKey hybridKey;
        if (!keystore.GetHybridKeyByHash(keyHash160, hybridKey))
            return false;

        CKey ecdsaKey = hybridKey.GetCKey();

        std::vector<unsigned char> ecdsaSig;
        if (!ecdsaKey.Sign(sighash, ecdsaSig))
            return false;

        ecdsaSig.push_back((unsigned char)nHashType);

        std::vector<unsigned char> mldsaSig;
        if (!hybridKey.mldsaSigner ||
            !hybridKey.mldsaSigner->Sign(hybridMsg, mldsaSig))
            return false;

        mldsaSig.push_back((unsigned char)nHashType);

        std::vector<unsigned char> ecdsaPub = hybridKey.secpPub.Raw();
        std::vector<unsigned char> mldsaPub = hybridKey.mldsaSigner->GetPublicKey();

        scriptSigRet
            << ecdsaSig
            << mldsaSig
            << ecdsaPub
            << mldsaPub;

        return true;
    }

    else if (scriptType == TX_HYBRID_MULTISIG)
    {
        // solutions: [0] = m, [1..2n] = key pairs (ecdsa, mldsa), [last] = n
        // scriptSig layout (matches OP_CHECKMULTIHYBRIDSIG):
        //   [sigEC1][sigML1] ... [sigECm][sigMLm]   (signatures only)
        if (solutions.size() < 3 || solutions[0].size() != 1)
            return false;

        int nM = solutions[0][0];
        int nN = solutions[solutions.size() - 1][0];
        if (nM < 1 || nN < 1 || nM > nN ||
            solutions.size() != 2 + (size_t)nN * 2)
            return false;

        int signed_count = 0;
        for (int key = 0; key < nN && signed_count < nM; key++)
        {
            CPubKey ecdsaPub(solutions[1 + key * 2]);
            CKeyID keyID = ecdsaPub.GetID();

            CHybridKey hybridKey;
            if (!keystore.GetHybridKeyByLegacyID(keyID, hybridKey))
                continue;

            CKey ecdsaKey = hybridKey.GetCKey();

            std::vector<unsigned char> ecdsaSig;
            if (!ecdsaKey.Sign(sighash, ecdsaSig))
                continue;
            ecdsaSig.push_back((unsigned char)nHashType);

            std::vector<unsigned char> mldsaSig;
            if (!hybridKey.mldsaSigner ||
                !hybridKey.mldsaSigner->Sign(hybridMsg, mldsaSig))
                return false;

            mldsaSig.push_back((unsigned char)nHashType);

            scriptSigRet
                << ecdsaSig
                << mldsaSig;

            signed_count++;
        }

        return signed_count >= nM;
    }

    return false;
}

bool SignSignature(const CKeyStore &keystore, const CScript& fromPubKey, CTransaction& txTo, unsigned int nIn, int nHashType) {
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    uint256 hash = SignatureHash(fromPubKey, txTo, nIn, nHashType);

    txnouttype whichType;
    vector<valtype> vSolutions;

    if (!Solver(fromPubKey, whichType, vSolutions))
        return false;

    if (whichType == TX_HYBRID_PUBKEY ||
        whichType == TX_HYBRID_PUBKEYHASH ||
        whichType == TX_HYBRID_MULTISIG)
    {
        bool ok = SignHybridTx(
            keystore,
            fromPubKey,
            txTo,
            nIn,
            nHashType,
            txin.scriptSig);

        return ok;
    }

    CScript scriptSigRet;
    if(!Solver(keystore, fromPubKey, hash, nHashType, scriptSigRet, whichType))
        return(false);
    if(whichType == TX_SCRIPTHASH) {
        CScript subscript = scriptSigRet;
        uint256 hash2 = SignatureHash(subscript, txTo, nIn, nHashType);
        txnouttype subType;
        bool fSolved =
            Solver(keystore, subscript, hash2, nHashType, scriptSigRet, subType) && subType != TX_SCRIPTHASH;
        if (!fSolved) {
            txnouttype templateType;
            std::vector<valtype> templateSolutions;
            if (Solver(subscript, templateType, templateSolutions)) {
                CScript hybridSigRet;
                if (templateType == TX_HYBRID_PUBKEY ||
                    templateType == TX_HYBRID_PUBKEYHASH ||
                    templateType == TX_HYBRID_MULTISIG)
                {
                    /*
                     * Keep whatever signatures we produced even when the
                     * multisig threshold has not been reached yet.  This
                     * permits several wallets to sign a P2SH hybrid
                     * multisig transaction one by one: the partial
                     * scriptSig emitted here is merged with the signatures
                     * of the other signers by CombineSignatures() the next
                     * time signrawtransaction() is called.
                     */
                    SignHybridTx(keystore, subscript, txTo, nIn, nHashType, hybridSigRet);
                    if (!hybridSigRet.empty())
                    {
                        scriptSigRet = hybridSigRet;
                        fSolved = true;
                    }
                }
            }
        }
        if (fSolved) {
            txin.scriptSig = scriptSigRet;
            txin.scriptSig << static_cast<valtype>(subscript);
        }
        if(!fSolved) return(false);
    } else {
        txin.scriptSig = scriptSigRet;
    }

    return VerifyScript(txin.scriptSig, fromPubKey, txTo, nIn, true, 0);
}

bool SignSignature(const CKeyStore &keystore, const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType) {
    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];
    return SignSignature(keystore, txout.scriptPubKey, txTo, nIn, nHashType);
}

bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, bool fValidatePayToScriptHash, int nHashType) {
    assert(nIn < txTo.vin.size());
    const CTxIn& txin = txTo.vin[nIn];
    if(txin.prevout.n >= txFrom.vout.size())
        return(false);
    const CTxOut& txout = txFrom.vout[txin.prevout.n];
    if(txin.prevout.hash != txFrom.GetHash())
        return(false);
    return VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, nIn, fValidatePayToScriptHash, nHashType);
}

static CScript PushAll(const vector<valtype>& values) {
    CScript result;
    BOOST_FOREACH(const valtype& v, values)
    result << v;
    return result;
}

static bool CheckSigWrapper(const std::vector<unsigned char>& sig,
                            const std::vector<unsigned char>& pubkey,
                            const CScript& scriptCode,
                            const CTransaction& txTo,
                            unsigned int nIn,
                            int nHashType)
{
    // Original CheckSig takes vectors by value, script by non-const reference
return CheckSig(sig, pubkey, scriptCode, txTo, nIn, nHashType);

}

static CScript CombineMultisig(const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn,
                               const std::vector<valtype>& vSolutions,
                               std::vector<valtype>& sigs1, std::vector<valtype>& sigs2)
{
    // Combine all the signatures we've got:
    std::set<valtype> allsigs;
    for (const valtype& v : sigs1) {
        if (!v.empty()) allsigs.insert(v);
    }
    for (const valtype& v : sigs2) {
        if (!v.empty()) allsigs.insert(v);
    }

    // Build a map of pubkey -> signature by matching sigs to pubkeys
    assert(vSolutions.size() > 1);
    unsigned int nSigsRequired = vSolutions.front()[0];
    unsigned int nPubKeys = vSolutions.size() - 2;

    std::map<valtype, valtype> sigsMap;

    for (const valtype& sig : allsigs) {
        for (unsigned int i = 0; i < nPubKeys; i++) {
            const valtype& pubkey = vSolutions[i + 1];
            if (sigsMap.count(pubkey)) continue; // Already have a sig

            if (CheckSigWrapper(sig, pubkey, scriptPubKey, txTo, nIn, 0)) {
                sigsMap[pubkey] = sig;
                break;
            }
        }
    }

    // Now build a merged CScript
    unsigned int nSigsHave = 0;
    CScript result;
    result << OP_0; // Pop-one-too-many workaround

    for (unsigned int i = 0; i < nPubKeys && nSigsHave < nSigsRequired; i++) {
        const valtype& pubkey = vSolutions[i + 1];
        if (sigsMap.count(pubkey)) {
            result << sigsMap[pubkey];
            ++nSigsHave;
        }
    }

    // Fill any missing with OP_0
    for (unsigned int i = nSigsHave; i < nSigsRequired; i++) {
        result << OP_0;
    }

    return result;
}

static CScript CombineHybridMultisig(const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn,
                                     const std::vector<valtype>& vSolutions,
                                     std::vector<valtype>& sigs1, std::vector<valtype>& sigs2)
{
    if (vSolutions.size() < 3 || vSolutions[0].size() != 1)
        return CScript();

    unsigned int nN = vSolutions[vSolutions.size() - 1][0];
    if (nN < 1 || vSolutions.size() != 2 + (size_t)nN * 2)
        return CScript();

    std::vector<valtype> both;
    for (const valtype& v : sigs1)
        if (!v.empty()) both.push_back(v);
    for (const valtype& v : sigs2)
        if (!v.empty()) both.push_back(v);

    unsigned int nM = vSolutions[0][0];
    if (nM < 1 || nM > nN)
        return CScript();

    std::vector<bool> have(nN, false);
    std::vector<valtype> ecSigFor(nN), mlSigFor(nN);

    for (size_t bi = 0; bi + 1 < both.size(); bi += 2) {
        const valtype& ecSig = both[bi];
        const valtype& mlSig = both[bi + 1];
        for (unsigned int i = 0; i < nN; i++) {
            if (have[i]) continue;
            const valtype& ecPub = vSolutions[1 + i * 2];
            const valtype& mlPub = vSolutions[2 + i * 2];
            if (VerifyHybridSignature(ecSig, mlSig, ecPub, mlPub,
                                      scriptPubKey, txTo, nIn, 0)) {
                have[i] = true;
                ecSigFor[i] = ecSig;
                mlSigFor[i] = mlSig;
                break;
            }
        }
    }

    // OP_CHECKMULTIHYBRIDSIG matches at most nM pairs: the two-pointer
    // matcher stops once sigIndex reaches nM and leaves any surplus pairs
    // unmatched on the stack. Consensus tolerates that (no clean-stack rule
    // in this fork), but AreInputsStandard expects exactly nM*2 signature
    // items, so an over-emitted scriptSig is non-standard and cannot be
    // relayed or mined. Emit only the first nM matched keys in order.
    CScript result;
    unsigned int count = 0;
    for (unsigned int i = 0; i < nN; i++) {
        if (have[i]) {
            result << ecSigFor[i] << mlSigFor[i];
            if (++count >= nM)
                break;
        }
    }
    return result;
}

static CScript CombineSignatures(CScript scriptPubKey, const CTransaction& txTo, unsigned int nIn,
                                 const txnouttype txType, const vector<valtype>& vSolutions,
                                 vector<valtype>& sigs1, vector<valtype>& sigs2) {
    switch(txType) {
    case TX_NONSTANDARD:
        // Don't know anything about this, assume bigger one is correct:
        if(sigs1.size() >= sigs2.size())
            return PushAll(sigs1);
        return PushAll(sigs2);
    case TX_PUBKEY:
    case TX_PUBKEYHASH:
        // Signatures are bigger than placeholders or empty scripts:
        if(sigs1.empty() || sigs1[0].empty())
            return PushAll(sigs2);
        return PushAll(sigs1);
    case TX_SCRIPTHASH:
        if(sigs1.empty() || sigs1.back().empty())
            return PushAll(sigs2);
        else if(sigs2.empty() || sigs2.back().empty())
            return PushAll(sigs1);
        else {
            // Recur to combine:
            valtype spk = sigs1.back();
            CScript pubKey2(spk.begin(), spk.end());
            txnouttype txType2;
            vector<vector<unsigned char> > vSolutions2;
            Solver(pubKey2, txType2, vSolutions2);
            sigs1.pop_back();
            sigs2.pop_back();
            CScript result = CombineSignatures(pubKey2, txTo, nIn, txType2, vSolutions2, sigs1, sigs2);
            result << spk;
            return result;
        }
    case TX_MULTISIG:
        return CombineMultisig(scriptPubKey, txTo, nIn, vSolutions, sigs1, sigs2);

    // Hybrid signature types
    case TX_HYBRID_MULTISIG:
        return CombineHybridMultisig(scriptPubKey, txTo, nIn, vSolutions, sigs1, sigs2);
    case TX_HYBRID_PUBKEY:
    case TX_HYBRID_PUBKEYHASH:
        // Single-signature types: prefer the more complete signature set
        if (sigs1.size() >= sigs2.size())
            return PushAll(sigs1);
        return PushAll(sigs2);
    }
    return CScript();
}

CScript CombineSignatures(CScript scriptPubKey, const CTransaction& txTo, unsigned int nIn,
                          const CScript& scriptSig1, const CScript& scriptSig2) {
    txnouttype txType;
    vector<vector<unsigned char> > vSolutions;
    Solver(scriptPubKey, txType, vSolutions);
    vector<valtype> stack1;
    EvalScript(stack1, scriptSig1, CTransaction(), 0, 0);
    vector<valtype> stack2;
    EvalScript(stack2, scriptSig2, CTransaction(), 0, 0);
    return CombineSignatures(scriptPubKey, txTo, nIn, txType, vSolutions, stack1, stack2);
}

unsigned int CScript::GetSigOpCount(bool fAccurate) const {
    unsigned int n = 0;
    const_iterator pc = begin();
    opcodetype lastOpcode = OP_INVALIDOPCODE;
    while(pc < end()) {
        opcodetype opcode;
        if(!GetOp(pc, opcode))
            break;
        if(opcode == OP_CHECKSIG || opcode == OP_CHECKSIGVERIFY)
            n++;
        else if(opcode == OP_CHECKMULTISIG || opcode == OP_CHECKMULTISIGVERIFY) {
            if(fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16)
                n += DecodeOP_N(lastOpcode);
            else
                n += 20;
        }
        else if(opcode == OP_CHECKHYBRIDSIG || opcode == OP_CHECKHYBRIDSIGVERIFY) {
            // Hybrid signature verification costs 2 signature operations:
            // 1 for ECDSA (classical secp256k1)
            // 1 for ML-DSA-65 (post-quantum)
            n += 2;
        }
        else if(opcode == OP_CHECKMULTIHYBRIDSIG) {
            // Hybrid multisig: each key represents 2 signature operations
            // (one for ECDSA component, one for ML-DSA component)
            if(fAccurate && lastOpcode >= OP_1 && lastOpcode <= OP_16) {
                // Multiply number of required keys by 2
                n += DecodeOP_N(lastOpcode) * 2;
            } else {
                // Conservative estimate: assume up to 20 keys
                n += 20 * 2;
            }
        }
        lastOpcode = opcode;
    }
    return n;
}

unsigned int CScript::GetSigOpCount(const CScript& scriptSig) const {
    if(!IsPayToScriptHash())
        return GetSigOpCount(true);
    // This is a pay-to-script-hash scriptPubKey;
    // get the last item that the scriptSig
    // pushes onto the stack:
    const_iterator pc = scriptSig.begin();
    vector<unsigned char> data;
    while(pc < scriptSig.end()) {
        opcodetype opcode;
        if(!scriptSig.GetOp(pc, opcode, data))
            return 0;
        if(opcode > OP_16)
            return 0;
    }
    /// ... and return its opcount:
    CScript subscript(data.begin(), data.end());
    return subscript.GetSigOpCount(true);
}

bool CScript::IsPayToScriptHash() const {
    // Extra-fast test for pay-to-script-hash CScripts:
    return (this->size() == 23 &&
            this->at(0) == OP_HASH160 &&
            this->at(1) == 0x14 &&
            this->at(22) == OP_EQUAL);
}

class CScriptVisitor : public boost::static_visitor<bool> {
   private:
    CScript *script;

   public:
    CScriptVisitor(CScript *scriptin) { script = scriptin; }

    bool operator()(const CNoDestination &/*dest*/) const {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const {
        script->clear();
        *script << OP_DUP << OP_HASH160 << keyID << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CScriptID &scriptID) const {
        script->clear();
        *script << OP_HASH160 << scriptID << OP_EQUAL;
        return true;
    }

    bool operator()(const CHybridKeyID &keyID) const {
        script->clear();
        *script << OP_DUPHYBRID << OP_HASHHYBRID160 << keyID << OP_EQUALVERIFY
                << OP_CHECKHYBRIDSIG;

        std::vector<std::vector<unsigned char> > sol;
        txnouttype type;

        Solver(*script, type, sol);

        return true;
    }
};

void CScript::SetDestination(const CTxDestination& dest) {
    boost::apply_visitor(CScriptVisitor(this), dest);
}

void CScript::SetMultisig(int nRequired, const std::vector<CKey>& keys) {
    this->clear();
    *this << EncodeOP_N(nRequired);
    BOOST_FOREACH(const CKey& key, keys)
    *this << key.GetPubKey();
    *this << EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
}

/* Produces a P2PKH pubkey script using a pubkey hash */
CScript GetScriptForPubKeyHash(const CKeyID &keyID) {
    CScript script;

    script.clear();
    script << OP_DUP << OP_HASH160 << keyID << OP_EQUALVERIFY << OP_CHECKSIG;

    return(script);
}

// ============================================================================
// HYBRID SCRIPT TEMPLATES & HELPER FUNCTIONS
// ============================================================================

/**
 * Create Pay-to-Hybrid-Public-Key (P2PH) script
 *
 * Script: [ECDSA_PUBKEY] [MLDSA_PUBKEY] OP_CHECKHYBRIDSIG
 * Size: 1985 + 2 = 1987 bytes
 */
CScript GetScriptForHybridPubKey(const CHybridPubKey& hybridKey) {

    if (!hybridKey.IsValid()) {
        return CScript();  // Invalid
    }

    CScript script;
    script << hybridKey.ecdsaPubKey
           << hybridKey.mldsaPubKey
           << OP_CHECKHYBRIDSIG;

    return script;
}

/**
 * Create Pay-to-Hybrid-Public-Key-Hash (P2HPKH) script
 *
 * Script: OP_DUP OP_HASH256 [HASH256] OP_EQUALVERIFY OP_CHECKHYBRIDSIG
 * Size: 36 bytes
 *
 * Receiver publishes: HASH256(ecdsaPubKey || mldsaPubKey)
 * Sender reveals full key when spending
 */
CScript GetScriptForHybridPubKeyHash(const uint160& hash)
{

std::vector<unsigned char> hashBytes(20);
memcpy(&hashBytes[0], &hash, 20);

return CScript()
    << OP_DUPHYBRID
    << OP_HASHHYBRID160
    << hashBytes
    << OP_EQUALVERIFY
    << OP_CHECKHYBRIDSIG;

}

/**
 * Create an M-of-N Hybrid Multisignature output.
 *
 * Script layout (matches OP_CHECKMULTIHYBRIDSIG's expectations):
 *
 *   OP_<m> <ecdsaPub1> <mldsaPub1> ... <ecdsaPubN> <mldsaPubN> OP_<n> OP_CHECKMULTIHYBRIDSIG
 *
 * Each hybrid public key is pushed as TWO separate stack items (the ECDSA
 * public key followed by the ML-DSA public key), matching how the verifier
 * reads keys via stacktop(-ikey-1)/stacktop(-ikey).
 */
CScript GetScriptForHybridMultisig(int nRequired,
                                  const std::vector<CHybridPubKey>& keys) {
    if (nRequired < 1 || nRequired > 16)
        return CScript();  // EncodeOP_N supports 1..16 only
    if (keys.empty() || keys.size() > 16)
        return CScript();  // EncodeOP_N supports 1..16 only
    if ((size_t)nRequired > keys.size())
        return CScript();  // cannot require more keys than supplied

    CScript script;
    script << CScript::EncodeOP_N(nRequired);

    for (const auto& key : keys) {
        if (!key.IsValid()) {
            return CScript();  // Invalid input
        }
        script << key.ecdsaPubKey << key.mldsaPubKey;
    }

    script << CScript::EncodeOP_N(keys.size())
           << OP_CHECKMULTIHYBRIDSIG;

    return script;
}
