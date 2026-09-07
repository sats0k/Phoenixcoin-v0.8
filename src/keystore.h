// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#ifndef KEYSTORE_H
#define KEYSTORE_H

#include <boost/signals2/signal.hpp>
#include <boost/variant.hpp>

#include <map>
#include <utility>
#include <vector>
#include <set>

#include "crypter.h"
#include "sync.h"

struct CHybridKey;

class CScript;

class CNoDestination {
public:
    friend bool operator==(const CNoDestination &/*a*/, const CNoDestination &/*b*/) { return true; }
    friend bool operator<(const CNoDestination &/*a*/, const CNoDestination &/*b*/) { return true; }
};

class CHybridKeyID : public uint160
{
public:
    CHybridKeyID() {}
    CHybridKeyID(const uint160& in) : uint160(in) {}
};

/* Hybrid Public Key Storage */
struct CHybridPubKey {
    std::vector<unsigned char> ecdsaPubKey;    // 33 bytes (compressed secp256k1)
    std::vector<unsigned char> mldsaPubKey;    // 1952 bytes (raw ML-DSA-65)

    CHybridPubKey() = default;
    CHybridPubKey(const std::vector<unsigned char>& ecdsa,
                  const std::vector<unsigned char>& mldsa)
        : ecdsaPubKey(ecdsa), mldsaPubKey(mldsa) {}

    // Size validation
    static constexpr size_t ECDSA_SIZE = 33;
    static constexpr size_t MLDSA_SIZE = 1952;
    static constexpr size_t TOTAL_SIZE = ECDSA_SIZE + MLDSA_SIZE;

    bool IsValid() const {
        return ecdsaPubKey.size() == ECDSA_SIZE &&
               mldsaPubKey.size() == MLDSA_SIZE;
    }

    // Serialize to combined form (used in script)
    std::vector<unsigned char> Serialize() const {
        std::vector<unsigned char> result;
        result.reserve(TOTAL_SIZE);
        result.insert(result.end(), ecdsaPubKey.begin(), ecdsaPubKey.end());
        result.insert(result.end(), mldsaPubKey.begin(), mldsaPubKey.end());
        return result;
    }

    // Deserialize from combined form
    static CHybridPubKey Deserialize(const std::vector<unsigned char>& data) {
        if (data.size() != TOTAL_SIZE) {
            return CHybridPubKey();
        }
        return CHybridPubKey(
            std::vector<unsigned char>(data.begin(), data.begin() + ECDSA_SIZE),
            std::vector<unsigned char>(data.begin() + ECDSA_SIZE, data.end())
        );
    }

    // Required for std::set and std::map
    bool operator<(const CHybridPubKey& other) const {
        if (ecdsaPubKey.size() != other.ecdsaPubKey.size())
            return ecdsaPubKey.size() < other.ecdsaPubKey.size();
        if (ecdsaPubKey != other.ecdsaPubKey)
            return ecdsaPubKey < other.ecdsaPubKey;
        return mldsaPubKey < other.mldsaPubKey;
     }

    bool operator==(const CHybridPubKey& other) const {
        return ecdsaPubKey == other.ecdsaPubKey &&
               mldsaPubKey == other.mldsaPubKey;
    }

    CHybridKeyID GetID() const
    {
        std::vector<unsigned char> blob = Serialize();
            return CHybridKeyID(Hash160(blob));
    }
};

typedef boost::variant<CNoDestination, CKeyID, CScriptID, CHybridKeyID> CTxDestination;

/** A virtual base class for key stores */
class CKeyStore
{
protected:
    mutable CCriticalSection cs_KeyStore;

public:
    virtual ~CKeyStore() {}

    // Add a key to the store.
    virtual bool AddKey(const CKey& key) =0;

    // Check whether a key corresponding to a given address is present in the store.
    virtual bool HaveKey(const CKeyID &address) const =0;
    virtual bool GetKey(const CKeyID &address, CKey& keyOut) const =0;
    virtual void GetKeys(std::set<CKeyID> &setAddress) const =0;
    virtual bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;

    virtual bool IsLocked() const { return false; }

    // Support for BIP 0013 : see https://en.bitcoin.it/wiki/BIP_0013
    virtual bool AddCScript(const CScript& redeemScript) =0;
    virtual bool HaveCScript(const CScriptID &hash) const =0;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const =0;

    /* Support for watch only addresses */
    virtual bool AddWatchOnly(const CScript &dest) = 0;
    virtual bool RemoveWatchOnly(const CScript &dest) = 0;
    virtual bool HaveWatchOnly(const CScript &dest) const = 0;
    virtual bool HaveWatchOnly() const = 0;

    virtual bool GetSecret(const CKeyID &address, CSecret& vchSecret, bool &fCompressed) const
    {
        CKey key;
        if (!GetKey(address, key))
            return false;
        vchSecret = key.GetSecret(fCompressed);
        return true;
    }

    // ===== Hybrid key support (forward declared in wallethybrid.h) =====
    virtual bool HaveHybridKey(const CHybridKeyID &/*address*/) const
    {
        return false;
    }

    virtual bool HaveHybridKeyByHash(const uint160 &/*keyHash*/) const
    {
        return false;
    }

    // mapHybridKeys is keyed by CHybridKeyID = Hash160(secp || mldsa), which
    // differs from the CKeyID = Hash160(secp) found in TX_HYBRID_PUBKEY and
    // TX_HYBRID_MULTISIG script solutions.
    virtual bool HaveHybridKeyByLegacyID(const CKeyID &/*keyID*/) const
    {
        return false;
    }

    virtual bool GetHybridKey(const CHybridKeyID &/*address*/, CHybridKey &/*keyOut*/) const
    {
        return false;
    }

    virtual bool GetHybridKeyByHash(const uint160 &/*keyHash*/, CHybridKey &/*keyOut*/) const
    {
        return false;
    }

    // Look up a hybrid key by its legacy ECDSA public-key hash. mapHybridKeys
    // is keyed by CHybridKeyID = Hash160(secp || mldsa), which differs from the
    // CKeyID = Hash160(secp) used in TX_HYBRID_PUBKEY / TX_HYBRID_MULTISIG
    // script solutions; the caller only has the ECDSA pubkey hash.
    virtual bool GetHybridKeyByLegacyID(const CKeyID &/*keyID*/, CHybridKey &/*keyOut*/) const
    {
        return false;
    }
};

typedef std::map<CKeyID, std::pair<CSecret, bool> > KeyMap;
typedef std::map<CScriptID, CScript > ScriptMap;
typedef std::set<CScript> WatchOnlySet;

/** Basic key store, that keeps keys in an address->secret map */
class CBasicKeyStore : public CKeyStore
{
protected:
    KeyMap mapKeys;
    ScriptMap mapScripts;
    WatchOnlySet setWatchOnly;

public:
    bool AddKey(const CKey& key);
    bool HaveKey(const CKeyID &address) const
    {
        bool result;
        {
            LOCK(cs_KeyStore);
            result = (mapKeys.count(address) > 0);
        }
        return result;
    }
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        setAddress.clear();
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.begin();
            while (mi != mapKeys.end())
            {
                setAddress.insert((*mi).first);
                mi++;
            }
        }
    }
    bool GetKey(const CKeyID &address, CKey &keyOut) const
    {
        {
            LOCK(cs_KeyStore);
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end())
            {
                keyOut.Reset();
                keyOut.SetSecret((*mi).second.first, (*mi).second.second);
                return true;
            }
        }
        return false;
    }
    virtual bool AddCScript(const CScript& redeemScript);
    virtual bool HaveCScript(const CScriptID &hash) const;
    virtual bool GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const;

    virtual bool AddWatchOnly(const CScript &dest);
    virtual bool RemoveWatchOnly(const CScript &dest);
    virtual bool HaveWatchOnly(const CScript &dest) const;
    virtual bool HaveWatchOnly() const;
};

typedef std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char> > > CryptedKeyMap;

/** Keystore which keeps the private keys encrypted.
 * It derives from the basic key store, which is used if no encryption is active.
 */
class CCryptoKeyStore : public CBasicKeyStore
{
private:
    CryptedKeyMap mapCryptedKeys;

    CKeyingMaterial vMasterKey;

    // if fUseCrypto is true, mapKeys must be empty
    // if fUseCrypto is false, vMasterKey must be empty
    bool fUseCrypto;

protected:
    bool SetCrypted();

    // will encrypt previously unencrypted keys
    bool EncryptKeys(CKeyingMaterial& vMasterKeyIn);

    bool Unlock(const CKeyingMaterial& vMasterKeyIn);

    // In-memory wallet master key. Only valid while the wallet is unlocked
    // (empty while locked). Callers must hold the wallet/keystore lock.
    const CKeyingMaterial& GetMasterKey() const
    {
        return vMasterKey;
    }

public:
    CCryptoKeyStore() : fUseCrypto(false)
    {
    }

    bool IsCrypted() const
    {
        return fUseCrypto;
    }

    virtual bool IsLocked() const
    {
        if (!IsCrypted())
            return false;
        bool result;
        {
            LOCK(cs_KeyStore);
            result = vMasterKey.empty();
        }
        return result;
    }

    virtual bool Lock();

    virtual bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    bool AddKey(const CKey& key);
    bool HaveKey(const CKeyID &address) const
    {
        {
            LOCK(cs_KeyStore);
            if (!IsCrypted())
                return CBasicKeyStore::HaveKey(address);
            return mapCryptedKeys.count(address) > 0;
        }
        return false;
    }
    bool GetKey(const CKeyID &address, CKey& keyOut) const;
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;
    void GetKeys(std::set<CKeyID> &setAddress) const
    {
        if (!IsCrypted())
        {
            CBasicKeyStore::GetKeys(setAddress);
            return;
        }
        setAddress.clear();
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        while (mi != mapCryptedKeys.end())
        {
            setAddress.insert((*mi).first);
            mi++;
        }
    }

    /* Wallet status (encrypted, locked) changed.
     * Note: Called without locks held.
     */
    boost::signals2::signal<void (CCryptoKeyStore* wallet)> NotifyStatusChanged;
};

#endif /* KEYSTORE_H */
