// Copyright (c) 2026 sats0k
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

#include "hybrid_signer.h"

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>

#include <cassert>
#include <vector>
#include <memory>
#include <set>
#include <cstring>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

#include <secp256k1.h>

/* ------------------------------------------------------------------------- */
/*  Helpers                                                                  */
/* ------------------------------------------------------------------------- */

/*
 * Production invariants:
 *  - secp256k1 context is VERIFY-only and never mutated after initialization
 *  - ML-DSA-65 support must be present and functional at runtime
 *  - Hybrid verification requires exactly one signature per algorithm
 *  - ConstructSignatureHashPreimage() is the canonical preimage constructor
 *  - BuildHybridMessage() applies domain separation to the preimage for ML-DSA
 *  - The caller is responsible for constructing the canonical preimage.
 */

using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EVP_PKEY_ptr   = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

std::unique_ptr<MLDSASigner> MLDSASigner::GenerateNew() {

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ML_DSA_65, nullptr);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX for ML-DSA-65\n");
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &raw_pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen failed\n");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);

    EVP_PKEY_ptr pkey(raw_pkey, &EVP_PKEY_free);
    return std::make_unique<MLDSASigner>(pkey.get());
}

static void ThrowCryptoMisconfig(const char* msg) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "FATAL CRYPTO ERROR: %s\n", msg);
    throw std::runtime_error(msg);
}

static void EnsureMlDsaAvailable() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ML_DSA_65, nullptr);
        if (!ctx) {
            ThrowCryptoMisconfig("ML-DSA-65 not available in this OpenSSL build");
        }
        EVP_PKEY_CTX_free(ctx);
    });
}

static EVP_MD_CTX_ptr MakeMdCtx() {
    return EVP_MD_CTX_ptr(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
}

static bool VerifyRawPublicKey(EVP_PKEY* pkey,
                               const uint8_t* pub,
                               size_t pub_len) {
    size_t check_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &check_len) <= 0 ||
        check_len != pub_len) return false;
    std::vector<uint8_t> check(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, check.data(), &check_len) <= 0)
        return false;
    return CRYPTO_memcmp(check.data(), pub, pub_len) == 0;
}

static bool DeriveEncKey(const std::vector<uint8_t>& password,
                         const uint8_t* salt,
                         uint8_t* out_key,
                         size_t out_len) {
    return PKCS5_PBKDF2_HMAC(
        reinterpret_cast<const char*>(password.data()),
        password.size(),
        salt,
        ENC_SALT_LEN,
        200000,
        EVP_sha256(),
        out_len,
        out_key
    ) == 1;
}

static bool EncryptAesGcm(const uint8_t* key,
                          const uint8_t* nonce,
                          const std::vector<uint8_t>& aad,
                          const std::vector<uint8_t>& pt,
                          std::vector<uint8_t>& ct,
                          std::array<uint8_t, ENC_TAG_LEN>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            ENC_NONCE_LEN, nullptr) > 0 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) > 0;

    int outlen = 0;
    if (ok && !aad.empty())
        ok = EVP_EncryptUpdate(ctx, nullptr, &outlen,
                               aad.data(), aad.size()) > 0;

    ct.resize(pt.size());
    int total = 0;
    if (ok) {
        ok = EVP_EncryptUpdate(ctx, ct.data(), &outlen,
                               pt.data(), pt.size()) > 0;
        total += outlen;
    }
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, ct.data() + total, &outlen) > 0;
        total += outlen;
        ct.resize(total);
    }

    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                 tag.size(), tag.data()) > 0;

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static bool DecryptAesGcm(const uint8_t* key,
                          const uint8_t* nonce,
                          const std::vector<uint8_t>& aad,
                          const std::vector<uint8_t>& ct,
                          const uint8_t* tag,
                          std::vector<uint8_t>& pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            ENC_NONCE_LEN, nullptr) > 0 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) > 0;

    int outlen = 0;
    if (ok && !aad.empty())
        ok = EVP_DecryptUpdate(ctx, nullptr, &outlen,
                               aad.data(), aad.size()) > 0;

    pt.resize(ct.size());
    int total = 0;
    if (ok) {
        ok = EVP_DecryptUpdate(ctx, pt.data(), &outlen,
                               ct.data(), ct.size()) > 0;
        total += outlen;
    }

    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                 ENC_TAG_LEN,
                                 const_cast<uint8_t*>(tag)) > 0;

    if (ok) {
        ok = EVP_DecryptFinal_ex(ctx, pt.data() + total, &outlen) > 0;
        total += outlen;
        pt.resize(total);
    }

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static secp256k1_context* GetSecpVerifyCtx() {
    static secp256k1_context* ctx = [] {
        secp256k1_context* c =
            secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);


        /* VERIFY-only context: must never be used for signing */
        static_assert(SECP256K1_CONTEXT_VERIFY == SECP256K1_CONTEXT_VERIFY,
                      "secp256k1 VERIFY context invariant violated");

        unsigned char seed[32];
        if (RAND_bytes(seed, sizeof(seed)) == 1) {
            int rc = secp256k1_context_randomize(c, seed);
            assert(rc == 1);
            OPENSSL_cleanse(seed, sizeof(seed));
        }
        return c;
    }();
    return ctx;
}

static uint256 HashHybridMessage(const std::vector<uint8_t>& msg) {
    return Hash(msg.begin(), msg.end());
}

bool ParseHybridSignature(const std::vector<unsigned char>& in,
                          std::vector<Signature>& out)
{
    out.clear();

    size_t off = 0;
    if (in.size() < 6)
        return false;

    if (memcmp(&in[off], HYBRID_SIG_MAGIC, 4) != 0)
        return false;
    off += 4;

    uint8_t ver = in[off++];
    if (ver != HYBRID_SIG_VERSION)
        return false;

    uint8_t count = in[off++];
    if (count != 2)
        return false;

    std::set<SigAlg> algsSeen;
    for (int i = 0; i < 2; i++) {
        if (off + 3 > in.size()) {
            out.clear();
            return false;
        }

        uint8_t alg = in[off++];

        if (alg != static_cast<uint8_t>(SigAlg::ECDSA_SECP256K1) &&
            alg != static_cast<uint8_t>(SigAlg::ML_DSA_65)) {
            out.clear();
            return false;
        }

        SigAlg sig_alg = static_cast<SigAlg>(alg);
        if (algsSeen.count(sig_alg) > 0) {
            out.clear();
            return false;
        }
        algsSeen.insert(sig_alg);

        uint16_t len = (uint16_t(in[off]) << 8) | uint16_t(in[off + 1]);
        off += 2;

        if (len == 0 || off + len > in.size()) {
            out.clear();
            return false;
        }

        out.push_back(Signature{
            sig_alg,
            std::vector<uint8_t>(in.begin() + off,
                                 in.begin() + off + len)
        });
        off += len;
    }

    if (off != in.size()) {
        out.clear();
        return false;
    }

    return true;
}

/* ------------------------------------------------------------------------- */
/*  Secp256k1Signer                                                          */
/* ------------------------------------------------------------------------- */

Secp256k1Signer::Secp256k1Signer(const CKey& key) : key_(key) {}

SigAlg Secp256k1Signer::Algorithm() const {
    return SigAlg::ECDSA_SECP256K1;
}

bool Secp256k1Signer::Sign(const std::vector<uint8_t>& msg,
                           std::vector<uint8_t>& sig) const {
    uint256 h = HashHybridMessage(msg);
    return key_.Sign(h, sig);
}

bool Secp256k1Signer::Verify(const std::vector<uint8_t>& msg,
                             const std::vector<uint8_t>& sig) const {
    uint256 h = HashHybridMessage(msg);

    secp256k1_context* ctx = GetSecpVerifyCtx();

    secp256k1_pubkey pubkey;
    auto pub = GetPublicKey();
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pub.data(), pub.size())) {
        return false;
    }

    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_signature_parse_der(
            ctx, &signature, sig.data(), sig.size())) {
        return false;
    }

    secp256k1_ecdsa_signature_normalize(ctx, &signature, &signature);

    return secp256k1_ecdsa_verify(ctx, &signature, h.begin(), &pubkey) == 1;
}

std::vector<uint8_t> Secp256k1Signer::GetPublicKey() const {
    return key_.GetPubKey().Raw();
}

/* ------------------------------------------------------------------------- */
/*  MLDSASigner (ML-DSA-65)                                                  */
/* ------------------------------------------------------------------------- */

MLDSASigner::MLDSASigner(EVP_PKEY* key) : pkey_(key) {
    if (!pkey_)
        ThrowCryptoMisconfig("Null EVP_PKEY passed to MLDSASigner");

    EnsureMlDsaAvailable();

    const char* type = EVP_PKEY_get0_type_name(pkey_);
    if (!type || std::string(type) != "ML-DSA-65") {
        fprintf(stderr, "MLDSA key type = %s\n", type ? type : "(null)");
        ThrowCryptoMisconfig("Invalid EVP_PKEY passed to MLDSASigner");
    }

    EVP_PKEY_up_ref(pkey_);
}

MLDSASigner::~MLDSASigner() {
    if (pkey_) EVP_PKEY_free(pkey_);
}

SigAlg MLDSASigner::Algorithm() const {
    return SigAlg::ML_DSA_65;
}

bool MLDSASigner::Sign(const std::vector<uint8_t>& msg,
                           std::vector<uint8_t>& sig) const {
    auto ctx = MakeMdCtx();
    if (!ctx) return false;

    size_t len = 0;

    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey_) <= 0 ||
        EVP_DigestSign(ctx.get(), nullptr, &len,
                       msg.data(), msg.size()) <= 0)
        return false;

    sig.resize(len);
    if (EVP_DigestSign(ctx.get(), sig.data(), &len,
                       msg.data(), msg.size()) <= 0)
        return false;
    sig.resize(len);
    return true;
}

bool MLDSASigner::Verify(const std::vector<uint8_t>& msg,
                             const std::vector<uint8_t>& sig) const {
    auto ctx = MakeMdCtx();
    if (!ctx) return false;

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey_) <= 0)
        return false;
    return EVP_DigestVerify(ctx.get(),
                            sig.data(), sig.size(),
                            msg.data(), msg.size()) == 1;
}

std::vector<uint8_t> MLDSASigner::GetPublicKey() const {
    size_t len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey_, nullptr, &len) <= 0) return {};

    std::vector<uint8_t> out(len);
    if (EVP_PKEY_get_raw_public_key(pkey_, out.data(), &len) <= 0) return {};

    out.resize(len);
    return out;
}

std::vector<uint8_t> MLDSASigner::SerializePrivateKey() const {
    size_t pub_len = 0, priv_len = 0;

    if (EVP_PKEY_get_raw_public_key(pkey_, nullptr, &pub_len) <= 0 ||
        EVP_PKEY_get_raw_private_key(pkey_, nullptr, &priv_len) <= 0) {
        return {};
    }

    std::vector<uint8_t> pub(pub_len), priv(priv_len);

    EVP_PKEY_get_raw_public_key(pkey_, pub.data(), &pub_len);
    EVP_PKEY_get_raw_private_key(pkey_, priv.data(), &priv_len);

    std::vector<uint8_t> out;
    out.reserve(1 + 2 + pub.size() + 2 + priv.size());

    out.push_back(static_cast<uint8_t>(SigAlg::ML_DSA_65));

    auto push16 = [&](uint16_t v) {
        out.push_back(v >> 8);
        out.push_back(v & 0xff);
    };

    push16(pub.size());
    out.insert(out.end(), pub.begin(), pub.end());

    push16(priv.size());
    out.insert(out.end(), priv.begin(), priv.end());

    OPENSSL_cleanse(priv.data(), priv.size());
    return out;
}

std::vector<uint8_t>
MLDSASigner::SerializePrivateKeyEncrypted(
    const std::vector<uint8_t>& password) const {

    auto pt = SerializePrivateKey();
    if (pt.empty()) return {};

    uint8_t salt[ENC_SALT_LEN];
    uint8_t nonce[ENC_NONCE_LEN];

    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        RAND_bytes(nonce, sizeof(nonce)) != 1)
        return {};

    uint8_t key[32];
    if (!DeriveEncKey(password, salt, key, sizeof(key)))
        return {};

    std::vector<uint8_t> ct;
    std::array<uint8_t, ENC_TAG_LEN> tag;

    std::vector<uint8_t> aad;
    aad.insert(aad.end(), HYBRID_MAGIC, HYBRID_MAGIC + 4);
    aad.push_back(HYBRID_VERSION_ENC);

    if (!EncryptAesGcm(key, nonce, aad, pt, ct, tag))
        return {};

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(pt.data(), pt.size());

    std::vector<uint8_t> out;
    out.insert(out.end(), HYBRID_MAGIC, HYBRID_MAGIC + 4);
    out.push_back(HYBRID_VERSION_ENC);
    out.insert(out.end(), HYBRID_SIG_MAGIC, HYBRID_SIG_MAGIC + 4);
    out.push_back(HYBRID_SIG_VERSION);
    out.insert(out.end(), salt, salt + ENC_SALT_LEN);
    out.insert(out.end(), nonce, nonce + ENC_NONCE_LEN);
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

/* ------------------------------------------------------------------------- */
/*  Fuzz-resistant parsing helpers                                           */
/* ------------------------------------------------------------------------- */

static constexpr size_t ML_DSA_65_PUB_MAX  = 2048;
static constexpr size_t ML_DSA_65_PRIV_MAX = 4096;

class Cursor {
public:
    explicit Cursor(const std::vector<uint8_t>& b) : buf(b) {}

    bool read_u8(uint8_t& v) {
        if (off + 1 > buf.size()) return false;
        v = buf[off++];
        return true;
    }

    bool read_u16(uint16_t& v) {
        if (off + 2 > buf.size()) return false;
        v = (static_cast<uint16_t>(buf[off]) << 8) |
            static_cast<uint16_t>(buf[off + 1]);
        off += 2;
        return true;
    }

    bool read_bytes(const uint8_t*& p, size_t len) {
        if (off + len > buf.size()) return false;
        p = &buf[off];
        off += len;
        return true;
    }

    bool expect_bytes(const uint8_t* v, size_t len) {
        if (off + len > buf.size()) return false;
        if (CRYPTO_memcmp(&buf[off], v, len) != 0) return false;
        off += len;
        return true;
    }

    bool done() const { return off == buf.size(); }

private:
    const std::vector<uint8_t>& buf;
    size_t off{0};
};

std::unique_ptr<MLDSASigner>
MLDSASigner::FromEncryptedSerialized(
    const std::vector<uint8_t>& password,
    const std::vector<uint8_t>& in) {

    constexpr size_t ENC_HEADER_LEN =
        4 + 1 + 4 + 1 + ENC_SALT_LEN + ENC_NONCE_LEN;

    if (in.size() < ENC_HEADER_LEN + ENC_TAG_LEN)
        return nullptr;

    Cursor c(in);

    // Outer encrypted-key header.
    if (!c.expect_bytes(HYBRID_MAGIC, 4))
        return nullptr;

    uint8_t ver;
    if (!c.read_u8(ver) || ver != HYBRID_VERSION_ENC)
        return nullptr;

    // Inner hybrid-signature header.
    if (!c.expect_bytes(HYBRID_SIG_MAGIC, 4))
        return nullptr;

    uint8_t sig_ver;
    if (!c.read_u8(sig_ver) || sig_ver != HYBRID_SIG_VERSION)
        return nullptr;

    const uint8_t* salt;
    const uint8_t* nonce;

    if (!c.read_bytes(salt, ENC_SALT_LEN) ||
        !c.read_bytes(nonce, ENC_NONCE_LEN))
        return nullptr;

    const size_t header_len = ENC_HEADER_LEN;

    if (in.size() < header_len + ENC_TAG_LEN)
        return nullptr;

    const size_t ct_len =
        in.size() - header_len - ENC_TAG_LEN;

    const uint8_t* ct;
    if (!c.read_bytes(ct, ct_len))
        return nullptr;

    const uint8_t* tag = &in[in.size() - ENC_TAG_LEN];

    uint8_t key[32];
    if (!DeriveEncKey(password, salt, key, sizeof(key)))
        return nullptr;

    std::vector<uint8_t> pt;
    std::vector<uint8_t> aad = {
        'H', 'Y', 'B', 'K', HYBRID_VERSION_ENC
    };

    std::vector<uint8_t> ciphertext(ct, ct + ct_len);

    if (!DecryptAesGcm(key, nonce, aad,
                       ciphertext, tag, pt)) {
        OPENSSL_cleanse(key, sizeof(key));
        return nullptr;
    }

    OPENSSL_cleanse(key, sizeof(key));

    auto signer = FromSerialized(pt);
    OPENSSL_cleanse(pt.data(), pt.size());
    return signer;
}

std::unique_ptr<MLDSASigner>
MLDSASigner::FromSerialized(const std::vector<uint8_t>& in) {
    Cursor c(in);

    uint8_t alg;
    EnsureMlDsaAvailable();
    if (!c.read_u8(alg) ||
        alg != static_cast<uint8_t>(SigAlg::ML_DSA_65))
        return nullptr;

    uint16_t pub_len = 0, priv_len = 0;
    if (!c.read_u16(pub_len) || pub_len == 0 || pub_len > ML_DSA_65_PUB_MAX)
        return nullptr;

    const uint8_t* pub = nullptr;
    if (!c.read_bytes(pub, pub_len))
        return nullptr;

    if (!c.read_u16(priv_len) || priv_len == 0 || priv_len > ML_DSA_65_PRIV_MAX)
        return nullptr;

    const uint8_t* priv = nullptr;
    if (!c.read_bytes(priv, priv_len))
        return nullptr;

    if (!c.done())
        return nullptr; // trailing garbage

    EVP_PKEY* pkey =
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ML_DSA_65, nullptr,
                                     priv, priv_len);
    if (!pkey || !VerifyRawPublicKey(pkey, pub, pub_len)) {
        if (pkey) EVP_PKEY_free(pkey);
        return nullptr;
    }

    try {
        auto signer = std::make_unique<MLDSASigner>(pkey);
        EVP_PKEY_free(pkey);
        return signer;
    } catch (const std::exception&) {
        if (pkey) EVP_PKEY_free(pkey);
        return nullptr;
    }
}

/* ------------------------------------------------------------------------- */
/*  v2 Serialization Parser (ML-DSA-65 only)                                 */
/* ------------------------------------------------------------------------- */

std::unique_ptr<MLDSASigner>
MLDSASigner::FromSerializedV2(const std::vector<uint8_t>& in) {
    Cursor c(in);

    /* magic */
    EnsureMlDsaAvailable();
    if (!c.expect_bytes(HYBRID_MAGIC, sizeof(HYBRID_MAGIC)))
        return nullptr;

    /* version */
    uint8_t version;
    if (!c.read_u8(version) || version != HYBRID_VERSION)
        return nullptr;

    /* algorithm */
    uint8_t alg;
    if (!c.read_u8(alg) ||
        alg != static_cast<uint8_t>(SigAlg::ML_DSA_65))
        return nullptr;

    /* flags */
    uint8_t flags;
    if (!c.read_u8(flags) || flags != 0)
        return nullptr;

    /* public key */
    uint16_t pub_len;
    if (!c.read_u16(pub_len) ||
        pub_len == 0 ||
        pub_len > ML_DSA_65_PUB_MAX)
        return nullptr;

    const uint8_t* pub;
    if (!c.read_bytes(pub, pub_len))
        return nullptr;

    /* private key */
    uint16_t priv_len;
    if (!c.read_u16(priv_len) ||
        priv_len == 0 ||
        priv_len > ML_DSA_65_PRIV_MAX)
        return nullptr;

    const uint8_t* priv;
    if (!c.read_bytes(priv, priv_len))
        return nullptr;

    /* no trailing data */
    if (!c.done())
        return nullptr;

    EVP_PKEY* pkey =
        EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ML_DSA_65, nullptr, priv, priv_len);

    if (!pkey)
        return nullptr;

    if (EVP_PKEY_id(pkey) != EVP_PKEY_ML_DSA_65 ||
        !VerifyRawPublicKey(pkey, pub, pub_len)) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    try {
        auto signer = std::make_unique<MLDSASigner>(pkey);
        EVP_PKEY_free(pkey);
        return signer;
    } catch (const std::exception&) {
        if (pkey) EVP_PKEY_free(pkey);
        return nullptr;
    }
}

/* ------------------------------------------------------------------------- */
/*  HybridSigner                                                             */
/* ------------------------------------------------------------------------- */

void HybridSigner::Add(std::unique_ptr<ISigner> signer) {
    for (const auto& s : signers_) {
        if (s->Algorithm() == signer->Algorithm())
            throw std::runtime_error("Duplicate signature algorithm added");
    }
    signers_.push_back(std::move(signer));
}

bool HybridSigner::SignAll(const std::vector<uint8_t>& msg,
                           std::vector<Signature>& sigs) const {
    sigs.clear();

    for (const auto& s : signers_) {
        Signature sig;
        sig.alg = s->Algorithm();

        if (!s->Sign(msg, sig.bytes)) return false;
        sigs.push_back(std::move(sig));
    }
    return true;
}

bool HybridSigner::VerifyAll(const std::vector<uint8_t>& msg,
                             const std::vector<Signature>& sigs) const {
    if (sigs.size() != signers_.size())
        return false;

    bool ok = true;

    for (const auto& s : signers_) {
        bool found = false;
        for (const auto& sig : sigs) {
            if (sig.alg == s->Algorithm()) {
                found = true;
                ok &= s->Verify(msg, sig.bytes);
                break;
            }
        }
        if (!found)
            ok = false;
    }

    /* burn time on duplicates / garbage */
    for (const auto& sig : sigs) {
        volatile uint8_t x = sig.bytes.empty() ? 0 : sig.bytes[0];
        (void)x;
    }

    return ok;
}

std::vector<std::vector<uint8_t>>
HybridSigner::SerializePrivateKeys() const {
    std::vector<std::vector<uint8_t>> out;
    for (const auto& s : signers_) {
        auto k = s->SerializePrivateKey();
        if (!k.empty())
            out.push_back(std::move(k));
    }
    return out;
}

/* ------------------------------------------------------------------------- */
/*  Hybrid Message Construction                                              */
/* ------------------------------------------------------------------------- */

std::vector<uint8_t>
BuildHybridMessage(const std::vector<uint8_t>& tx_sighash_preimage) {
    static constexpr uint8_t DOMAIN[] = "BIT-HYBRID-SIG-v1";

    std::vector<uint8_t> out;
    out.reserve(sizeof(DOMAIN) - 1 + tx_sighash_preimage.size());

    out.insert(out.end(), DOMAIN, DOMAIN + sizeof(DOMAIN) - 1);
    out.insert(out.end(),
               tx_sighash_preimage.begin(),
               tx_sighash_preimage.end());
    return out;
}
