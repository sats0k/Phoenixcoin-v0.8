#include "hs/hybrid_signer.h"

#include <cstdio>

static bool check(bool condition, const char* message)
{
    if (!condition)
        std::fprintf(stderr, "FAIL: %s\n", message);
    return condition;
}

int main()
{
    const std::vector<uint8_t> password = {
        't', 'e', 's', 't', '-', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
    };

    const std::vector<uint8_t> wrong_password = {
        'w', 'r', 'o', 'n', 'g'
    };

    /*
     * 1. Generate a real ML-DSA-65 key.
     */
    auto original = MLDSASigner::GenerateNew();

    if (!check(original != nullptr, "ML-DSA key generation"))
        return 1;

    /*
     * Keep the original public/private serialization so that the
     * decrypted key can be compared byte-for-byte after the round trip.
     */
    const std::vector<uint8_t> original_public =
        original->GetPublicKey();

    const std::vector<uint8_t> original_private =
        original->SerializePrivateKey();

    if (!check(!original_public.empty(),
               "original public key is not empty"))
        return 1;

    if (!check(!original_private.empty(),
               "original private serialization is not empty"))
        return 1;

    /*
     * 2. Encrypt the private key.
     */
    const std::vector<uint8_t> encrypted =
        original->SerializePrivateKeyEncrypted(password);

    if (!check(!encrypted.empty(),
               "encrypted serialization is not empty"))
        return 1;

    /*
     * v3 encrypted format:
     *
     *   HYBK
     *   version
     *   HYBS
     *   sig_version
     *   salt
     *   nonce
     *   ciphertext
     *   GCM tag
     */
    const size_t expected_header =
        4 + 1 + 4 + 1 + ENC_SALT_LEN + ENC_NONCE_LEN + ENC_TAG_LEN;

    if (!check(encrypted.size() > expected_header,
               "encrypted serialization has expected minimum size"))
        return 1;

    if (!check(encrypted[0] == 'H' &&
               encrypted[1] == 'Y' &&
               encrypted[2] == 'B' &&
               encrypted[3] == 'K',
               "encrypted serialization has HYBK magic"))
        return 1;

    if (!check(encrypted[4] == HYBRID_VERSION_ENC,
               "encrypted serialization has version 3"))
        return 1;

    /*
     * 3. Deserialize using the correct password.
     */
    auto restored =
        MLDSASigner::FromEncryptedSerialized(password, encrypted);

    if (!check(restored != nullptr,
               "encrypted private key deserialization"))
        return 1;

    /*
     * 4. Public key must survive the round trip unchanged.
     */
    const std::vector<uint8_t> restored_public =
        restored->GetPublicKey();

    if (!check(restored_public == original_public,
               "public key survives encrypted round trip"))
        return 1;

    /*
     * 5. Raw private serialization must also survive unchanged.
     */
    const std::vector<uint8_t> restored_private =
        restored->SerializePrivateKey();

    if (!check(restored_private == original_private,
               "private key survives encrypted round trip"))
        return 1;

    /*
     * 6. Verify that the restored key is actually usable.
     */
    const std::vector<uint8_t> message = {
        'p', 'h', 'o', 'e', 'n', 'i', 'x',
        '-', 'q', 'u', 'a', 'n', 't', 'u', 'm'
    };

    std::vector<uint8_t> signature;

    if (!check(restored->Sign(message, signature),
               "restored key can sign"))
        return 1;

    if (!check(!signature.empty(),
               "restored signature is not empty"))
        return 1;

    if (!check(restored->Verify(message, signature),
               "restored key can verify its signature"))
        return 1;

    /*
     * 7. Wrong password must fail authentication.
     */
    auto wrong =
        MLDSASigner::FromEncryptedSerialized(
            wrong_password, encrypted);

    if (!check(wrong == nullptr,
               "wrong password is rejected"))
        return 1;

    /*
     * 8. Modifying the ciphertext must fail AES-GCM authentication.
     *
     * The first 4 + 1 + 4 + 1 + salt + nonce bytes are the header.
     * Flip a byte in the ciphertext instead.
     */
    std::vector<uint8_t> tampered = encrypted;

    const size_t ciphertext_offset =
        4 + 1 + 4 + 1 + ENC_SALT_LEN + ENC_NONCE_LEN;

    if (!check(tampered.size() >
                   ciphertext_offset + ENC_TAG_LEN,
               "encrypted data contains ciphertext"))
        return 1;

    tampered[ciphertext_offset] ^= 0x01;

    auto corrupted =
        MLDSASigner::FromEncryptedSerialized(
            password, tampered);

    if (!check(corrupted == nullptr,
               "modified ciphertext is rejected"))
        return 1;

    OutputDebugStringF("Encrypted ML-DSA serialization round-trip: PASS\n");
    return 0;
}
