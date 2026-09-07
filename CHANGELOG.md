# Changelog

All notable changes to the **Phoenixcoin Quantum** development branch are documented in this file.

Phoenixcoin Quantum is a development/pre-release line that adds hybrid ECDSA + ML-DSA-65 post-quantum transactions. It is **not** consensus-compatible with the historical Phoenixcoin network until a coordinated hard fork is activated.

---

## [0.8.0] - in development

### Added

- Hybrid multisig P2SH wallet spend support.
- Partial-signature combining for hybrid multisig: `CombineSignatures` merges disjoint `[ECDSA][ML-DSA]` partial script-sigs into a complete redeemable script, verifying each ECDSA half against the script keys before merging.
- `addhybridmultisigaddress` RPC to create an N-of-M hybrid multisig P2SH address from hybrid public keys.
- ML-DSA-65 signature vector added to the hybrid test data loader.
- Hybrid-key plaintext-to-encrypted serialization migration (encrypted `CHybridKeyDisk` records bound to the wallet master key).

### Fixed

- Remote crash (out-of-bounds read) on unvalidated block data.
- P2SH hybrid spends could never relay (`IsStandard`/script-sig handling).
- Hybrid multisig script and signing layout.
- Hybrid multisig sighash preimage and domain separation for both the ECDSA and ML-DSA components.
- Hybrid `IsMine` for encrypted, locked wallets.
- `mapHybridKeyDisk` no longer holds plaintext hybrid key material.
- `CWallet::Lock()` leaving decrypted hybrid keys in memory.
- Hybrid key lookup by wrong ID (`mapHybridKeys` CKeyID mismatch).
- Hybrid key RPC use-after-lock.
- Wallet DB update tracking for hybrid keys.
- Stale/incorrect crypto test vectors replaced.
- ML-DSA `EVP_PKEY` ownership and exception safety.
- Encrypted-wallet hybrid private key persistence.
- Encrypted ML-DSA serialization round-trip.
- Reused output could claim a double signature; the condition is now cleared.
- Unsupported and duplicate signature algorithms are rejected.
- Real C++ data race in `EnsureMlDsaAvailable()`.
- `EVP_PKEY` reference leaks.
- Corrected the documented minimum OpenSSL version.

### Changed

- Version bumped to 0.8.0.
- Removed the dead duplicate hybrid signer `SignHybridTransaction()`.
- `Makefile.linux` now tracks test-object header dependencies (`obj-test/*.P`).

### Testing

`src/test/hybrid_multisig_tests.cpp` expanded to 11 test cases:

- Hybrid multisig `IsMine` and spend generation.
- Hybrid multisig P2SH spends.
- Hybrid signature-hash types.
- Encrypted-and-locked wallet hybrid output recognition.
- Disjoint partial-signature combining into a redeemable script.
- m-of-n signature combination matrix (1/2/3-of-3, plus under-signed negative cases).
- Signature pair ordering enforcement and cross-key mismatch rejection.
- Missing, malformed, and extra signature argument rejection.
- Wallet unlock failures keeping the wallet locked.
- Hybrid-key plaintext-to-encrypted serialization migration.
- Hybrid multisig script size limits (n-required and key-count bounds).

### Notes

- `GetScriptForHybridMultisig` is now defensive: n-required and key
  counts outside the `1..16` range supported by `EncodeOP_N` return an
  empty script instead of reaching the assertion in `EncodeOP_N`.
- `addhybridmultisigaddress` rejects requests with more than 16 keys or
  an n-required above 16 with an explicit error.

---

## Core Quantum implementation (earlier on the branch)

The foundational hybrid post-quantum layer was added earlier on this branch:

- Quantum-resilient hybrid authentication combining ECDSA (secp256k1) and ML-DSA-65 (Dilithium).
- ML-DSA-65 signature verification through the OpenSSL EVP interface (OpenSSL 3.2+).
- Hybrid address types and script templates (`OP_CHECKHYBRIDSIG`, `OP_CHECKHYBRIDSIGVERIFY`, `OP_CHECKMULTIHYBRIDSIG`, `OP_HASHHYBRID160`, `OP_DUPHYBRID`).
- M-of-N hybrid multisig via `OP_CHECKMULTIHYBRIDSIG`.
- Hybrid wallet integration: key generation, validation, key pool, automatic address allocation, change addresses, and transaction signing.
- Hybrid RPC commands (initially: `gethybridaddress`, `listhybridaddresses`, `gethybridkey`, `dumphybridkey`).
- Hybrid transaction mining support (internal and external miners, P2Pool).
- Post-quantum crypto vector harness and signature-verification optimization by reusing the transaction sighash.
- Encrypted hybrid private-key serialization.

---

## Earlier history

The branch inherits the upstream Phoenixcoin/Bitcoin 0.8-style history. See `LICENCE` for licensing, `README.md` for the full Quantum feature documentation, `SECURITY.md` for the security model, and `PROJECT_STATUS.md` for the current implementation status.