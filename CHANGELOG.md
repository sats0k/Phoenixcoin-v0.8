# Changelog

All notable changes to the **Phoenixcoin Quantum** development branch are documented in this file.

Phoenixcoin Quantum is a development/pre-release line that adds hybrid ECDSA + ML-DSA-65 post-quantum transactions. It is **not** consensus-compatible with the historical Phoenixcoin network until a coordinated hard fork is activated.

---

## [0.8.1] - in development

Changes since v0.8.0.

### Added

- Hybrid single-key scripts (P2PH / P2HPKH) are now signed when nested
  inside P2SH redeem scripts, not only in bare form.
- Hybrid multisig P2SH inputs keep partial script-sigs during signing, so
  different wallets can each contribute `[ECDSA][ML-DSA]` pairs and
  `CombineSignatures` merges them into a complete redeemable script
  (multi-wallet partial signing).
- `wallet` `keypoolrefill [<newsize>]` parameter restored.
- Qt GUI: runtime light/dark theme switch (sun/moon icons), Fusion style,
  Cantarell font, and a Phoenixcoin Quantum wordmark.
- Legacy upstream unit tests re-enabled against the current codebase
  (script, multisig, transaction, sigopcount, P2SH, miner, DoS),
  including a fix for a `CScript` self-assignment bug.
- New hybrid unit/regression tests (see Testing below), first on-chain
  validation of P2SH hybrid single-key spends and encrypted-wallet hybrid
  spends on a testnet blockchain.

### Changed

- Hybrid code consolidated under `src/hs`.
- Redundant `src/ecies` dropped; ECIES now lives in `key.cpp`.
- `CKey::RecoverPubKey` declared in `key.h`.
- Per-thread secp256k1 signing context freed on thread exit.

### Fixed

- `DecodeOP_N` assertion crash in the hybrid-multisig `Solver` on the
  genesis block.
- ECDH shared secret produced with the private key in the wrong byte
  order.
- `CKey::SignCompact` performed an out-of-bounds read when the key was
  unset or its secret was empty.
- `CHybridKeyDisk::FromSerializedV2` rejected every valid provider-created
  ML-DSA-65 key (`EVP_PKEY_id()` returns -1 for those keys); the redundant
  check was removed.
- `CombineHybridMultisig` now caps the merged script-sig at exactly `m`
  signature pairs; surplus matched pairs previously left the
  two-pointer matcher with unmatched signatures and made the script
  unspendable under `OP_CHECKMULTIHYBRIDSIG`.
- Used hybrid keys are persisted, so already-issued hybrid addresses are
  never re-issued.
- Hybrid key usage rolls back if the wallet DB write fails.
- Coin Control no longer guesses which output is change from the address
  book; outputs are remembered as change.
- Wallet reaccept rescans only blocks that can contain the missing
  transactions.
- `addrman` re-adds nodes missing from new buckets on `Good()` instead of
  dropping them.
- RPC socket accept failures are logged instead of silently dropped.
- `getwork()` miner state serialized across RPC handler threads.

### Removed (dead code)

- Hybrid `ParseHybridSignature` and `Secp256k1Signer`.
- Wallet helpers `ScanForWalletTransaction`, `AddReserveKey`,
  `UnlockAllCoins`, `GetWalletFile`, and the dead hybrid address-book /
  metadata helpers.
- RPC `decodescript` and `getnewpubkey` commands and the
  `ParseHashV/O` / `ParseHexV/O` helpers.
- Script `MakeSameSize`, util `LogException`, netbase
  `LookupHostNumeric` / `IsMulticast` and the `print` helpers, four dead
  checkpoint helpers, and `CKey` `VerifyCompact` /
  `SetCompressedPubKey`.

### Testing

`src/test/hybrid_multisig_tests.cpp` expanded from 12 to 22 test cases and
the full Boost suite from 90 to 95, all passing. New hybrid coverage:

- Combined signatures capped at the required `m` (regression for the
  `CombineHybridMultisig` fix).
- Hybrid-key pool invariants (`EnsureHybridKeyPool` / `GetUnusedHybridKey`
  top-ups, 1:1 legacy-to-hybrid ID lookup, locked-wallet refusal).
- Hybrid address round trip and Base58 corruption.
- `ValidateHybridKey` negatives.
- `VerifyHybridSignature` in isolation (size guards, EC/ML sighash-type
  mismatch, `nHashType` enforcement).
- Hybrid-key disk-format tampering and legacy-record parsing guard.
- P2HPKH (hybrid mining coinbase) spend path.
- `OP_CHECKHYBRIDSIGVERIFY` opcode.
- Single-signer tamper rejection.
- ML-DSA signer serialization edges (`FromSerializedV2` regression).

### Notes

- The `FromSerializedV2` type-check removal and the combiner cap do not
  change consensus: surplus signature pairs are still rejected by mempool
  standardness, since `ScriptSigArgsExpected` returns `m * 2` for hybrid
  multisig and this fork has no clean-stack rule.

---

## [0.8.0]

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

`src/test/hybrid_multisig_tests.cpp` expanded to 12 test cases:

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
- Combination rejecting signature pairs with a valid ECDSA but invalid
  ML-DSA half.

### Notes

- `GetScriptForHybridMultisig` is now defensive: n-required and key
  counts outside the `1..16` range supported by `EncodeOP_N` return an
  empty script instead of reaching the assertion in `EncodeOP_N`.
- `addhybridmultisigaddress` rejects requests with more than 16 keys or
  an n-required above 16 with an explicit error.
- `CombineHybridMultisig` now verifies BOTH signature halves of each
  candidate pair (via `VerifyHybridSignature`) before merging it into
  the combined script-sig, instead of only checking the ECDSA half.
  Signature pairs with a valid ECDSA but invalid ML-DSA component are
  no longer propagated.

---

## Core Quantum implementation (earlier on the branch)

The foundational hybrid post-quantum layer was added earlier on this branch:

- Quantum-resilient hybrid authentication combining ECDSA (secp256k1) and ML-DSA-65 (Dilithium).
- ML-DSA-65 signature verification through the OpenSSL EVP interface (OpenSSL 3.5+).
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