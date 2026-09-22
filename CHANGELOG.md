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
- Hybrid message signatures for `signmessage` / `verifymessage`: hybrid
  addresses now produce and verify a self-describing v1 `HYBS` container
  (ECDSA compact signature, ECDSA pubkey, ML-DSA-65 pubkey, ML-DSA-65
  signature). Both public keys are embedded because ML-DSA has no key
  recovery; verification recomputes the hybrid address from the embedded
  keys and requires no wallet access.
- `encryptmessage` / `decryptmessage` accept hybrid addresses, encrypting
  to / decrypting with the hybrid key's secp256k1 component (ECIES).
- Qt GUI: the Sign / Verify Message dialog now accepts hybrid addresses
  for both signing (`SignHybridMessage`) and verification
  (`VerifyHybridMessage`), matching the RPC behavior.
- Hardened `VerifyHybridMessage`: the ML-DSA signature length field is
  now required to hold exactly the raw ML-DSA-65 size (3,309 bytes),
  matching the consensus verifier (`VerifyMLDSA`). Verification is
  rejected earlier, before any OpenSSL work.
- `importhybridkey "secp_wif" "mldsa_priv_der_b64" ["label"] [rescan]`
  imports a hybrid private key previously exported by `dumphybridkey`
  (ECDSA half as WIF, ML-DSA-65 half as Base64 DER), validates it, and
  persists it to the wallet exactly like a wallet-generated key
  (transparent for plaintext wallets, encrypted at rest for encrypted
  wallets). Returns the derived hybrid address; rescan is on by default.
- The v1 `HYBS` container parser was extracted into a pure, dependency-light
  module (`src/hs/hybrid_message.{h,cpp}`, `ParseHybridMessage`) shared by
  the message-signature path and fuzzing. The parser is transactional —
  rejected input never partially populates its outputs — and performs
  bounded reads, so a hostile `0xFFFF` length field is rejected by the
  exact-size guard before any allocation for the claimed size.
- New libFuzzer target `fuzz_hybrid_message_parse` fuzzes the pure `HYBS`
  parser with arbitrary bytes under Clang + ASan/UBSan, asserting the
  fixed-size contract and the no-partial-acceptance invariant.

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
- `CHybridKey::GetCKey()` re-published the public key after `SetPrivKey()`,
  which reset the private `EVP_PKEY` handle; any private-key-engine
  operation (e.g. ECIES decryption via `CKey::DecryptData`) then failed
  with "ECDH failed", breaking `decryptmessage` for hybrid addresses. The
  redundant `SetPubKey` call was removed and the derived public key is
  validated against `secpPub`.
- `CKey` had only implicit shallow copy semantics while owning a raw
  `EVP_PKEY*` that its destructor frees. `decryptmessage` assigns the
  result of `CHybridKey::GetCKey()` into an existing key
  (`key = hk.GetCKey();`), so the temporary's destructor freed the PKEY and
  `key` was left with a dangling pointer; `CKey::DecryptData` then
  dereferenced freed memory and segfaulted. `CKey` now has real copy/move
  semantics: copies share the underlying `EVP_PKEY` through an extra
  reference (`EVP_PKEY_up_ref`), and functions return their key without
  relying on copy elision to avoid the double-free.

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

`src/test/hybrid_multisig_tests.cpp` is at 26 test cases and the full Boost
suite passes all 104 cases. New coverage in this change:

- `key_copy_move_hybrid_signing` (`src/test/hybrid_multisig_tests.cpp`):
  CKey copy/move through the hybrid transaction signing path. A keystore
  churns the stored hybrid key's ECDSA component through copy-chain /
  move-chain / move-assign modes on every hand-out, then `SignSignature`
  drives `SignHybridTx` on P2PH, P2HPKH and hybrid-multisig outputs (and a
  P2SH wrapper); each scriptSig must verify, the ECDSA half must be
  stable across re-signs while the ML-DSA half is randomized (hedged
  signing), and the signed spend must survive serialization.
  Same as its legacy sibling it crashes (SIGSEGV) under the pre-fix
  shallow-copy CKey.

- `SignHybridTx` (fixed): now clears its `scriptSigRet` before signing.
  It filled the output by appending, so re-signing an input accumulated
  stale signature pairs (masked in tests because the deterministic ECDSA
  half re-satisfied `OP_CHECKHYBRIDSIG` from the top of the stack); the
  re-sign loop in `key_copy_move_hybrid_signing` pins it.

- `key_copy_move_legacy_signing` (`src/test/key_tests.cpp`): legacy
  transaction signing through CKey copy/move ownership. A keystore whose
  `GetKey()` rebuilds the stored secret into a fresh CKey and hands it out
  via each copy/move pathway (plain copy-assign, forced two-step copy,
  move, nested move, by-value dispatch) drives `SignSignature` on P2PKH and
  P2PK funding outputs; each produced scriptSig must pass
  `VerifySignature`, the signed transaction must round-trip through
  serialization, and re-signing after many handouts must stay stable. The
  signer key is never the object the caller created - the store keeps only
  the secret - so a shallow-copy/refcount bug double-frees the shared
  `EVP_PKEY`; this test was verified to crash (SIGSEGV) under the
  pre-fix implicit-shallow-copy CKey.

- `key_copy_move_lifetime` (`src/test/key_tests.cpp`): CKey copy/move/swap
  ownership and lifetime. Covers refcounted-PKEY copies surviving each
  other's destruction, move constructor/assignment leaving the source null
  (and a moved-from key being a safe null key), swap-based move assignment
  keeping the displaced key alive, self-assignments, `swap()` exchanging
  compressed/uncompressed state, and the `decryptmessage` regression
  (`key = GetCKey()` copy/move assignment) with ECIES decrypts performed
  through copies after their sources — including the by-value provider —
  have been destroyed. The ECIES decrypt probes are the meaningful checks
  because they exercise `EVP_PKEY_derive` on the shared PKEY, which
  `SignCompact()` (secret-only) cannot.

- Systematic malformed-`HYBS` matrix (`hybrid_message_malformed_matrix`)
  over a signed round-trip container, additionally pinned to its exact
  total size: every truncation prefix, bad magic (each magic byte), bad
  version, wrong-length ECDSA pubkey, ML-DSA pubkey-length field set to 0 /
  1 / short-by-one / long-by-one / `0xFFFF`, ML-DSA signature-length field
  set to 0 / 3308 / 3310 / `0xFFFF`, trailing bytes (including a second
  magic trailer), zero buffers up to 64 KiB, and a positive parse control.
  Each mutation must fail cleanly and, per the parser's transactional
  contract, leave `ParseHybridMessage` outputs empty.
- Hybrid message signature round trip and negative/tamper coverage
  (`hybrid_message_sign_verify`, `hybrid_message_verify_negatives`):
  valid round trip and address re-derivation via `CCoinAddress`, plus
  rejection of a wrong address, tampered message, legacy 65-byte
  signature, and single-byte corruption of the magic, version, ECDSA
  signature/pubkey, ML-DSA pubkey, an ML-DSA pubkey length, or the ML-DSA
  signature, as well as truncation, trailing garbage, and empty input.
- Hybrid ECIES encrypt/decrypt round trip for hybrid keys
  (`hybrid_message_encrypt_decrypt`): encrypt-to-secp / decrypt-with-key
  round trip, wrong-key rejection, and tampered ciphertext/tag rejection —
  regression coverage for the `CHybridKey::GetCKey()` ECDH fix.
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