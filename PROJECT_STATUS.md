# PhoenixCoin Quantum – Project Status

## Current Status

The hybrid post-quantum transaction layer is implemented and functioning.

Implemented components include:

- Hybrid wallet key generation (ECDSA + ML-DSA-65)
- CHybridKeyID address format
- Hybrid address generation
- Hybrid transaction signing
- Hybrid transaction verification
- OP_DUPHYBRID
- OP_HASHHYBRID160
- OP_CHECKHYBRIDSIG
- Hybrid P2PKH scripts
- Hybrid P2PK scripts
- Hybrid multisignature support
- OpenSSL ML-DSA-65 verification
- Signature cache compatibility
- Wallet import compatibility (`wallet.dat`, `importprivkey`)
- Legacy transaction compatibility
- Hybrid wallet key pool
- Automatic hybrid change address support
- Hybrid address book support
- Hybrid key persistence in `wallet.dat`
- Hybrid transaction creation and coin selection support
- Hybrid multisig P2SH wallet spends
- P2SH spends of single-key hybrid scripts (P2PH/P2HPKH redeem scripts)
- Multi-wallet partial signing (P2SH hybrid multisig inputs keep partial script-sigs so signatures from different wallets can be combined)
- Partial-signature combining for hybrid multisig (`CombineSignatures`), capped at the required `m` pairs
- Persisted hybrid key usage (already-issued hybrid addresses are never re-issued)
- Encrypted-wallet hybrid key persistence and plaintext-to-encrypted migration
- `addhybridmultisigaddress` RPC for creating N-of-M hybrid multisig P2SH addresses
- Hybrid message signatures for `signmessage`/`verifymessage` (self-describing ECDSA + ML-DSA-65 container with both public keys embedded)
- Hybrid address support in `encryptmessage`/`decryptmessage` (ECIES over the key's secp256k1 component)
- Qt GUI Sign / Verify Message dialog accepts hybrid addresses
- Hybrid key export/import: `dumphybridkey` exports the ECDSA half as WIF and the ML-DSA-65 half as Base64 DER; `importhybridkey` re-imports both halves, validates them, and persists the key to the wallet like a wallet-generated key

## Verification

Testing on a fresh Quantum blockchain confirms that:

- Valid hybrid transactions are accepted.
- Corrupting a single byte of the ECDSA signature causes verification failure.
- Corrupting a single byte of the ML-DSA signature causes verification failure.
- Corrupting the ML-DSA public key causes verification failure.
- Both signatures are mandatory; there is no legacy fallback.
- Legacy transactions continue to verify using the original ECDSA path.
- Legacy-to-hybrid transactions confirm successfully.
- Hybrid-to-hybrid transactions confirm successfully.
- Hybrid change outputs are generated correctly.
- Multiple hybrid transactions can be included in the same block.
- Hybrid transactions propagate and validate normally across the network.
- Hybrid transactions are mined successfully by both internal and external miners.
- Single hybrid keys are spendable inside P2SH (1-of-1 hybrid multisig) on-chain.
- Encrypted wallets sign hybrid transactions end-to-end (encrypt → lock → unlock → sign → broadcast), with keys persisting across daemon restarts.

## Automated Test Suite

`src/test/hybrid_multisig_tests.cpp` provides the hybrid unit/regression suite (26 test cases) inside the full Boost suite, which reports **104 test cases** and passes with no errors (the legacy script/multisig/transaction/P2SH/miner/DoS suites are re-enabled alongside). Coverage:

- ML-DSA signer serialization edge cases (v1/v2 `FromSerialized*`), including regression coverage for `FromSerializedV2` rejecting valid provider-created keys
- Hybrid-key disk-format tampering resistance (`FromLegacyDiskFormat` strict field guards on truncated/corrupted records)
- Encrypted ML-DSA serialization round-trip (standalone `test_encrypted_keys` check)
- Hybrid multisig IsMine and spend generation
- Hybrid multisig P2SH spends
- Hybrid signature-hash types
- Encrypted-locked-wallet hybrid output recognition (`IsMine`)
- Disjoint partial-signature combining into a redeemable script
- Combined signatures capped at the required `m`
- m-of-n signature combination matrix (1/2/3-of-3, plus under-signed negative cases)
- Signature pair ordering enforcement and cross-key mismatch rejection
- Missing, malformed, and extra signature argument rejection
- Wallet unlock failures keeping the wallet locked
- Hybrid-key plaintext-to-encrypted serialization migration
- Hybrid multisig script size limits (n-required and key-count bounds)
- Combination rejecting signature pairs with valid ECDSA but invalid ML-DSA halves
- Single-signer tamper rejection (ECDSA, ML-DSA, and ML-DSA public-key corruption)
- P2HPKH (hybrid mining coinbase) spend path
- `OP_CHECKHYBRIDSIGVERIFY`
- Hybrid-key pool invariants (`EnsureHybridKeyPool`/`GetUnusedHybridKey`, uniqueness, locked-wallet refusal)
- Hybrid address round trip and Base58 corruption
- `ValidateHybridKey` negatives
- `VerifyHybridSignature` in isolation
- Hybrid message signature round trip and address re-derivation
- Hybrid message verification negatives (wrong address, tampered magic/version/ECDSA/ML-DSA regions, wrong pubkey length, truncation, trailing garbage)
- Hybrid ECIES encrypt/decrypt round trip (wrong-key and tampered-ciphertext rejection, validating the `CHybridKey::GetCKey()` ECDH fix on `decryptmessage`)
- Hybrid key export/import round trip (WIF + Base64-DER → re-parse, validate, wallet `LoadHybridKey` path, identity and signing reproduced)
- Malformed-`HYBS` matrix (every truncation prefix, bad magic/version, wrong ECDSA-pubkey length, ML-DSA pubkey/signature length fields at 0/1/short/long/`0xFFFF`, trailing bytes, 64 KiB zero buffers) asserting clean failure with no partially accepted/partially populated parser output
- `CKey` copy/move lifetime (`key_copy_move_lifetime` in `key_tests.cpp`): refcounted-PKEY sharing across copies, move/swaps, self-assignments, and ECIES decrypts performed after the source keys were destroyed — the whole `decryptmessage` (`key = GetCKey()`) regression family
- `CKey` copy/move under legacy transaction signing (`key_copy_move_legacy_signing` in `key_tests.cpp`): a keystore churning the signing key through every copy/move pathway drives `SignSignature` on P2PKH/P2PK outputs, asserting `VerifySignature`, serialization round-trip, and repeated-signing stability; it crashes (SIGSEGV) under the pre-fix shallow-copy CKey
- `CKey` copy/move under hybrid transaction signing (`key_copy_move_hybrid_signing` in `hybrid_multisig_tests.cpp`): the same churn drives `SignHybridTx` on P2PH, P2HPKH, hybrid-multisig and P2SH-wrapped outputs; every scriptSig verifies, the ECDSA half is re-sign stable, and it crashes (SIGSEGV) under the pre-fix shallow-copy CKey. This test surfaced and pins a `SignHybridTx` append bug (the output scriptSig was filled incrementally, so re-signing accumulated stale signatures) — now cleared at the start of the call

Build and run with:

```bash
cd src
make -j$(nproc) STATIC=1 -f Makefile.linux test_phoenixcoin
./test_phoenixcoin
```

Four libFuzzer targets (`fuzz_MLDSASigner_deserialize`, `fuzz_encrypted_keys`, `fuzz_hybrid_verify`, `fuzz_hybrid_message_parse`) build and run cleanly under Clang with ASan/UBSan; `fuzz_hybrid_message_parse` fuzzes the pure v1 `HYBS` parser extracted into `src/hs/hybrid_message.{h,cpp}`. See `fuzzREADME.md` at the repository root.

## Consensus

The Quantum client is **not consensus-compatible** with the historical PhoenixCoin network.

Legacy nodes do not recognize:

- OP_DUPHYBRID
- OP_HASHHYBRID160
- OP_CHECKHYBRIDSIG
- Hybrid output types

A coordinated hard fork is therefore required for network deployment.

## Mining

Testing on a fresh Quantum blockchain confirms:

- The built-in CPU miner successfully mines hybrid transactions.
- External CPU miners successfully mine hybrid transactions.
- External GPU miners successfully mine hybrid transactions.
- P2Pool successfully mines hybrid transactions.
- Hybrid transactions require no miner-side modifications.
- Hybrid transactions require no P2Pool modifications.
- Hybrid transaction validation remains entirely consensus-side.
- Existing mining infrastructure remains compatible after the Quantum fork.

## Current Limitations

### Network Deployment

The Quantum client requires a coordinated hard fork before deployment on an existing PhoenixCoin network.

Historical PhoenixCoin nodes will reject Quantum blocks because they do not understand the new hybrid opcodes and script types.

### Wallet Features

Future improvements may still include:

- Hybrid wallet recovery/backup tooling beyond key import/export
- Additional wallet recovery tools
- Additional RPC functionality
- User interface integration

Known limitation: `encryptmessage` to a hybrid address requires the wallet to hold the hybrid key (hybrid public keys are not stored in a public-only index), so an encrypted, locked wallet cannot encrypt to a hybrid address even though encryption only needs the public key; `verifymessage` is unaffected and needs no wallet at all.

These items are wallet improvements only and do not affect consensus.

## Next Phase

Automated testing is complete: the Boost unit suite passes all 104 test cases with no errors, and the four libFuzzer targets build and run cleanly under Clang with AddressSanitizer/UBSan, including fuzzing of the isolated v1 `HYBS` container parser.

Remaining work focuses on:

- Define the Quantum hard fork height.
- Release Quantum node software.
- Release updated wallet binaries.
- Coordinate network activation.

## Summary

The hybrid cryptographic implementation is complete and operational.

Hybrid transactions are fully functional, consensus-enforced, wallet-supported, and successfully mined by the internal miner, external miners, and P2Pool without requiring modifications to mining software.

The remaining work is primarily related to wallet improvements, release preparation, and coordinated network deployment through a hard fork.
