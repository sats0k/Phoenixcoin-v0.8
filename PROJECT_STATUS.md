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
- Partial-signature combining for hybrid multisig (`CombineSignatures`)
- Encrypted-wallet hybrid key persistence and plaintext-to-encrypted migration
- `addhybridmultisigaddress` RPC for creating N-of-M hybrid multisig P2SH addresses

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

## Automated Test Suite

`src/test/hybrid_multisig_tests.cpp` provides the hybrid unit/regression suite (17 test cases) inside the full Boost suite, which reports **90 test cases** and passes with no errors. Coverage:

- ML-DSA signer serialization edge cases (v1/v2 `FromSerialized*`), including regression coverage for `FromSerializedV2` rejecting valid provider-created keys
- Hybrid-key disk-format tampering resistance (`FromLegacyDiskFormat` strict field guards on truncated/corrupted records)
- Encrypted ML-DSA serialization round-trip (standalone `test_encrypted_keys` check)
- Hybrid multisig IsMine and spend generation
- Hybrid multisig P2SH spends
- Hybrid signature-hash types
- Encrypted-locked-wallet hybrid output recognition (`IsMine`)
- Disjoint partial-signature combining into a redeemable script
- m-of-n signature combination matrix (1/2/3-of-3, plus under-signed negative cases)
- Signature pair ordering enforcement and cross-key mismatch rejection
- Missing, malformed, and extra signature argument rejection
- Wallet unlock failures keeping the wallet locked
- Hybrid-key plaintext-to-encrypted serialization migration
- Hybrid multisig script size limits (n-required and key-count bounds)
- Combination rejecting signature pairs with valid ECDSA but invalid ML-DSA halves

Build and run with:

```bash
cd src
make -j$(nproc) STATIC=1 -f Makefile.linux test_phoenixcoin
./test_phoenixcoin
```

Three libFuzzer targets (`fuzz_MLDSASigner_deserialize`, `fuzz_encrypted_keys`, `fuzz_hybrid_verify`) build and run cleanly under Clang with ASan/UBSan; see `fuzzREADME.md` at the repository root.

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

- Hybrid key usage tracking (`fUsed`)
- Hybrid key export/import improvements
- Additional wallet recovery tools
- Additional RPC functionality
- User interface integration

These items are wallet improvements only and do not affect consensus.

## Next Phase

Automated testing is complete: the Boost unit suite passes all 90 test cases with no errors, and the three libFuzzer targets build and run cleanly under Clang with AddressSanitizer/UBSan.

Remaining work focuses on:

- Define the Quantum hard fork height.
- Finalize wallet usability improvements, including hybrid support in message RPCs (`signmessage`/`verifymessage`/`encryptmessage`/`decryptmessage` currently reject hybrid addresses).
- Release Quantum node software.
- Release updated wallet binaries.
- Coordinate network activation.

## Summary

The hybrid cryptographic implementation is complete and operational.

Hybrid transactions are fully functional, consensus-enforced, wallet-supported, and successfully mined by the internal miner, external miners, and P2Pool without requiring modifications to mining software.

The remaining work is primarily related to wallet improvements, release preparation, and coordinated network deployment through a hard fork.
