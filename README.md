# Phoenixcoin Quantum

**Phoenixcoin (PXC) — Hybrid Post-Quantum Cryptography**

> **Development / pre-release branch — not compatible with the historical Phoenixcoin network.**

Phoenixcoin Quantum is a development version of Phoenixcoin that adds a **hybrid post-quantum transaction system** combining the existing **ECDSA/secp256k1** signature scheme with **ML-DSA-65** (formerly known as Dilithium) signatures.

The objective is to provide a transition path from classical public-key cryptography to post-quantum cryptography while retaining the existing Phoenixcoin transaction model and compatibility with legacy ECDSA transactions.

A coordinated network upgrade / hard fork is required before Quantum can be deployed on the historical Phoenixcoin network.

---

## Phoenixcoin

Phoenixcoin (PXC) is a decentralized open-source digital currency based on Bitcoin and operating on its own blockchain.

Originally released in May 2013, Phoenixcoin uses NeoScrypt proof-of-work and maintains the original Phoenixcoin monetary and blockchain characteristics.

### Base network characteristics

* NeoScrypt proof-of-work
* N = 128, r = 2, p = 1
* Approximately 98 million maximum coins
* 1.5 minute target block interval
* 3.125 PXC block reward
* Block reward halving every 1 million blocks
* Difficulty retarget every 20 blocks
* Approximately 30 minute retarget interval
* Maximum retarget change: +5% / -2%
* Advanced averaging using 100 + 500 block windows
* Advanced checkpointing
* Default P2P port: `9555`
* Default RPC port: `9554`

---

# Quantum Hybrid Cryptography

Phoenixcoin Quantum introduces a **dual-signature authentication model**.

Each hybrid spend is authenticated by:

1. **ECDSA over secp256k1**
2. **ML-DSA-65**

Both signatures are mandatory.

A hybrid transaction is valid only when **both cryptographic components verify successfully**.

This is an important distinction from systems that merely offer an optional post-quantum signature. Quantum's hybrid transaction type is consensus-enforced: failure of either signature causes script verification to fail.

### Security model

The hybrid construction is intended to preserve security if either the classical or post-quantum assumption remains secure.

Conceptually:

```text
                 Transaction
                     |
                SignatureHash
                     |
              Hybrid message
                /         \
               /           \
        ECDSA/secp256k1   ML-DSA-65
               \           /
                \         /
                 Both must
                   verify
                     |
                  VALID
```

---

# ML-DSA-65

The post-quantum component uses **ML-DSA-65**, the standardized successor to the Dilithium family.

The implementation uses the OpenSSL EVP interface for ML-DSA key generation and signature verification.

### ML-DSA-65 parameters used by the transaction layer

| Parameter            |        Size |
| -------------------- | ----------: |
| Raw public key       | 1,952 bytes |
| Raw signature        | 3,310 bytes |
| Algorithm identifier |      `0x02` |

The classical public key remains a compressed 33-byte secp256k1 public key.

Consequently, hybrid transactions are substantially larger than traditional ECDSA-only transactions. This is an expected property of post-quantum signatures and must be considered when evaluating transaction size, bandwidth, storage, and fees.

---

# Hybrid Signature Construction

Hybrid signatures use a domain-separated message derived from the transaction signature hash.

The transaction signature hash is computed once and then used by both cryptographic components.

The design is:

```text
transaction
     |
     v
SignatureHash
     |
     +----------------------+
     |                      |
     v                      v
 ECDSA/secp256k1       Hybrid message
     |                      |
     |                  ML-DSA-65
     |                      |
     +----------+-----------+
                |
        both signatures
          must verify
```

The ECDSA component signs the transaction hash.

The ML-DSA component signs the domain-separated hybrid message.

The domain separation prevents the two signature mechanisms from being treated as interchangeable signatures over unrelated contexts.

---

# Hybrid Addresses

Quantum introduces a dedicated hybrid address type.

A hybrid public key contains:

```text
ECDSA public key
+
ML-DSA-65 public key
```

The hybrid identifier is derived from the serialized hybrid public key.

The implementation provides:

* Hybrid address generation
* Hybrid address parsing
* Hybrid key identifiers
* Hybrid public-key serialization
* Hybrid wallet key storage
* Hybrid address-book support
* Hybrid key pools
* Hybrid change addresses

Hybrid addresses are therefore distinct from traditional Phoenixcoin ECDSA addresses.

---

# Hybrid Scripts

Quantum adds dedicated script types for hybrid public keys and hybrid public-key hashes.

Supported script classifications include:

```text
TX_HYBRID_PUBKEY
TX_HYBRID_PUBKEYHASH
TX_HYBRID_MULTISIG
```

The script system also introduces hybrid-specific operations including:

```text
OP_CHECKHYBRIDSIG
OP_CHECKHYBRIDSIGVERIFY
OP_CHECKMULTIHYBRIDSIG
OP_HASHHYBRID160
OP_DUPHYBRID
```

These operations are part of the Quantum consensus rules.

Hybrid mining coinbases (`-minehybrid`) spend to a
Pay-to-Hybrid-Public-Key-Hash (P2HPKH) template:

```text
OP_DUPHYBRID OP_HASHHYBRID160 <Hash160(pubEC || pubML)>
OP_EQUALVERIFY OP_CHECKHYBRIDSIG
```

Because the script only commits to the hybrid key hash, the spender must
reveal both public keys on the stack: the script-sig is
`<sigEC> <sigML> <pubEC> <pubML>`, with `OP_DUPHYBRID` duplicating the two
public keys before they are hashed.

Legacy Phoenixcoin nodes do not understand these opcodes or hybrid output types.

---

# Hybrid Multisignature

Quantum also supports hybrid multisignature transactions.

Hybrid multisig combines the existing multisignature transaction model with hybrid public keys.

The implementation supports:

* M-of-N hybrid multisig
* Hybrid public-key scripts with hybrid P2PK/P2PKH outputs
* Hybrid signature verification
* Consensus enforcement of both signature algorithms
* Combined signing (every script element is an `[ECDSA][ML-DSA]` signature pair)
* Partial-signature combining (disjoint partial script-sigs are merged by `CombineSignatures` into a complete redeemable script, each `[ECDSA][ML-DSA]` pair verified against the script's hybrid keys before merging)
* Multi-wallet partial signing (P2SH hybrid multisig inputs keep partial script-sigs, so signatures produced by different wallets can be combined)
* Combined script-sigs capped at exactly the `m` required pairs (surplus matched pairs are dropped, keeping the merged script spendable and standard)
* Pay-to-script-hash wrapping (hybrid multisig scripts — and single-key hybrid P2PH/P2HPKH scripts — are spent as P2SH outputs)

Each signature element in a hybrid multisig script-sig is a pair of an ECDSA signature followed by an ML-DSA signature over the same hybrid message. Both halves must verify for the script to pass consensus.

---

# Hybrid Message Signatures

`signmessage` / `verifymessage` accept hybrid addresses and sign arbitrary text messages:

* `signmessage <hybrid-address> <message>` returns a Base64-encoded, self-describing container holding both the ECDSA and the ML-DSA-65 signature.
* `verifymessage <hybrid-address> <signature> <message>` recomputes the hybrid address from the two public keys embedded in the container and verifies both signatures — no wallet access is required.

The v1 message-signature container (`HYBS`) is:

```text
Magic          "HYBS"                4 bytes
Version        1                     1 byte
Signature      ECDSA compact        65 bytes
EC pubkey      compressed           33 bytes
ML-DSA pubkey length (u16 BE)
ML-DSA pubkey                        1,952 bytes
ML-DSA signature length (u16 BE)
ML-DSA signature                     3,310 bytes
```

The ECDSA component signs the standard Bitcoin-style message hash over `"Phoenixcoin Signed Message:\n" || message`; the ML-DSA component signs the same prefixed message through the domain-separated hybrid message construction (`"BIT-HYBRID-SIG-v1" || "Phoenixcoin Signed Message:\n" || message`), matching the transaction-layer asymmetry.

Both public keys are embedded because ML-DSA signatures cannot recover the signer's public key.

`encryptmessage` / `decryptmessage` also accept hybrid addresses: `encryptmessage` encrypts to the hybrid key's secp256k1 public component (ECIES), and `decryptmessage` (which requires an unlocked wallet) decrypts with the matching private key.

The Qt wallet's Sign / Verify Message dialog (Tools > Sign/Verify Message) also accepts hybrid addresses and uses the same container format.

---

# Wallet Support

The Quantum wallet has native support for hybrid keys.

Implemented functionality includes:

* Hybrid key generation
* Hybrid key pools
* Hybrid key persistence
* Hybrid address generation
* Hybrid address-book entries
* Hybrid transaction creation
* Hybrid coin selection
* Hybrid change addresses
* Hybrid key lookup
* Hybrid key import compatibility
* Hybrid private-key serialization
* Encrypted hybrid private-key serialization
* Persisted hybrid key usage (already-issued hybrid addresses are never re-issued)

Hybrid keys are persisted in `wallet.dat`.

The wallet maintains the classical secp256k1 component together with the corresponding ML-DSA private key.

---

# Private-Key Protection

The hybrid key implementation supports encrypted private-key serialization.

The encrypted format uses:

* PBKDF2-HMAC-SHA256
* 200,000 PBKDF2 iterations
* Random 128-bit salt
* AES-256-GCM
* Random 96-bit nonce
* 128-bit authentication tag
* Versioned serialization format

Modification of authenticated encrypted-key data causes decryption to fail.

See [`SECURITY.md`](SECURITY.md) for the detailed cryptographic security model.

---

# Legacy Transaction Compatibility

Quantum retains the original ECDSA transaction path.

Therefore the client can validate:

* Legacy ECDSA transactions
* Hybrid transactions
* Legacy-to-hybrid transactions
* Hybrid-to-hybrid transactions

Legacy transactions continue to use the existing secp256k1/ECDSA verification path.

Hybrid transactions do **not** have a legacy-signature fallback.

If a hybrid transaction requires both ECDSA and ML-DSA signatures, both must be valid.

---

# Consensus

The current development configuration activates hybrid consensus at:

```text
HYBRID_ACTIVATION_HEIGHT = 0
```

This is appropriate for the dedicated Quantum development/test chain but **must not be interpreted as a deployment height for the historical Phoenixcoin network**.

Before deployment to an existing network, a coordinated activation height and complete fork plan must be defined.

### Important compatibility warning

The Quantum client is **not consensus-compatible with historical Phoenixcoin nodes**.

Historical nodes do not recognize the new hybrid script types and opcodes.

Consequently:

> **A coordinated hard fork is required before Quantum can be deployed to the historical Phoenixcoin network.**

Do not connect experimental Quantum nodes to a production historical Phoenixcoin network unless the network has explicitly activated the Quantum consensus rules.

---

# Mining

Hybrid transactions are validated entirely by the node's consensus and script-validation layer.

Testing of the Quantum implementation has demonstrated hybrid transaction mining with:

* The built-in CPU miner
* External CPU miners
* External GPU miners
* P2Pool

No miner-side modification is required merely to include hybrid transactions.

The same applies to P2Pool: hybrid transaction validation remains the responsibility of the Quantum node.

---

# Cryptographic Components

The Quantum implementation currently uses:

| Component         | Purpose                                  |
| ----------------- | ---------------------------------------- |
| secp256k1         | Classical public-key cryptography        |
| ECDSA             | Classical transaction signatures         |
| ML-DSA-65         | Post-quantum transaction signatures      |
| OpenSSL EVP       | ML-DSA key/signature interface           |
| OpenSSL providers | Cryptographic algorithm/provider support |
| NeoScrypt         | Proof of work                            |
| LevelDB           | Blockchain/wallet database storage       |

---

# Software Requirements

The Quantum branch requires a modern cryptographic environment.

Minimum versions used by this development branch include:

* **OpenSSL 3.5 or newer**
* **Boost 1.89 or newer**
* C++20-capable compiler

---

# Building

A typical development build starts with:

```bash
qmake
make -j$(nproc)

cd src
make -f Makefile.linux -j$(nproc)
```

The complete Phoenixcoin daemon/wallet build may additionally require the project's normal platform dependencies and build configuration.

Before attempting to build or run Quantum, verify the installed OpenSSL version:

```bash
openssl version
```

The runtime cryptographic environment must provide ML-DSA-65 support.

---

# Hybrid Key and Signature Formats

The implementation uses explicit versioned serialization formats.

Important identifiers include:

```text
HYBK    Hybrid key serialization
HYBS    Hybrid signature serialization
```

The current hybrid signature format contains:

```text
Magic
Version
Signature count
Algorithm identifier
Signature length
Signature data
...
```

The parser requires exactly two signature components for the current hybrid format:

```text
ECDSA/secp256k1
ML-DSA-65
```

Malformed lengths, unexpected algorithms, missing signatures, duplicate/missing components, and trailing data are rejected.

---

# RPC Support

The wallet exposes RPC functionality for hybrid addresses and keys.

Current hybrid-related RPC functionality includes:

```text
gethybridaddress
listhybridaddresses
gethybridkey
dumphybridkey
addhybridmultisigaddress
signmessage / verifymessage (hybrid addresses)
encryptmessage / decryptmessage (hybrid addresses)
```

`addhybridmultisigaddress <n-required> <'["hybridpubkey",...]'> [account]` creates an N-of-M hybrid multisignature P2SH address from hybrid public keys and adds it to the wallet.

Each `hybridpubkey` is the hex-encoded serialized hybrid public key (`pubkey_serialized_hex`) returned by `gethybridkey` — a 33-byte compressed secp256k1 public key followed by the 1,952-byte ML-DSA-65 public key. The hybrid private key must be present (and the wallet unlocked, if encrypted) to sign for such an address.

`dumphybridkey` is particularly sensitive because it exposes the hybrid private key material.

It should only be used in a controlled environment where the RPC interface and returned private-key data are appropriately protected.

`signmessage` and `encryptmessage` behave as usual for legacy addresses; for hybrid addresses they produce a hybrid message signature / ECIES ciphertext as described in the [Hybrid Message Signatures](#hybrid-message-signatures) section. `verifymessage` and `decryptmessage` verify/decrypt them, `verifymessage` without any wallet access. Both `signmessage` and `decryptmessage` require the wallet to hold the hybrid private key (and an unlocked wallet if encrypted).

---

# Testing and Validation

The Quantum branch includes dedicated hybrid and fuzz-testing sources.

Testing has covered:

* Hybrid key generation
* Hybrid signature generation
* Hybrid signature verification
* Invalid ECDSA signatures
* Invalid ML-DSA signatures
* Invalid ML-DSA public keys
* Malformed hybrid serialization
* Encrypted private-key serialization
* Legacy transaction verification
* Hybrid transaction verification
* Hybrid change generation
* Hybrid transaction propagation
* Hybrid transaction mining
* Hybrid multisignature transactions
* Hybrid multisig P2SH wallet spends
* Partial-signature combining for hybrid multisig
* Hybrid multisig m-of-n signature combinations
* Hybrid signature pair ordering and cross-key mismatch rejection
* Missing, malformed, and extra hybrid signature arguments
* Wallet encryption unlock-failure handling
* Hybrid-key plaintext-to-encrypted migration
* Hybrid multisig script size limits (n-required and key-count bounds)
* Hybrid multisig combination rejecting invalid ML-DSA halves
* Combined signatures capped at the required `m`
* Hybrid-key pool invariants (top-ups, uniqueness, locked-wallet refusal)
* Hybrid address round trip and Base58 corruption
* `ValidateHybridKey` negatives
* `VerifyHybridSignature` in isolation (size guards, sighash-type mismatch, `nHashType` enforcement)
* Hybrid-key disk-format tampering and legacy-record parsing guards
* P2HPKH (hybrid mining coinbase) spend path
* `OP_CHECKHYBRIDSIGVERIFY`
* Single-signer tamper rejection
* ML-DSA signer serialization edges
* Hybrid message signature round trip and negative/tamper cases
* Hybrid ECIES encrypt/decrypt round trip for hybrid keys

An automated unit-test suite covers these scenarios under `src/test/hybrid_multisig_tests.cpp` (25 test cases), alongside the re-enabled legacy Boost suites (script, multisig, transaction, P2SH, miner, DoS); the full suite reports **99 test cases** and passes with no errors:

```bash
cd src
make -j$(nproc) STATIC=1 -f Makefile.linux test_phoenixcoin
./test_phoenixcoin
```

The implementation has also been tested with fuzzing targets covering hybrid key deserialization, encrypted keys, and hybrid verification.

---

# Current Project Status

The hybrid post-quantum transaction layer is substantially implemented.

### Implemented

* [x] ECDSA + ML-DSA-65 hybrid keys
* [x] Hybrid addresses
* [x] Hybrid address identifiers
* [x] Hybrid wallet key generation
* [x] Hybrid wallet key persistence
* [x] Hybrid key pool
* [x] Hybrid address book
* [x] Hybrid transaction signing
* [x] Hybrid transaction verification
* [x] Hybrid P2PK scripts
* [x] Hybrid P2PKH scripts
* [x] Hybrid multisignature
* [x] Hybrid script opcodes
* [x] Hybrid change addresses
* [x] Hybrid coin selection
* [x] Legacy transaction compatibility
* [x] Encrypted hybrid private-key serialization
* [x] Hybrid transaction mining
* [x] P2Pool compatibility testing
* [x] Persisted hybrid key usage (used hybrid addresses never re-issued)
* [x] P2SH spends of single-key hybrid scripts
* [x] Multi-wallet partial signing of hybrid multisig
* [x] Hybrid message signing (`signmessage` / `verifymessage`)
* [x] Hybrid encrypt / decrypt message RPCs (`encryptmessage` / `decryptmessage`)
* [x] Hybrid message signing in the Qt GUI (Sign / Verify Message dialog)

### Remaining deployment work

* [ ] Finalize Quantum hard-fork activation height
* [ ] Complete network upgrade specification
* [ ] Expand automated consensus/regression testing
* [ ] Complete wallet UI integration
* [ ] Finalize key import/export tooling
* [ ] Complete release testing
* [ ] Publish production binaries
* [ ] Coordinate network activation

---

# Security Considerations

Quantum is experimental software.

The hybrid design is intended to provide protection against the eventual practical threat posed by sufficiently powerful quantum computers to classical public-key cryptography.

However, post-quantum cryptography does not make a system automatically secure.

The implementation does **not** protect against:

* Compromised systems
* Malware
* Compromised private keys
* Malicious or compromised cryptographic libraries
* Hardware side-channel attacks
* Weak wallet passwords
* Incorrect deployment or consensus configuration
* Bugs in the implementation

The ML-DSA implementation relies on the security and correctness of the underlying cryptographic provider and OpenSSL implementation.

Users should not treat the Quantum branch as production-ready merely because it uses a post-quantum algorithm.

See [`SECURITY.md`](SECURITY.md) for additional security information.

---

# Network Compatibility Warning

**Do not use this branch as a drop-in replacement for the historical Phoenixcoin client.**

The Quantum consensus rules introduce new transaction types that historical Phoenixcoin nodes cannot validate.

A network upgrade requires:

1. A defined activation height
2. Consensus-rule coordination
3. Updated node software
4. Updated wallet software
5. Mining infrastructure coordination
6. P2Pool/network coordination
7. Sufficient regression and interoperability testing

Until those conditions are satisfied, Quantum should be considered a separate development network.

---

# Project Structure

The principal Quantum components are located under:

```text
src/hs/
```

Important files include:

```text
src/hs/hybrid_signer.h
src/hs/hybrid_signer.cpp
src/hs/hybrid_verify.h
src/hs/hybrid_verify.cpp
src/hs/hybrid_script.h

src/hs/wallethybrid.h
src/hs/wallethybrid.cpp
src/hs/wallet_hybrid_address.cpp
```

Consensus and script integration is primarily implemented through:

```text
src/script.h
src/script.cpp
src/main.h
src/main.cpp
src/wallet.h
src/wallet.cpp
```

Hybrid RPC integration is implemented through the wallet/RPC sources.

Automated hybrid unit/regression tests are located under:

```text
src/test/hybrid_multisig_tests.cpp
```

---

# Development Status

This repository represents the **Phoenixcoin Quantum development branch**.

It should be treated as experimental software until the network upgrade, wallet, testing, and release processes have been completed.

For current implementation status, see:

[`PROJECT_STATUS.md`](PROJECT_STATUS.md)

For security information, see:

[`SECURITY.md`](SECURITY.md)

---

# License

Phoenixcoin is open-source software.

The original Phoenixcoin components are distributed under the licenses contained in this repository. New Quantum components retain the licensing notices included in their respective source files.

See [`LICENCE`](LICENCE) for the applicable license information.

---

# Disclaimer

This software is provided **"as is"**, without warranty of any kind.

The Quantum branch is intended for development, testing, and research into hybrid post-quantum cryptocurrency transactions.

**Do not use experimental Quantum software with funds you cannot afford to lose.**
