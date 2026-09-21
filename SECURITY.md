# Security Policy

## Overview

This project implements a **hybrid digital signature system** combining:

- ECDSA (secp256k1)
- ML-DSA-65 (post-quantum, Dilithium)

It also supports **password-encrypted private key serialization** using
AES-256-GCM with PBKDF2 key derivation.

This document describes the security assumptions, guarantees, and
responsible disclosure process.

---

## Cryptographic Design

### Signature Algorithms

| Algorithm       | Purpose                                     |
|-----------------|---------------------------------------------|
| ECDSA secp256k1 | Classical security, ecosystem compatibility |
| ML-DSA-65       | Post-quantum security                       |

Hybrid verification **requires exactly one valid signature per algorithm**.
Missing, duplicate, or malformed signatures cause verification failure.

---

### Message Construction

All signatures operate over a domain-separated message:

`"BIT-HYBRID-SIG-v1"`

- ECDSA signs the **hash** of the hybrid message
- ML-DSA signs the **raw hybrid message**

This asymmetry is intentional and consensus-critical.

---

### Private Key Encryption

Encrypted private keys use:

- PBKDF2-HMAC-SHA256 (200,000 iterations)
- Random 128-bit salt
- AES-256-GCM
- Random 96-bit nonce
- Authenticated header (magic + version)

Any modification to ciphertext, header, salt, nonce, or tag
causes decryption failure.

Encrypted hybrid key records (`CHybridKeyDisk`, version 3) are
bound to the wallet master key rather than a per-record passphrase.
They are therefore only decryptable while the wallet is unlocked
with the correct password. Converting a plaintext hybrid key to its
encrypted form also requires an unlocked wallet; attempting it while
the wallet is locked fails rather than producing an unencrypted
fallback.

---

### Hybrid Multisignature Partial Signing

Hybrid multisig script-sigs are merged in the combining layer
(`CombineSignatures`):

- Every script element is an `[ECDSA][ML-DSA]` signature pair.
- Both halves of each pair must verify — against the corresponding
  ECDSA and ML-DSA public keys present in the script — before the pair
  is accepted for combination; unverified, cross-key-mismatched, or
  invalid-ML-DSA material is never propagated.
- Combined pairs are ordered by the key index they correspond to.
- The merged script-sig is capped at exactly the `m` required pairs, so a
  combiner fed more valid pairs than the threshold still emits a
  spendable, standard input. This fork has no clean-stack rule at
  consensus time, so surplus pairs are gated by mempool standardness
  (`ScriptSigArgsExpected` = `m * 2`).
- Combined scripts must still pass the full consensus
  `VerifyScript`; combining disjoint partials never relaxes the m-of-n
  requirement, and a returned partial script-sig remains unspendable
  until the required threshold of valid pairs is present.

This prevents a combiner from inserting unverified, duplicated, or
misordered signature data into a transaction that is then relayed.

---

## Threat Model

### Defended Against

- Offline brute-force attacks on encrypted private keys
- Signature malleability (low-S normalization)
- Algorithm substitution attacks
- Parsing ambiguities / length overflows
- Timing attacks in key comparisons
- Unverified or misordered hybrid multisig partial signatures
- Post-quantum cryptanalytic attacks (via ML-DSA)

---

### Not Defended Against

- Compromised endpoints
- Malicious OpenSSL builds
- Side-channel attacks on hardware (e.g. cache attacks)
- Weak user-chosen passwords

---

## Determinism & Test Vectors

- Test vectors are generated once and committed
- No runtime RNG dependence in tests
- ML-DSA key generation uses OpenSSL DRBG
- Regenerating vectors is forbidden

---

## Fuzzing & Hardening

- All serialized inputs are length-checked
- Trailing data is rejected
- Constant-time comparisons are used for key material
- Verify-only secp256k1 context is enforced

---

## Reporting Security Issues

**Please do not open public GitHub issues for security bugs.**

Instead, report vulnerabilities to: gsats0k@gmail.com

Include:
- Description of the issue
- Impact analysis
- Proof-of-concept if available

---

## Supported Versions

Only the **latest released version** is supported with security updates.

---

## License & Disclaimer

This software is provided "as is" without warranty.
Use at your own risk in accordance with applicable laws.
