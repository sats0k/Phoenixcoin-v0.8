The sources in this directory are unit test cases. Boost includes a
unit testing framework, and since Phoenixcoin already uses Boost, the
Boost Unit Test Framework is used for the project's unit tests.

The current test executable is called `test_phoenixcoin`. The main
test source file is `test_bitcoin.cpp`, which provides the Boost test
module and the common test setup. Individual test cases are implemented
in separate source files.

## Current tests

The currently enabled test sources are:

```
test_bitcoin.cpp
hybrid_multisig_tests.cpp
accounting_tests.cpp
allocator_tests.cpp
base32_tests.cpp
base58_tests.cpp
base64_tests.cpp
bignum_tests.cpp
Checkpoints_tests.cpp
DoS_tests.cpp
getarg_tests.cpp
key_tests.cpp
miner_tests.cpp
mruset_tests.cpp
multisig_tests.cpp
netbase_tests.cpp
rpc_tests.cpp
script_P2SH_tests.cpp
script_tests.cpp
sigopcount_tests.cpp
transaction_tests.cpp
uint160_tests.cpp
uint256_tests.cpp
util_tests.cpp
wallet_tests.cpp
testutil.cpp
```

`testutil.cpp` provides shared helpers (e.g. `read_json`) for the data
driven tests.

`hybrid_multisig_tests.cpp` contains tests for the hybrid multisignature
implementation: sighash types, `IsMine` detection and direct spending of
hybrid multisig scripts, spending via P2SH-wrapped hybrid multisig
(redeem script) transactions, `IsMine` behavior for locked (encrypted)
wallets, merging of partial hybrid multisig signatures via
`CombineSignatures` (direct and P2SH-wrapped), an m-of-n matrix
(1/2/3-of-3) covering positive and under-signature cases, and
ECDSA/ML-DSA pair ordering with cross-key mismatch rejection, plus
malformed/missing/extra signature argument handling (consensus rejection
for under-supplied or invalid signature arguments, and standardness
rejection for surplus arguments. A wallet-crypto test
(`wallet_crypto_unlock_failure_keeps_locked`) verifies the real
encrypted-wallet `Unlock` path: a wrong passphrase leaves the wallet
locked and the keys inaccessible, a correct passphrase unlocks it, and
re-locking clears the master key again. A hybrid-key migration test
(`hybrid_key_plaintext_to_encrypted_migration`) verifies that plaintext
in-memory hybrid keys convert to checksummed, encrypted at-rest
`CHybridKeyDisk` records: no plaintext leakage, round-trip decryption with
the wallet master key, checksum/tamper detection, refusal without an
unlocked master key (locked-wallet `MakeHybridKeyDisk` throws), and the
plaintext-wallet path that keeps records unencrypted. A script-size-limits
test (`hybrid_multisig_script_size_limits`) verifies that
`GetScriptForHybridMultisig` rejects n-required and key counts outside the
`1..16` range (`EncodeOP_N` assertion) by returning an empty script instead
of crashing, including the positive 16-key boundary. A combine test
(`hybrid_multisig_combine_rejects_invalid_mldsa`) verifies that the
combining layer requires BOTH the ECDSA and the ML-DSA half of each
candidate pair to verify (`VerifyHybridSignature`) before accepting it, so
a pair with a valid ECDSA but invalid ML-DSA signature is never propagated
into the combined scriptSig. A combining-cap regression test
(`hybrid_multisig_combine_caps_sigs_at_m`) pins the combiner output to
exactly `nMa` signature pairs: a 2-of-3 spent by two partials carrying 1 + 2
= 3 valid pairs between them must emit only the first `nMa` matched pairs,
in key order, the 2-pair result must verify through both the bare and the
P2SH paths and be a standard input, and a surplus pair makes the input
non-standard (`ScriptSigArgsExpected` returns `nMa * 2`). It also documents
that this fork has no clean-stack rule, so extra pairs still verify at
consensus: the guard therefore belongs in the combiner, and the effective
gate on a live chain is mempool standardness (`AreInputsStandard`). An
address-round-trip test (`hybrid_address_roundtrip`) encodes a
`CHybridKeyID` with `CCoinAddress` and decodes it back to the same key ID
through both `GetHybridKeyID` and the `CTxDestination` variant, checks
`IsMine` (spendable with the key in the store, `MINE_NO` otherwise),
verifies that the ECDSA-only PubKey address of the same legacy key is not a
hybrid address, and confirms that flipping any single Base58 character
breaks the checksum so the tampered string no longer parses. A
ValidateHybridKey test (`validate_hybrid_key_negatives`) mutates a valid
key in isolation and checks each gate rejects it: a wrong/blank/near-miss
MLDSA algorithm tag, a null MLDSA signer, an uncompressed (65-byte)
secp256k1 public key synthesized with libsecp256k1, and zero or negative
creation time. A signature-isolation test (`verify_hybrid_signature_isolation`)
calls `VerifyHybridSignature` directly instead of through the script
interpreter: the size guards on the EC (33) and ML-DSA (1952) public keys
(empty, undersized, oversized), the shared-sighash-type requirement between
the EC and ML halves, the `nHashType` enforcement gate, and tampered
signature/public-key bodies — with positive controls proving genuine pairs
still verify. A
hybrid-key-pool test (`hybrid_key_pool_invariants`) covers the wallet's
pre-generated hybrid key pool: `EnsureHybridKeyPool` tops up to its target
without duplicate `CHybridKeyID`s and is a no-op past it,
`GetUnusedHybridKey` tops up by +20 when the unused set runs below 5, pool
accounting holds (`mapHybridKeys == used + unused`), every legacy ECDSA key
maps 1:1 back to its `CHybridKeyID` via `GetHybridKeyIDByLegacyKeyID`, and
an encrypted/locked wallet refuses both top-up and allocation until
unlocked. A
tamper-rejection test
(`hybrid_single_tamper_rejected`) flips a single byte in each of the ECDSA
signature, the ML-DSA signature, and the ML-DSA public key of a valid P2PH
spend and asserts that the corrupted variant fails to verify while the
unmodified baseline still passes (the public-key case is checked directly
via `VerifyMLDSA` so the corruption is isolated from script re-hashing). A
P2HPKH spend test (`hybrid_p2hphk_spend`) exercises the
`OP_DUPHYBRID`/`OP_HASHHYBRID160`/`OP_CHECKHYBRIDSIG` output used by hybrid
mining coinbases (`GetScriptForHybridPubKeyHash`): the script is detected as
`TX_HYBRID_PUBKEYHASH`, recognized as mine via `HaveHybridKeyByHash`, signed
by the keystore, and verified. It asserts the `<sigEC> <sigML> <pubEC>
<pubML>` scriptSig layout (the public keys must be revealed for
`OP_DUPHYBRID`), and rejects byte flips in the stored hash and in the
revealed ML-DSA public key as well as a signature-only scriptSig (the
four-item `OP_DUPHYBRID` stack guard). A `OP_CHECKHYBRIDSIGVERIFY` test
(`hybrid_checksigverify_opcode`) covers the VERIFY variant of the single-key
check: a valid pair is consumed and script execution continues, a byte flip
in either signature aborts the whole script, and an under-supplied
scriptSig hits the four-item stack guard. It also pins down that a
VERIFY-terminated script solves as `TX_NONSTANDARD` (the Solver template
only recognizes the plain `OP_CHECKHYBRIDSIG` form). A disk-format
tampering test (`hybrid_key_disk_format_tampering`) verifies that every
`CHybridKeyDisk` field of both the plaintext (v2) and encrypted (v3)
at-rest records is covered by the payload checksum: single-byte flips in
the private keys, public keys, algorithm string, creation time, or the
checksum field itself are all detected, the serialization round trip is
exact (version byte first), and forging the version byte to switch
plaintext/encrypted misparses but fails the checksum. It also exercises
`FromLegacyDiskFormat`: a valid legacy stream round-trips, while truncated,
empty, trailing-garbage, and version/layout-mismatched streams are
rejected, plus `LoadHybridKey` rejections for a bad checksum, an
unsupported version, and an encrypted record in a plaintext wallet.
Building the tampering test exposed that `FromLegacyDiskFormat` accepted
truncated/empty records because `CDataStream::read()` zero-fills on short
reads instead of throwing; the parser is now explicitly guarded field by
field so such records are rejected. Running the suite prints a single
expected stderr diagnostic, `ERROR: CDataStream::read() : end of data`
(serialize.h), from the deliberately truncated v2-without-MLDSA negative
case in this test; it is benign, the record is still rejected by the new
field guards, and the suite reports no failures. A serializer edge-case test
(`ml_dsa_signer_serializer_edges`) covers all three `MLDSASigner`
private-key wire formats. For each format a record reopens to the exact
same key material (public key and private-key re-serialization identical,
cross signing/verifying against the original signer). The v1 and v2
parsers reject wrong algorithm bytes, zero-length and over-limit length
fields (2048/4096), truncation inside either key, trailing garbage, and
(shared) mismatched public keys; v2 additionally rejects a bad magic
byte, wrong versions, and non-zero reserved flags. The v3 encrypted
format rejects wrong and empty-vs-nonempty passwords via the GCM
authentication tag, corrupted magic, outer/inner version bytes, salt,
nonce, ciphertext, or tag bytes, truncation, and the header+tag minimum
size. Building this test exposed a real defect: `FromSerializedV2`
rejected every valid record because `EVP_PKEY_id()` returns -1 for
provider-created ML-DSA-65 keys; the redundant type check was removed to
match the v1 parser (the type is already fixed by
`EVP_PKEY_new_raw_private_key`).

The hybrid message RPC tests cover `signmessage` / `verifymessage` on
hybrid addresses. `hybrid_message_sign_verify` round-trips a
self-describing `HYBS` v1 container (magic + version + ECDSA compact
signature + ECDSA pubkey + ML-DSA-65 pubkey + ML-DSA-65 signature) and
re-derives the hybrid address through `CCoinAddress`, while
`hybrid_message_verify_negatives` rejects a wrong address, a tampered
message, a legacy 65-byte signature, and single-byte corruption of the
magic, version, ECDSA signature, ECDSA pubkey, ML-DSA pubkey, an ML-DSA
pubkey length, or the ML-DSA signature, as well as truncation, trailing
garbage, and empty input (`VerifyHybridMessage` embeds both public keys
because ML-DSA has no key recovery). `hybrid_message_encrypt_decrypt`
exercises the ECIES path used by `encryptmessage` / `decryptmessage` on a
hybrid key's secp256k1 component: encrypt-to-public / decrypt-with-private
round trip, wrong-key rejection, and tampered ciphertext/tag rejection.
Building it exposed a real defect: `CHybridKey::GetCKey()` re-published
the public key after `SetPrivKey()`, resetting the private `EVP_PKEY` so
`CKey::DecryptData` threw "ECDH failed"; the redundant `SetPubKey` call
was removed. It also exposed the deeper cause of a `decryptmessage`
segfault: `CKey` owns a raw `EVP_PKEY*` freed in its destructor but only
had implicit shallow copy semantics, so the RPC's copy-assignment form
(`key = hk.GetCKey();`) left `key` with a dangling pointer after the
temporary was destroyed (the safer copy-init form only works because NRVO
elides the copy). `CKey` now has real copy/move semantics that share the
`EVP_PKEY` through `EVP_PKEY_up_ref`, and the test exercises the copy
assignment, a direct copy constructor, and a forced by-value dispatch.

Walkthrough of the legacy test sources that were restored:

- `accounting_tests.cpp` needed an `extern CWallet* pwalletMain;`
  declaration (the global is defined in `test_bitcoin.cpp`).
- `base58_tests.cpp` gained `CHybridKeyID` overloads for its two visitors,
  and the `base58_keys_valid.json` / `base58_encode_decode.json` data were
  re-encoded from Bitcoin mainnet prefixes to Phoenixcoin prefixes
  (`0x38`/`0x3F`/`0x6F`/`0x34` and private-key `0xB8`/`0xEF`).
- `bignum_tests.cpp` was updated from the removed `setulong()` to the
  current `setuint()`.
- `Checkpoints_tests.cpp` was rewritten for the current `CheckHardened`
  checkpoint API using real Phoenixcoin checkpoint heights.
- `key_tests.cpp` uses Phoenixcoin base58 secret/address vectors (the
  codebase always serializes public keys compressed).
- `rpc_tests.cpp` includes `rpcmain.h` (the old `rpc.h` header is gone).
- `wallet_tests.cpp` passes the new `fSpendable` argument to the
  `COutput` constructor. The wallet test suite also carries a
  backward-compatibility regression for the change-tracking wallet
  (`wallet_change_marker_regression`): records written before change
  tracking carried no `"change"` marker, so `CWalletTx::Unserialize`
  must load them with an empty `vfChange`, letting `CWalletTx::IsChange`
  fall back to the address-book heuristic for legacy change outputs.
- `DoS_tests.cpp` re-implements the removed `ComputeMinWork` helper
  locally (with its original Bitcoin-era parameters, since the
  checkpoint data in the test is Bitcoin blockchain data) and adapts the
  `-maxsigcachesize` block to deterministic RFC6979 signatures: re-signing
  now reproduces the identical `scriptSig` instead of a distinct one.
- `miner_tests.cpp` was rewritten for Phoenixcoin: the original Bitcoin
  PoW nonce table and `SHA256Transform` check depended on the SHA256
  mining engine that was replaced by NeoScrypt, and `CreateNewBlock`
  requires a live chain (it self-validates via `ConnectBlock`), so it is
  not exercisable in the unit-test environment. The suite now verifies the
  fork-based `GetProofOfWorkReward` / `GetMoneySupply` schedule (including
  the bit-shift halving every 1M blocks) for mainnet and testnet, and
  exercises `IncrementExtraNonce` without a chain.
- `multisig_tests.cpp` was fixed by avoiding implicit `CKey` copies
  (`CKey` holds a raw `EVP_PKEY*` with a freeing destructor and no copy
  semantics, so passing by value caused double-frees) and by adding a
  minimal-DER-sig length guard in `CheckSig` to prevent a secp256k1 abort
  on non-signature values (e.g. the OP_1 data push).
- `sigopcount_tests.cpp` had the same `CKey` copy/double-free issue in its
  `vector<CKey>` construction; the 1-of-3 multisig script is now built
  directly from a `CKey` array (only public keys are serialized), avoiding
  the intermediate vector.
- `transaction_tests.cpp` uses the Bitcoin consensus-vector JSON data with
  vectors that do not apply to Phoenixcoin removed: the `23b397ed` and
  `f7fdd091` transactions carry non-minimal DER signatures (integer
  components with the high bit set without a leading zero byte) that
  Bitcoin's historical OpenSSL verifier accepted but the current
  libsecp256k1 parser rejects; and the Bitcoin `MAX_MONEY` output vectors
  exceed Phoenixcoin's `MAX_MONEY`, so they are invalid outputs rather than
  boundary-valid ones. The `tx_invalid` coinbase-size vectors relied on
  Bitcoin's 100-byte coinbase scriptSig limit, which Phoenixcoin raises to
  200000 bytes. `ParseScript` was moved into `testutil.cpp` so the shared
  helper is available to both enabled data-driven suites.
- `script_tests.cpp` drives the standard Bitcoin `script_valid.json` /
  `script_invalid.json` vectors plus real multisig and `CombineSignatures`
  round trips. Its `sign_multisig`/CHECKMULTISIG cases were converted to
  the pointer-based `CKey*` pattern (no `vector<CKey>` copies, see the
  `multisig_tests` note), the `SetMultisig` call in the combine test was
  replaced by an equivalent manual script build, and the duplicate
  `ParseScript`/`read_json` definitions were removed in favour of the
  shared helpers in `testutil.cpp`. The `>520 byte push` and `10,001-byte
  scriptPubKey` `script_invalid` vectors were removed because Phoenixcoin's
  `MAX_SCRIPT_ELEMENT_SIZE` is 66000 bytes rather than Bitcoin's 520.
- `script_P2SH_tests.cpp` exercises `SignSignature`/`VerifySignature` and
  the `Set*`/`IsPayToScriptHash`/`AreInputsStandard`/`GetP2SHSigOpCount`
  logic. The `SetMultisig` calls (which require a `std::vector<CKey>`,
  triggering implicit `CKey` copies, see the `multisig_tests` note) were
  replaced with the same manual script build used by `script_tests.cpp`
  (`EncodeOP_N` + public keys + `EncodeOP_N` + `OP_CHECKMULTISIG`) from a
  `CKey*` pointer array.

Enabling `script_P2SH_tests` also fixed a latent production bug in
`CScript::operator=`: it previously performed `clear()` before copying the
source, so self-assignment (`a = a`) silently emptied the script. The
`sign` test deliberately assigns a transaction's own scriptSig to itself
(within an exhaustive cross-verification loop); with upstream-style
assignment delegating to `std::vector<uchar>::operator=` the 
self-assignment is a correct no-op.

All of the disabled legacy test suites are now enabled again.

## Building the tests

Build the test executable with the Boost static libraries:

```
make -j4 STATIC=1 -f Makefile.linux test_phoenixcoin
```

If necessary, perform a clean build first:

```
make -f Makefile.linux clean
make -j4 STATIC=1 -f Makefile.linux test_phoenixcoin
```

Use `STATIC=1` rather than `DYNAMIC=1`: the shared Boost Unit Test
Framework library does not export `main`, so a `DYNAMIC=1` build fails
to link the test executable.

## Running the tests

Run the complete currently enabled test suite:

```
./test_phoenixcoin
```

Run only the hybrid multisignature tests:

```
./test_phoenixcoin --run_test=hybrid_multisig_*
```

Run one specific test case, for example the P2SH spend test:

```
./test_phoenixcoin --run_test=hybrid_multisig_p2sh_ismine_and_spend
```

A successful test run should report:

```
Running 104 test cases...

*** No errors detected
```

The hybrid message-key suite now also covers the `dumphybridkey` /
`importhybridkey` round trip: a key exported as WIF + Base64-DER is
re-parsed, validated, and loaded into a wallet through the same
`CHybridKeyDisk` / `LoadHybridKey` path used by wallet-generated keys,
reproducing the original hybrid identity.

A systematic malformed-`HYBS` matrix (`hybrid_message_malformed_matrix`)
sweeps the parser with every truncation prefix plus bad magic/version,
wrong ECDSA-pubkey and ML-DSA length fields (including the `0xFFFF`
maximum), trailing bytes, and 64 KiB zero buffers, asserting clean failure
with no partially accepted or partially populated parser output. The same
parser (`ParseHybridMessage` in `src/hs/hybrid_message.cpp`) is fuzzed
independently by the `fuzz_hybrid_message_parse` libFuzzer target; see
`fuzzREADME.md`.

The `key_copy_move_lifetime` test (`key_tests.cpp`) exercises `CKey`
copy/move/swap ownership: refcounted-PKEY copies surviving each other's
destruction, moved-from keys becoming safe null keys, swap-based move
assignment, self-assignments, and ECIES decrypts performed through copies
after their source keys have been destroyed (the `decryptmessage`
`key = GetCKey()` regression family).

`key_copy_move_legacy_signing` (`key_tests.cpp`) drives real legacy
transaction signing through those semantics: a keystore hands the signing
key out via every copy/move pathway, and `SignSignature` must produce a
`VerifySignature`-passing scriptSig for P2PKH and P2PK outputs whose signed
transactions round-trip through serialization. The store keeps only the
secret, so a shallow-copy/refcount bug double-frees the shared PKEY — this
test crashes (SIGSEGV) under the pre-fix implicit-shallow-copy `CKey`.

`key_copy_move_hybrid_signing` (`hybrid_multisig_tests.cpp`) does the same
for the hybrid transaction signing path: a keystore churns the stored
hybrid key's ECDSA component through copy-chain / move-chain / move-assign
modes on every hand-out, and `SignSignature` → `SignHybridTx` must produce
verifying scriptSigs for P2PH, P2HPKH, hybrid-multisig and P2SH-wrapped
outputs. The ECDSA half of the scriptSig is asserted re-sign-stable while
the ML-DSA half is intentionally randomized (OpenSSL hedged signing). It
crashes (SIGSEGV) under the pre-fix shallow-copy `CKey`, and its re-sign
loop also pins the `SignHybridTx` append fix (the output scriptSig is now
cleared at the start of the call instead of accumulating on re-sign).

## Adding tests

New tests should normally be placed in a separate source file in this
directory and use the Boost Unit Test Framework.

Test cases should be grouped into an appropriate Boost test suite using
`BOOST_AUTO_TEST_SUITE`.

For example:

```
BOOST_AUTO_TEST_SUITE(my_feature_tests)

BOOST_AUTO_TEST_CASE(my_test)
{
    ...
}

BOOST_AUTO_TEST_SUITE_END()
```

When adding a test source, add its corresponding object to `TESTOBJS`
in `src/Makefile.linux` and perform a clean build (see above), since test
objects are only rebuilt when their headers change.

For example:

```
TESTOBJS := \
    obj-test/test_bitcoin.o \
    obj-test/hybrid_multisig_tests.o
```

Header dependencies for test objects are tracked via `-include obj-test/*.P`
in `src/Makefile.linux`, so test sources are rebuilt when headers change.

## Boost Unit Test Framework

The test executable uses the Boost Unit Test Framework statically when
built with `STATIC=1`. The build system links against:

```
libboost_unit_test_framework.a
```

For further reading about the Boost Unit Test Framework, see:

```
http://www.alittlemadness.com/2009/03/31/c-unit-testing-with-boosttest/
```
