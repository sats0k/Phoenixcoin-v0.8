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
```

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
into the combined scriptSig.

Legacy test sources from the original Bitcoin/Phoenixcoin test suite
are not currently enabled because they depend on interfaces or wallet
behavior that have changed in the current codebase.

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

A successful hybrid test run should report:

```
Running 12 test cases...

*** No errors detected
```

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

When adding a test source to the build, add its corresponding object to
`TESTOBJS` in `src/Makefile.linux`.

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
