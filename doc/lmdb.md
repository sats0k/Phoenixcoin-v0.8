# LMDB chain index backend

Phoenixcoin stores the block index and the transaction/UTXO index in the chain
database.  Berkeley DB (`blkindex.dat`) remains the default backend; LMDB can be
selected explicitly with `-dbbackend=lmdb`.

The wallet has a separate backend switch.  `wallet.dat` remains the default and
Berkeley DB is still used unless `-walletbackend=lmdb` is given; see
[Wallet backend](#wallet-backend-optional-lmdb) below.  Address storage
(`peers.dat`) is unaffected.

## Enabling LMDB

1. Stop Phoenixcoin.
2. Back up the data directory.
3. Start with `-dbbackend=lmdb` (or put `dbbackend=lmdb` in
   `phoenixcoin.conf`).

On the first LMDB start Phoenixcoin copies every record from an existing
`blkindex.dat` into `<datadir>/blkindex/`.  The copy runs in a single LMDB
transaction, so an interrupted migration rolls back and is retried on the next
start.  `blkindex.dat` is left in place and is not modified.

After a successful migration Phoenixcoin writes `<datadir>/blkindex.backend`
containing `lmdb`.  This marker makes the data directory's backend explicit:

- starting without `-dbbackend=lmdb` fails with a clear error instead of
  silently loading the stale `blkindex.dat`;
- a datadir that already contains a non-empty `blkindex/data.mdb` but no marker
  (created by an older development build) is treated as an LMDB datadir for the
  same reason;
- a marker that says `lmdb` requires a non-empty LMDB index.  If `blkindex/` is
  missing, empty, or removed, startup fails rather than silently re-importing
  the migration-time `blkindex.dat` snapshot;
- migration from `blkindex.dat` only runs when no marker exists (or the marker
  is `bdb`).

## Returning to Berkeley DB

Back up the data directory, then remove both `<datadir>/blkindex` and
`<datadir>/blkindex.backend`.  Phoenixcoin will start with Berkeley DB again and
use the untouched `blkindex.dat`.  Any blocks imported while LMDB was active
must be re-downloaded or re-imported, because that work only exists in the LMDB
index.

## Wallet backend (optional, LMDB)

The wallet backend is independent of the chain index backend.  Both defaults
remain Berkeley DB, and the wallet is only moved when explicitly requested:

1. Stop Phoenixcoin and back up the data directory.
2. Start with `-walletbackend=lmdb` (or put `walletbackend=lmdb` in
   `phoenixcoin.conf`).

The LMDB wallet lives in `<datadir>/wallet/`.  The first LMDB start converts an
existing `wallet.dat`: every record is copied into the new environment inside a
single write transaction, read back and compared byte-for-byte before the
transaction commits, and the final record count must match the source.  Only
then is `<datadir>/wallet.backend` written with `lmdb`.  `wallet.dat` is opened
read-only and is left unchanged, so the Berkeley DB wallet remains available
until you deliberately remove it.

If the copy fails, the transaction is aborted, the newly created `wallet/` is
removed, no marker is written, and startup fails with an error.  The original
`wallet.dat` is untouched, a normal BDB start still works, and selecting LMDB
again retries the migration.  A crash after the commit but before the marker is
written is also safe: the populated `wallet/` is used on the next LMDB start and
the marker is written then.

The map for the one-shot copy is sized from `wallet.dat` itself, so a wallet
larger than `-lmdbwalletsize` still migrates; the startup log reports
`LMDB wallet map size increased ... to fit the wallet.dat migration`.  After
that, if the wallet reaches its map limit, writes fail with an `LMDB map is
full` message naming `-lmdbwalletsize`; restart with a larger value.

The marker makes ownership explicit:

- starting without `-walletbackend=lmdb` fails instead of silently opening a
  stale `wallet.dat`;
- a non-empty `<datadir>/wallet/data.mdb` without a marker is treated as an
  LMDB wallet for the same reason;
- a marker that says `lmdb` requires a non-empty LMDB wallet, so a missing or
  deleted `wallet/` fails rather than creating an empty wallet;
- a marker that says `bdb` refuses `-walletbackend=lmdb`, even when a leftover
  `wallet/` directory exists.  The `bdb` marker is authoritative: to migrate,
  back up the data directory, remove both `wallet.backend` and any stale
  `wallet/` directory, then restart with `-walletbackend=lmdb`.  Removing only
  the marker would let the stale LMDB wallet be adopted instead of migrating
  `wallet.dat`;
- Berkeley DB `wallet.dat` is left untouched while LMDB is active.

`-salvagewallet` is Berkeley DB specific and is rejected together with
`-walletbackend=lmdb`.  An LMDB wallet is an environment directory, so
`backupwallet <destination>` writes a directory, not a single file.  If
`<destination>` is an existing directory the copy is written to
`<destination>/wallet`; otherwise `<destination>` names the new backup
directory.  The target must not exist yet or must be empty; an existing
non-empty target is refused instead of being overwritten.

To return to Berkeley DB, stop the node, back up the data directory, and remove
both `<datadir>/wallet` and `<datadir>/wallet.backend`.  The untouched
`wallet.dat` is then used again.  Any keys or transactions created while the
LMDB wallet was active exist only in the LMDB copy.

## Options

- `-dbbackend=lmdb|bdb` — chain index backend, default `bdb`.
- `-lmdbmapsize=<MiB>` — maximum size of the LMDB chain index map.  The default
  is 4096 MiB on 64-bit platforms and 1024 MiB elsewhere.  The map size is a
  limit, not a preallocation.  The value must be a positive integer; values that
  are not representable or that exceed the platform's LMDB address-space limit
  are rejected at startup.  32-bit builds accept at most 2048 MiB, and the
  converted byte count must be a multiple of the system page size.
- `-lmdbnosync=<0|1>` — default `1`.  Commits do not fsync, matching Berkeley
  DB's `DB_TXN_WRITE_NOSYNC` behaviour and avoiding an fsync per block during
  initial sync.  Transactions remain atomic and consistent.  Set to `0` for
  per-commit durability.  A clean shutdown always flushes the environment.
  This option applies to both LMDB environments.
- `-walletbackend=lmdb|bdb` — wallet backend, default `bdb`.
- `-lmdbwalletsize=<MiB>` — maximum size of the LMDB wallet map, default
  4096 MiB on 64-bit platforms and 256 MiB elsewhere.  It is validated like
  `-lmdbmapsize` and enlarged automatically when the existing wallet or a
  pending `wallet.dat` migration needs more room.

## Map usage and growth

At startup Phoenixcoin prints how much of the LMDB map is in use:

```
LMDB chain index: 123.4 of 4096.0 MiB used
```

When the mapped file is already larger than the configured map size, the map is
enlarged automatically, so a datadir created with a larger `-lmdbmapsize` can be
started without repeating the option.  The wallet behaves the same way: an
existing `wallet/` is reopened large enough for `data.mdb`, and a pending
`wallet.dat` migration reserves space from the source file before the copy
starts.  If the index or wallet reaches the map limit, writes fail with an
`LMDB map is full` message; stop the node and restart with a larger
`-lmdbmapsize` or `-lmdbwalletsize`.

Online resizing while the node is running is not implemented.

## Write consistency

Adding a block writes its block-index record and, when it becomes the best
chain, the best-chain pointer in one transaction.  If any part of that write
fails, the transaction is aborted and the newly created in-memory
`mapBlockIndex` entry is removed again, so a failed write cannot leave an index
entry whose database record was rolled back.  This applies to both backends.

## Recovery

LMDB never overwrites committed pages in place, so an interrupted process leaves
the last committed transaction intact.  With `-lmdbnosync=1` a system crash or
power loss may lose the most recent commits, but the environment stays
consistent and is reconciled on the next start.

There is no `-reindex` mode in this codebase, and blocks are not replayed from
the `blk0001.dat` files.  If the index is lost, remove the chain index
(`blkindex/` and `blkindex.backend` for LMDB, or `blkindex.dat` for Berkeley DB)
and the node creates a fresh index containing only the genesis block, then
downloads the chain again.

If the marker says `lmdb` but the LMDB index is missing or empty, restore
`blkindex/` from a backup.  To deliberately fall back to the migration-time
snapshot, remove only `blkindex.backend`; the next LMDB start will then import
`blkindex.dat` again.  That snapshot does not contain blocks or UTXO changes
made after the original migration, so prefer a backup when one exists.

## Validation

The chain-index backend was validated on Linux x86-64 with a build configured
with `-fsanitize=address,undefined -fno-omit-frame-pointer` and LTO disabled.

- `kvdb_tests` passed 33/33 test cases in the normal build.  The chain-index
  subset that existed at the time (24 cases, 1238 assertions) also passed under
  AddressSanitizer and UndefinedBehaviorSanitizer with no sanitizer reports.
- `regression_lmdb_chain_migration.sh` passed 64/64 checks with
  AddressSanitizer and UndefinedBehaviorSanitizer enabled.
- The full unit suite passed 153 test cases with no errors in the normal build.
  Under sanitizers it passed 140/141 test cases (40534/40535 assertions).  The
  only failure was the timing-sensitive `DoS_tests/DoS_checkSig` under
  sanitizer slowdown.  There were no AddressSanitizer errors.  The eight
  UndefinedBehaviorSanitizer reports were all in pre-existing non-LMDB code
  (`Hash160` on an empty vector, base32/base64 decoding, and empty-vector
  handling in `EvalScript`).

Crash recovery was checked at two points:

- Killing the daemon part-way through migration left no backend marker.
  The next start discarded the partial index, repeated the migration, and
  produced the same 588001 records and chain tip as an uninterrupted
  migration.
- Three `SIGKILL`/restart cycles during initial sync at and above height
  202135 always reopened the last committed tip or a later one.  The tip
  block and its coinbase transaction remained readable after every restart,
  and syncing continued to height 227811 with 665129 records.

A full BDB chain at height 202135 (588001 records: 202136 `blockindex` and
385861 `tx`) was migrated in about three seconds.  LMDB contained exactly
588001 entries in a 72118272-byte `data.mdb`, and the BDB and LMDB tips had the
same hash.  The migrated node then continued syncing normally.

The wallet tests in `kvdb_tests` cover the wallet backend marker, the startup
action matrix (including migration), `CWalletDB` routing, commit/abort,
persistence across an environment restart, and prefix scans through `CDBScan`.
They check that the marker appears only after the source is intact and the copy
is committed, and that a restart uses the LMDB wallet without migrating again.
A dedicated regression covers the reverse authority case: with a `bdb` marker,
an existing `wallet.dat`, and a real LMDB environment left in `wallet/`, an LMDB
start is refused, the marker stays `bdb`, and the stale environment is not
adopted or modified.

`wallet_migration_tests` compares wallet semantics, not record counts.  It
builds a wallet containing compressed and uncompressed keys, key metadata,
watch-only and redeem scripts, address labels, a default key, a populated
keypool, hybrid keys, hybrid address labels, and transactions with block
association, timestamps, order positions, labels, spent outputs and
abandoned/conflicted metadata.  After migration it requires:

- every raw record to survive byte-for-byte, including encrypted key material;
- key IDs, public keys, private keys, metadata, default key and scripts to be
  unchanged;
- every hybrid `CHybridKey` (its legacy ECDSA half and embedded ML-DSA signer),
  every at-rest `hyb` record, every legacy ECDSA key record and every `hybaddr`
  label to match; the ECDSA key, hybrid record and signer must all agree, and
  all three must still agree after a restart;
- every transaction's txid, block hash and index, merkle branch, timestamps,
  order position, `mapValue` metadata and per-output spent/change state to be
  unchanged;
- address-book labels and watch-only state to be unchanged;
- the single keypool's indices and records to match, every pool key to be owned
  by the wallet, `GetAllReserveKeys` to agree with the pool, and the next index
  to continue sequentially;
- keypool reserve, return, keep, refill and `GetKeyFromPool` to behave the same
  after the migration and after a restart.

The hybrid import round-trip test runs
`importhybridkey` -> `dumphybridkey` -> restart -> `dumphybridkey` -> sign ->
verify on the LMDB wallet.  It checks that the imported key creates the legacy
ECDSA record, the `hyb` record and the labelled `hybaddr` record, that the dump
reproduces the original WIF and ML-DSA material before and after the restart,
and that both halves still sign and verify afterwards.

The encryption lifecycle test migrates an unencrypted wallet, signs with it,
encrypts it, and checks that no plaintext `key` or `wkey` records remain while
`ckey` and `mkey` records exist.  Hybrid `hyb` records must switch to their
encrypted form: the ECDSA and ML-DSA private bytes are gone and replaced by the
ciphertext, while the public key and checksum stay verifiable.  It then restarts
twice: the wallet must still load encrypted and locked, reject a wrong
passphrase, unlock with the right one, sign with both the legacy and hybrid
keys, lock, and sign again after another restart.  It also scans the compacted
`wallet/data.mdb` for the pre-encryption ECDSA and ML-DSA private bytes and
fails if any plaintext secret leaked into the LMDB environment.

Wallet write atomicity is covered by three failure-injection tests in
`wallet_migration_tests`.  They use the test-only hooks
`SetTestWalletWriteFailure` and `SetTestWalletCommitFailure`, which make one
matching LMDB wallet write (after an optional skip count) or the next wallet
commit fail.  The hooks are one-shot, inert until armed, and never affect
Berkeley DB or the chain index.  `wallet_atomic_write_boundaries` fails every
existing `CWalletDB` write boundary inside one explicit transaction -- `keymeta`
and `key`, `ckey`, `tx`, `name`, `bestblock`, `pool`, `cscript`, `watch`,
`defaultkey`, `orderposnext`, `hyb`, `hybaddr`, `hybused`, `mkey`, `setting`,
`acc`, `acentry`, `minversion` and `version` -- and requires the aborted
transaction, including a successful prefix and suffix write, to leave the
wallet record set unchanged both immediately and after an LMDB-only restart.
This wallet format has no HD-chain or descriptor records, so those boundaries
do not exist.  `wallet_atomic_hybrid_import_rollback` repeats the hybrid
`importhybridkey` transaction (ECDSA key, `hyb` record, label) with the failure
injected at each write and at the commit, then proves none of the new state is
visible in memory or after a restart and that the identical retry succeeds.
`wallet_atomic_hybrid_keypool_rollback` does the same for a keypool top-up,
failing the first, second and third `hyb` write; a final uninjected top-up must
commit the whole pool.

The keypool top-up path itself was made atomic for these tests:
`CWallet::EnsureHybridKeyPool` now generates and encrypts the whole batch
first, writes the ECDSA records and hybrid records in one database transaction,
and only registers the keys in memory after that transaction commits.  A
failure at any point leaves no partial pool behind.

These suites pass in the normal build together with the rest of the unit suite.

`regression_lmdb_wallet_migration.sh` passed 46/46 checks.  It starts from a
real Berkeley DB wallet and verifies the complete handoff:

- `wallet.dat` is byte-for-byte unchanged before and after the switch, and the
  LMDB wallet contains exactly the same number of raw records;
- legacy keys, hybrid keys, and address-book entries still resolve after the
  migration and after a restart;
- the migration runs once, the restart does not copy again, and addresses
  created while LMDB is active survive a restart;
- a default BDB start is refused while `wallet.backend` says `lmdb`;
- `backupwallet` produces a restorable LMDB environment;
- a deliberately unreadable `wallet.dat` fails startup without writing a
  marker or leaving `wallet/` behind, the untouched BDB wallet still starts,
  and a retry after restoring the file migrates successfully;
- the retry deliberately starts with `-lmdbwalletsize=1`; the map is enlarged
  from `wallet.dat` before the copy and the migration completes instead of
  failing with `MDB_MAP_FULL`.

`regression_lmdb_wallet_e2e.sh` passed 107/107 checks.  It is the full
lifecycle counterpart to the migration regression and drives real daemons
through:

- a populated Berkeley DB wallet: imported coinbase keys, labelled receiving
  addresses, a watch-only address, a multisig script, a signed message,
  keypool state and labelled hybrid keys;
- real wallet transactions before the switch, including a hybrid-signed spend
  that reaches the mempool;
- `encryptwallet`, the shutdown it triggers, and an encrypted restart with
  wrong-passphrase, lock and unlock checks;
- additional keypool and hybrid state while the wallet is unlocked;
- the LMDB migration, a restart, and verification of every key, label,
  transaction, signature, hybrid key and keypool path through RPC;
- normal use of the migrated wallet: new addresses and labels, message
  signing, new hybrid keys, a keypool refill and a brand new hybrid-signed
  transaction;
- one final restart that proves the new state persisted, while `wallet.dat`
  stays byte-for-byte unchanged and no second migration runs.

This codebase has no regtest mode, and spending a mainnet coinbase normally
needs 101 confirmations.  The test therefore submits a fixed six-block chain
fragment.  Blocks 5 and 6 were mined once under the same consensus rules and
pay keys whose WIFs are embedded in the test; the test daemons are started
with `PHOENIX_TEST_COINBASE_MATURITY=0`.  The hook in `LoadBlockIndex` changes
`nBaseMaturity` only when that environment variable is present and parses as a
value between 0 and `BASE_MATURITY`; it is inert otherwise, applies only to the
test daemon process, and is not set by any normal startup path.

A daemon smoke test on a temporary data directory also covered the stage-3
wiring: the first start created `wallet/` and `wallet.backend` and printed
`Wallet database: LMDB`; `getnewaddress` worked, the address survived a clean
restart, and the keypool was refilled through the LMDB wallet; `backupwallet`
produced an environment that loaded the same addresses when restored into a
fresh data directory; and `encryptwallet` compacted and rewrote the
environment, with the encrypted wallet reopening and unlocking after restart.

## Wallet backend parity

Record counts and byte-identical copies prove that migration moved data; they
do not prove that the two backends interpret it the same way.
`regression_lmdb_wallet_parity.sh` (passed 118/118 checks) closes that gap by
comparing the *logical* wallet state of a BDB wallet and an independently
migrated LMDB wallet:

- one populated BDB wallet is stopped at a known state, its datadir is copied
  twice, and exactly one copy is migrated to LMDB;
- both copies then run as independent daemons on separate datadirs and RPC
  ports, so neither side can answer for the other;
- at every checkpoint the test canonicalizes `dumpwallet`, `dumphybridkeys`,
  `listtransactions`, `listaccounts`, `listreceivedbyaccount` and
  `...byaddress`, `listaddressgroupings`, `listunspent`,
  `listhybridaddresses`, balances, and selected `gettransaction` results, and
  requires the two canonical documents to be equal.

Before encryption the comparison is `full`: every WIF, address, label, script,
txid, hybrid key and pool tag must match.  `encryptwallet` intentionally
regenerates the legacy keypool with fresh random keys, so later checkpoints
compare `structural` state: key material and address identities are reduced to
their shape (per-tag counts, labels, amounts), while transactions, account
entries, hybrid keys, balances and unspent values are still compared exactly.
Only timestamps are always dropped; structural mode also drops identity fields
and the ECDSA-DER-dependent `size_bytes`/`fee_per_kb` values, which vary by a
byte between independently created equivalent transactions.

The checkpoints cover the migration itself, equivalent deterministic
operations (`importprivkey`, `importhybridkey`, `setaccount`, `move`,
`gethybridaddress`, and cross-backend `signmessage`/`verifymessage`), an
encrypted restart followed by a real 40 PXC hybrid-signed spend, legacy
keypool growth from 50 to 81 entries plus fresh address allocation, and a final
restart.  The deterministic phase deliberately consumes no legacy keypool
keys, so the full comparison really covers the whole pool, and the shared
hybrid pool must allocate the same address on both branches.

## Wallet rewrite failures

`RewriteWalletLMDB()` closes the live environment before it moves `wallet/`
aside, so every failure after that point must either reopen a usable
environment or stop the process.  It never disables LMDB: `wallet.backend`
still says `lmdb`, and a Berkeley DB fallback would accept writes that the
next LMDB start could not see.  The failure paths are:

- a failed rename of `wallet/` leaves the active environment in place and
  reopens it;
- a failed install of `wallet.rewrite` restores `wallet.old` and reopens it;
- an installed copy that cannot be reopened is parked, `wallet.old` is
  restored and reopened;
- if the plaintext `wallet.old` copy cannot be removed, the new environment
  stays live and the rewrite reports failure so callers that require
  compaction can stop; startup recovery removes the leftover copy on the
  next start;
- only a failure with no recoverable environment exits the process.

`CWallet::EncryptWallet()` treats a failed rewrite as fatal: encryption is
already committed at that point, so continuing could leave plaintext key
material in the old copy.

Four named `kvdb_tests` cases inject each filesystem step with the inert
test-only `SetTestWalletRewriteFailure` hook:
`wallet_lmdb_rewrite_rename_old_failure`,
`wallet_lmdb_rewrite_install_failure`,
`wallet_lmdb_rewrite_reopen_failure` and
`wallet_lmdb_rewrite_cleanup_failure`.  They check that the marker stays
`lmdb`, that `wallet.dat` never appears as a Berkeley DB file, that later
writes still reach LMDB, that a write after an unrecoverable failure fails
instead of landing in Berkeley DB, and that a restart repairs the directory.
`SetTestWalletRewriteAbort(true)` makes the fatal path return false instead
of exiting, so the test can inspect the on-disk state; both hooks apply only
to the LMDB wallet.

`wallet_migration_tests/wallet_encryption_rewrite_failure_is_not_success`
covers the encryption caller.  It fails the post-encryption rewrite after
the encrypted records have been committed, requires `EncryptWallet()` to
return false (the test-only abort hook turns the production exit into an
observable failure), and scans `wallet/data.mdb` to prove plaintext pages
are still present.  A following successful rewrite must remove those bytes,
and the encrypted wallet must restart, unlock and sign.

## Wallet backend sanitizer validation

The wallet backend matrix was validated on Linux x86-64 with separate
AddressSanitizer and UndefinedBehaviorSanitizer builds
(`-fsanitize=address` and `-fsanitize=undefined`, with
`-fno-omit-frame-pointer -g` and LTO disabled).  Every entry passed in both
builds:

| Check | Result |
| --- | --- |
| `kvdb_tests/wallet_*`, `wallet_migration_tests`, `accounting_tests` | 15 cases, 12441 assertions |
| `regression_lmdb_wallet_migration.sh` | 46/46 |
| `regression_lmdb_wallet_e2e.sh` | 107/107 |
| `regression_lmdb_wallet_crash.sh` | 359/359 |
| `regression_lmdb_wallet_parity.sh` | 118/118 |
| full wallet suite (the unit cases above plus `wallet_tests`) | 17 cases, 21550 assertions |
| full unit suite | 158 cases |

The targeted unit runs used LeakSanitizer (`detect_leaks=1`) and reported no
leaks.  Broad runs used `detect_leaks=0` because of pre-existing RPC/asio
accepted-connection lifecycle leaks and the known test fixtures
(`wallet_tests.cpp` `add_coin` and `rpc_tests::HybridSet`); those are reported
separately and are not wallet-backend leaks.  No AddressSanitizer error
occurred in any run.

The full ASan suite passed 158/158.  A separate detailed rerun hit the
pre-existing timing-sensitive `DoS_tests/DoS_checkSig` assertion once (2 of 3
isolated reruns passed); it is unrelated to the wallet or LMDB code.
UndefinedBehaviorSanitizer produced eight reports, all in pre-existing
non-LMDB code: `Hash160` on the deliberately empty transaction written by
`accounting_tests`, base32 and base64 decoding, base58 encoding of an empty
vector, and empty-vector handling in `EvalScript`.  No report involved
`db.cpp`, the LMDB wrappers, wallet serialization, record lengths, cursor
iteration, map-size conversion, or version/enum conversion.

## Wallet crash safety

The chain-index validations above were mirrored for the wallet:
`regression_lmdb_wallet_crash.sh` kills a real daemon with `SIGKILL` at
every durable boundary and requires the restarted wallet to be either
exactly the pre-operation state or the fully committed state, never
anything in between.  It passed 359/359 checks.  The kill is injected by a
test-only hook, `TestWalletCrashPoint` (`src/db.cpp`), controlled by
`PHOENIX_TEST_CRASH_FILE`.  The file contains `<point> <skip>`; each matching
call decrements the skip and the call that finds it at zero raises
`SIGKILL` (falling back to `std::_Exit(137)`), after flushing stdio so
`debug.log` records how far the operation got.  With no file or no
environment variable the hook is inert, and it applies only to the LMDB
wallet, never to Berkeley DB or the chain index.

The crash points cover the whole wallet lifecycle:

- per-record writes: `wallet-write-{before,after}-commit:<type>`, where the
  type is the record family (`tx`, `name`, `key`, `pool`, `hyb`, ...), so a
  case can target one write without counting unrelated records;
- explicit transactions: `wallet-txn-{before,after}-commit` (hybrid import,
  keypool top-up, encryption rewrite);
- migration: `wallet-migrate-record` (copying one exact record),
  `wallet-migrate-{before,after}-commit`;
- the backend marker: `wallet-marker-{before,after}-rename`;
- the encryption rewrite: `wallet-rewrite-{after-copy,after-old-rename,
  after-install}`.

The script builds a Berkeley DB wallet on the same fixed mainnet fragment,
migrates a reference copy to LMDB, and gives every case its own datadir
copy, so no case can influence another and the user's real datadir is never
touched.  The cases fall into three groups:

- **A. Migration.**  Killed mid-copy, just before the commit, just after the
  commit but before the marker, before the marker temp file is renamed, and
  after the marker is written.  A partial migration is empty from LMDB's
  view because the transaction never committed, so startup discards it and
  repeats the migration; an LMDB environment committed without a marker is
  adopted and gets the marker written.  In every case the migration runs
  exactly once to completion, `wallet.dat` stays byte-for-byte unchanged,
  and the recovered wallet matches a clean migration record for record.
- **B. Normal operation.**  Sends, receiving (`importprivkey`), labels,
  keypool refills, hybrid imports and `encryptwallet` are killed on either
  side of their commit.  Before the commit the operation must be absent
  after restart and remain repeatable; after it the operation and its
  effects must be complete and intact.
- **C. Marker creation.**  The three marker/rewrite boundaries above must
  take a deterministic startup path: a leftover `wallet.backend.tmp` is
  removed, a committed environment is adopted, and an interrupted
  encryption rewrite is completed.

Interrupted `RewriteWalletLMDB` is repaired by
`RecoverInterruptedWalletRewrite`, called from
`InitLMDBWalletDBInternal`: if `wallet/` is missing it installs the staged
`wallet.rewrite` environment or restores `wallet.old`, otherwise it removes
the staging directories, and it removes a stale `wallet.backend.tmp`.
`CWallet::ReacceptWalletTransactions` also repairs spent flags from the
wallet's own transactions before consulting the chain index, so a wallet
that committed a send but was killed before that bookkeeping still reports
the correct balance.
