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
single write transaction, the copy is verified and committed, and only then is
`<datadir>/wallet.backend` written with `lmdb`.  `wallet.dat` is opened
read-only and is left unchanged, so the Berkeley DB wallet remains available
until you deliberately remove it.

If the copy fails, the transaction is aborted, the newly created `wallet/` is
removed, no marker is written, and startup fails with an error.  The original
`wallet.dat` is untouched, a normal BDB start still works, and selecting LMDB
again retries the migration.  A crash after the commit but before the marker is
written is also safe: the populated `wallet/` is used on the next LMDB start and
the marker is written then.

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
  512 MiB on 64-bit platforms and 256 MiB elsewhere.  It is validated like
  `-lmdbmapsize` and enlarged automatically when the existing wallet needs it.

## Map usage and growth

At startup Phoenixcoin prints how much of the LMDB map is in use:

```
LMDB chain index: 123.4 of 4096.0 MiB used
```

When the mapped file is already larger than the configured map size, the map is
enlarged automatically, so a datadir created with a larger `-lmdbmapsize` can be
started without repeating the option.  If the index reaches the map limit,
writes fail with an `LMDB map is full` message; stop the node and restart with a
larger `-lmdbmapsize`.

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

- `kvdb_tests` passed 31/31 test cases in the normal build.  The chain-index
  subset that existed at the time (24 cases, 1238 assertions) also passed under
  AddressSanitizer and UndefinedBehaviorSanitizer with no sanitizer reports.
- `regression_lmdb_chain_migration.sh` passed 64/64 checks with
  AddressSanitizer and UndefinedBehaviorSanitizer enabled.
- The full unit suite passed 148 test cases with no errors in the normal build.
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
The migration test starts from records in a Berkeley DB wallet, copies them into
an empty LMDB environment, verifies that the marker appears only after the
source is intact and the copy is committed, and checks that a restart uses the
LMDB wallet without migrating again.  A dedicated regression covers the reverse
authority case: with a `bdb` marker, an existing `wallet.dat`, and a real LMDB
environment left in `wallet/`, an LMDB start is refused, the marker stays
`bdb`, and the stale environment is not adopted or modified.  They pass in the
normal build together with the rest of the unit suite.

`regression_lmdb_wallet_migration.sh` passed 45/45 checks.  It starts from a
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
  and a retry after restoring the file migrates successfully.

A daemon smoke test on a temporary data directory also covered the stage-3
wiring: the first start created `wallet/` and `wallet.backend` and printed
`Wallet database: LMDB`; `getnewaddress` worked, the address survived a clean
restart, and the keypool was refilled through the LMDB wallet; `backupwallet`
produced an environment that loaded the same addresses when restored into a
fresh data directory; and `encryptwallet` compacted and rewrote the
environment, with the encrypted wallet reopening and unlocking after restart.
