# LMDB chain index backend

Phoenixcoin stores the block index and the transaction/UTXO index in the chain
database.  Berkeley DB (`blkindex.dat`) remains the default backend; LMDB can be
selected explicitly with `-dbbackend=lmdb`.

The wallet has a separate backend switch.  LMDB is the production default;
Berkeley DB `wallet.dat` remains available with `-walletbackend=bdb` for
compatibility and recovery.  See [Wallet backend](#wallet-backend) below.
Address storage (`peers.dat`) is unaffected.

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

## Wallet backend

The wallet backend is independent of the chain index backend.  LMDB is the
production default; Berkeley DB remains available for compatibility and
recovery with `-walletbackend=bdb`.  At startup the node prints the selected
backend, for example `Wallet backend: LMDB`.

To move an existing Berkeley DB `wallet.dat` to LMDB explicitly:

1. Stop Phoenixcoin and back up the data directory.
2. Start with `-walletbackend=lmdb` (or leave the default in place).

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
that the wallet map grows automatically while the node runs, up to
`-lmdbmaxwalletsize`; see [Map usage and growth](#map-usage-and-growth).

The marker makes ownership explicit:

- starting with `-walletbackend=bdb` fails instead of silently opening a
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

To return to Berkeley DB, stop the node, back up the data directory, remove
both `<datadir>/wallet` and `<datadir>/wallet.backend`, and start with
`-walletbackend=bdb`.  The untouched `wallet.dat` is then used again.  Any
keys or transactions created while the LMDB wallet was active exist only in
the LMDB copy.

## Online backup and restore

An LMDB wallet is an environment directory, not a single `wallet.dat` file.
Copying `data.mdb` with `cp`, `rsync`, a snapshot tool, or a file manager while
the node is running is **not** a valid backup: LMDB may be extending or
rewriting pages concurrently, and the copy can contain a torn B-tree or a data
file shorter than the pages its meta page refers to.  Use `backupwallet`.

### Taking a backup

1. Leave the node running.  `backupwallet` waits for open wallet handles to
   drain and serialises the copy against wallet writes; block processing
   continues.
2. Choose a destination that is either absent or an empty directory.  An
   existing directory is treated as a backup root, matching the Berkeley DB
   command, so the environment is written to `<destination>/wallet`:

   ```
   phoenixcoind backupwallet /media/backup/phoenixcoin-2026-11-03
   ```

3. The command copies the live environment with LMDB's compact copy
   (`MDB_CP_COMPACT`) into a hidden sibling staging directory.  It then runs a
   full record scan over the staged copy and requires the same committed entry
   count as the source.  Only after both checks pass is the staging directory
   renamed to the final destination.  A failed copy or verification removes the
   staging directory and leaves the live wallet and any existing destination
   untouched.

   A compact copy contains `data.mdb` only; it has no `lock.mdb` and is safe to
   place on read-only media.  Compaction also resets the LMDB transaction ID,
   so the copy's transaction counter is deliberately not compared with the
   source.

4. Verify the result independently, then copy the verified directory to a
   second medium if the backup matters:

   ```
   phoenixcoind -checklmdb=/media/backup/phoenixcoin-2026-11-03/wallet -checklmdbdeep
   ```

   A non-zero exit status means the backup is not usable.  Do not delete the
   previous good backup until this check and a restore test have passed.

`backupwallet` refuses a destination that exists as a regular file, and it
refuses a non-empty `<destination>/wallet`.  Choose a new path or remove the
old backup deliberately; the command will not overwrite one.

### Restoring a backup

1. Stop the node and keep the current wallet directory, in case the restore is
   the wrong choice:

   ```
   mv ~/.phoenixcoin/wallet ~/.phoenixcoin/wallet.failed
   ```

2. Copy the verified backup into place.  Copy `data.mdb` only; do not copy a
   stale `lock.mdb` from another host:

   ```
   mkdir ~/.phoenixcoin/wallet
   cp /media/backup/phoenixcoin-2026-11-03/wallet/data.mdb ~/.phoenixcoin/wallet/
   ```

3. Confirm that `~/.phoenixcoin/wallet.backend` still contains `lmdb`, then
   verify the restored environment offline before starting:

   ```
   phoenixcoind -checklmdb=$HOME/.phoenixcoin/wallet -checklmdbdeep
   ```

4. Start with the LMDB wallet selected:

   ```
   phoenixcoind -walletbackend=lmdb
   ```

5. Check `getdbinfo`: `wallet.data_file.complete` must be `true`,
   `wallet.opened_cleanly` must be `true`, and the `wallet.database.entries`
   count must match the count reported when the backup was taken.  Then confirm
   a known address with `validateaddress` and `dumpprivkey`, and make a small
   outgoing transaction if the wallet holds spendable coins.

A backup is a point-in-time snapshot.  Keys and transactions created after it
were not captured.  New addresses come from the pre-generated keypool, so a
key created after the backup may still exist in the restored wallet even though
its address-book entry and transaction history do not.

### Restoring the chain index

There is no online chain-index backup command.  To back up `blkindex/`,
`blkindex.backend`, `blk0001.dat` and `txleveldb` consistently, stop the node
first and copy the whole data directory.  A live `cp`/`rsync` of `blkindex/` is
subject to the same torn-copy risk as the wallet.  If only the wallet matters,
`backupwallet` is safe while the node runs.

If the chain index is lost or incomplete, restore a stopped-node backup.  There
is no `-reindex` mode in this codebase; if no backup exists, remove `blkindex/`
and `blkindex.backend` (or `blkindex.dat` for Berkeley DB) and let the node
download the chain again.

## Offline verification

`-checklmdb` checks an LMDB environment without starting a node and without
modifying it:

```
phoenixcoind -checklmdb=<directory> [-checklmdbdeep]
```

The directory may contain `data.mdb` directly, or be a backup root containing
`wallet/` or `blkindex/`; the command descends into the matching subdirectory.
`-checklmdbdeep` reads every record through a cursor, which exercises the
B-tree pages rather than only the meta page and database header.  Without it
the check is fast and validates the file size, meta pages and main database
header.

The check:

- requires the directory and `data.mdb` to exist;
- requires at least two LMDB meta pages and a data file covering every page the
  active meta page refers to;
- opens the environment read-only with `MDB_RDONLY | MDB_NOLOCK | MDB_NOTLS`, so
  it does not create `lock.mdb`, works on a read-only filesystem, and leaves
  `data.mdb` byte-for-byte unchanged;
- requires the `main` sub-database;
- with `-checklmdbdeep`, reads every key and value and reports the entry count.

It prints one field per line and ends with `result: OK` or `result: FAILED`.
The exit status is `0` only on success; a bare `-checklmdb` is an error and
requires an explicit directory.  Typical failures are:

```
data.mdb is missing
data.mdb is only 4096 bytes, too small to contain two LMDB meta pages
data.mdb is truncated: 8192 bytes on disk but the meta page refers to 12288 bytes
cannot open data.mdb: MDB_INVALID: File is not an LMDB file
main sub-database is missing or unreadable
```

The same check is available over RPC while the node is running:

```
phoenixcoind checklmdb <directory> [full]
```

`full` is a boolean and selects the full record scan.  The RPC returns an
object with `ok`, the same counters and a human-readable `error`; it reports
`ok: false` rather than throwing for verification failures.  It refuses an
environment that the running node has open, so use `getdbinfo` for live
diagnostics.  A backup root is accepted, and the result's `path` field shows
the environment that was actually checked.

Neither form is a substitute for a restore test.  Verification proves the
environment is structurally complete and readable; restoring it and checking a
known address proves the data is the state you intended to keep.

## Options

- `-dbbackend=lmdb|bdb` — chain index backend, default `bdb`.
- `-lmdbmapsize=<MiB>` — initial size of the LMDB chain index map.  The default
  is 4096 MiB on 64-bit platforms and 1024 MiB elsewhere.  If the existing
  environment is larger it is reopened at its current size.  The value must be a
  positive integer; values that are not representable or that exceed the
  platform's LMDB address-space limit are rejected at startup.  32-bit builds
  accept at most 2048 MiB, and the converted byte count must be a multiple of
  the system page size.
- `-lmdbmaxmapsize=<MiB>` — automatic chain index map growth ceiling, default
  1 TiB on 64-bit platforms and 2048 MiB elsewhere.  If `-lmdbmaxmapsize` is less
  than `-lmdbmapsize` startup fails.
- `-lmdbruntimegrow=<0|1>` — default `1`.  Grow the LMDB map automatically when
  a write transaction would exhaust the map.  When disabled the map is fixed at
  `-lmdbmapsize` (and `-lmdbmaxmapsize` is ignored).
- `-lmdbnosync=<0|1>` — default `1`.  Commits do not fsync, matching Berkeley
  DB's `DB_TXN_WRITE_NOSYNC` behaviour and avoiding an fsync per block during
  initial sync.  Transactions remain atomic and consistent.  Set to `0` for
  per-commit durability.  A clean shutdown always flushes the environment.
  This option applies to both LMDB environments.
- `-walletbackend=lmdb|bdb` — wallet backend, default `lmdb`.
- `-lmdbwalletsize=<MiB>` — initial size of the LMDB wallet map, default
  4096 MiB on 64-bit platforms and 256 MiB elsewhere.  It is validated like
  `-lmdbmapsize`, enlarged automatically when the existing wallet or a pending
  `wallet.dat` migration needs more room, and grows automatically at runtime
  subject to `-lmdbmaxwalletsize`.
- `-lmdbmaxwalletsize=<MiB>` — automatic wallet map growth ceiling, default
  1 TiB on 64-bit platforms and 2048 MiB elsewhere.  If less than
  `-lmdbwalletsize` startup fails.

## Map usage and growth

At startup Phoenixcoin prints how much of the LMDB map is in use:

```
LMDB chain index: 123.4 of 4096.0 MiB used
```

When the mapped file is already larger than the configured initial map size,
the map is enlarged automatically at open time, so a datadir created with a
larger `-lmdbmapsize` can be started without repeating the option.  The wallet
behaves the same way: an existing `wallet/` is reopened large enough for
`data.mdb`, and a pending `wallet.dat` migration reserves space from the source
file before the copy starts.

With `-lmdbruntimegrow=1` (the default), a write that exhausts the map does not
fail the operation.  Phoenixcoin aborts the LMDB transaction, waits until no
other transaction in the process is active, doubles the map (clamped to the
page-aligned ceiling), and replays the writes and erases already performed by
the caller in a fresh transaction.  The whole retry happens inside the original
`Write()`, `Erase()` or `Commit()` call, so callers still see a single
transaction and a partially committed state is never visible.  If the grown map
is still too small for the transaction, the sequence repeats until
`-lmdbmaxmapsize` or `-lmdbmaxwalletsize` is reached.  Each growth is logged:

```
LMDB map size increased from 1073741824 to 2147483648 bytes to recover from a
full map (-lmdbmapsize, maximum 1099511627776 bytes)
```

Replay records logical operations (a write with its overwrite flag, or an
erase), not the pages they dirtied, so a transaction containing a failed
`MDB_NOOVERWRITE` write such as a duplicate-key insert is replayed with the same
outcome.  Recorded keys and values are cleansed when the transaction ends.

Two limits apply:

- Replay needs a fresh LMDB transaction.  A transaction that has an open cursor
  or iterator cannot be replayed, because the cursor would still point into the
  aborted transaction.  Such a write fails safely with a message naming the map
  option; abort the transaction and retry it.
- Automatic growth stops at the configured ceiling.  A write that still fails
  there reports `LMDB map is full` and names both the initial-size and ceiling
  options.  Stop the node and raise `-lmdbmapsize` / `-lmdbmaxmapsize` (or the
  wallet equivalents) before restarting.

`-lmdbruntimegrow=0` disables online growth: the initial map size is the fixed
limit and a full map fails the write with the same message.  This is useful when
map size must be fixed by deployment policy.  Growth changes only the
address-space limit; the data file stays sparse, and `utilization_percent`
continues to describe committed pages.

## Health diagnostics

`getdbinfo` reports the state of both database backends without inspecting
`data.mdb` by hand:

```
phoenixcoind getdbinfo
```

The result has a `chain` and a `wallet` object with the same shape:

```
{
  "chain" : {
    "configured_backend" : "lmdb",
    "active_backend" : "lmdb",
    "lmdb_enabled" : true,
    "opened_cleanly" : true,
    "environment_open" : true,
    "database_open" : true,
    "path" : "/home/user/.phoenixcoin/blkindex",
    "marker" : {
      "present" : true,
      "value" : "lmdb",
      "matches_backend" : true
    },
    "data_file" : {
      "directory_exists" : true,
      "present" : true,
      "bytes" : 184549376,
      "lock_present" : true,
      "complete" : true,
      "reason" : ""
    },
    "environment" : {
      "map_size" : 4294967296,
      "max_map_size" : 1099511627776,
      "auto_grow" : true,
      "page_size" : 4096,
      "used_bytes" : 184549376,
      "free_bytes" : 4110417920,
      "utilization_percent" : 4.29,
      "last_page" : 45055,
      "last_txn_id" : 918273,
      "max_readers" : 126,
      "readers" : 0,
      "writer_active" : false,
      "read_only" : false,
      "nosync" : true
    },
    "database" : {
      "entries" : 128439,
      "depth" : 2,
      "branch_pages" : 12,
      "leaf_pages" : 3102,
      "overflow_pages" : 0,
      "page_size" : 4096
    },
    "error" : ""
  },
  "wallet" : { ... }
}
```

Field meanings:

- `configured_backend` is what the command line selected; `active_backend`
  and `lmdb_enabled` describe what startup actually opened.
- `marker` reports the `blkindex.backend` / `wallet.backend` file.  A missing
  marker matches Berkeley DB; `marker.matches_backend` is false if the marker
  and the active backend disagree, which is a migration or startup problem
  rather than a healthy state.
- `opened_cleanly` is true when both the LMDB environment and its main
  database handle opened successfully.  `environment_open`, `database_open`
  and `error` narrow down a false value.  Berkeley DB reports `opened_cleanly`
  as true and leaves the LMDB counters at zero.
- `data_file` is the on-disk inspection that startup uses before opening the
  environment.  `present` and `bytes` describe `data.mdb`, `lock_present`
  reports `lock.mdb`, and `complete` is false for an empty, missing or
  truncated file.  `reason` explains an incomplete state, for example
  `data.mdb is missing` or `data.mdb is only 4096 bytes, too small to contain
  two LMDB meta pages`.  A healthy live LMDB backend has `complete: true` and
  an empty `reason`; Berkeley DB leaves these fields false/zero.
- `environment.map_size` is the current map limit (the configured initial size
  or a size chosen while opening or growing), not a preallocated file size.
  `max_map_size` is the automatic growth ceiling and `auto_grow` reports
  whether runtime growth is enabled.  `used_bytes` is the copy-on-write file
  footprint, `(last_page + 1) * page_size`.  `free_bytes` is the remaining map
  space before writes fail with `MDB_MAP_FULL`, and `utilization_percent` is
  `used_bytes / map_size`.
- `environment.readers`, `max_readers` and `writer_active` show current LMDB
  transaction state.  `read_only` and `nosync` report the environment open
  flags.
- `database` contains the `mdb_stat()` counters for the main sub-database:
  live entries, B-tree depth, and branch, leaf and overflow page counts.

The free-space figure is an estimate: LMDB reuses free pages inside the file
before extending it, so `used_bytes` tracks the high-water mark rather than
the sum of live records.  A growing `utilization_percent` with a small
`free_bytes` is the signal to stop the node and raise the initial size or the
growth ceiling (`-lmdbmapsize` / `-lmdbmaxmapsize`, or the wallet equivalents).
When `auto_grow` is true and `map_size` equals `max_map_size`, the next full map
can no longer grow.

`getdbinfo` only reads counters in a short-lived read transaction; it does not
modify either environment.

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
- an explicit BDB start is refused while `wallet.backend` says `lmdb`;
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

### Backup, verification and restore validation

`regression_lmdb_wallet_backup.sh` passed 52/52 checks against a real daemon.
It follows the operator workflow described above:

- creates an LMDB wallet with a known address and key;
- takes an online `backupwallet` to a new path, requires the compacted copy to
  contain `data.mdb` and no `lock.mdb`, and restores both the address and its
  private key;
- runs `-checklmdbdeep` and the `checklmdb` RPC against the backup and checks
  that `data.mdb` keeps its SHA-256 checksum and no `lock.mdb` appears;
- writes an existing-directory backup to `<destination>/wallet`, auto-descends
  into that subdirectory for both check forms, and refuses a non-empty
  `<destination>/wallet`, a regular-file destination, and leaves no staging
  directory behind after a refusal;
- rejects a data file truncated to its two meta pages, zeroed meta pages and
  an empty directory through both the standalone command and the RPC;
- starts against a truncated live wallet and requires a non-zero exit, a clear
  `LMDB wallet ... is incomplete` error, and an unchanged `wallet.backend`;
- restores the point-in-time backup into the live datadir and proves that the
  pre-backup address and label survive while an address-book entry created
  after the backup is gone; then creates a new address, restarts, and signs
  with both the restored and the new key.

The unit tests `kvdb_tests/lmdb_environment_verify` and
`kvdb_tests/wallet_lmdb_backup` cover the same verifier and backup paths in
memory, including missing/non-directory/too-small/truncated/corrupt
environments, full-scan behaviour, non-mutation of the backup, inactive-wallet
failure, element-count mismatch detection, staging cleanup, and a restore that
reopens through the normal wallet code.

The make targets run the restore test in CI/nightly jobs:

```
cd src
make -f Makefile.linux check-lmdb-backup
make -f Makefile.linux nightly-lmdb
```

`check-lmdb-backup` builds the daemon and test binary, runs the two focused
unit tests, then runs `regression_lmdb_wallet_backup.sh`.  `nightly-lmdb` adds
the wallet and chain migration regressions.

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

## Wallet backend performance

`src/test/wallet_perf.cpp` is a standalone benchmark binary.  It is kept out
of `test_phoenixcoin` because the unit-test fixture deliberately uses an
in-memory Berkeley DB environment; on-disk timings and database sizes are only
meaningful against the real backends.  Build it with:

```
cd src
make -j4 DYNAMIC=1 -f Makefile.linux wallet_perf
```

The benchmark has three phases.  `seed` creates one realistic Berkeley DB
wallet, `bdb` and `lmdb` restore independent copies of that seed and run the
identical operations on each backend.  The seed used below contained 10,000
transactions (one to three inputs and two to three outputs each), 1,000 legacy
keys, 200 redeem scripts, 200 watch-only scripts, 200 address book labels and
a 100-key keypool; its `wallet.dat` was 6.43 MB.  After seeding, each measured
run inserted 2,000 more transactions, generated 500 keys, performed 1,000,000
in-memory lookups and 5,000 direct record reads, added 500 of each
script/label record, and refilled a 100-key keypool.

The numbers below are medians of three runs on an Intel Xeon E3-1220L (four
threads) with an ext4 filesystem on NVMe, so they include real writeback.
Both backends run with their normal no-sync commit setting; the final flush is
included in shutdown.

| Metric | Berkeley DB | LMDB | Difference |
| --- | ---: | ---: | ---: |
| Startup, environment open | 17.2 ms | 0.40 ms | 43x faster |
| Startup, wallet load | 443.4 ms | 334.0 ms | 1.33x faster |
| Startup, total | 459.7 ms | 334.4 ms | 1.37x faster |
| Migration, source env open plus copy | n/a | 70.1 ms | (copy itself 50.0 ms) |
| Shutdown | 47.0 ms | 76.0 ms | see note |
| Transaction lookup, loaded map | 3.26 us/op | 3.32 us/op | about equal |
| Transaction lookup, direct record | 5.64 us/op | 3.92 us/op | 1.44x faster |
| Transaction insertion | 8.35 ms/op (120 tx/s) | 60.7 us/op (16,469 tx/s) | 138x faster |
| Key insertion | 4.41 ms/op | 0.124 ms/op | 36x faster |
| Keypool refill | 434.7 ms (230 keys/s) | 15.2 ms (6,592 keys/s) | 29x faster |
| Add redeem script* | 4.19 ms/op | 16.5 us/op | 253x faster |
| Add watch-only script* | 4.27 ms/op | 11.8 us/op | 362x faster |
| Address book label* | 4.31 ms/op | 24.0 us/op | 179x faster |
| Wallet file after the run | 7.79 MB | 7.68 MB | 1.4% smaller |
| Whole data directory after the run | 18.27 MB | 24.60 MB | not comparable |

\* This wallet format has no descriptor records.  The rows marked with an
asterisk measure the closest persisted operations it does have:
`AddCScript`, `AddWatchOnly` and `SetAddressBookName`.

The large insertion gap is not a generic Berkeley DB versus LMDB claim.  Every
wallet write constructs a short-lived `CWalletDB`, and `CDB::Close()` runs
`txn_checkpoint()` on the Berkeley DB environment.  The wallet therefore pays
a checkpoint and synchronization on essentially every record write.  LMDB
keeps one environment open, commits without forcing a checkpoint per record,
and flushes it on close.  That is the real behavior of the current wallet
code, but the comparison should be read as "this BDB wallet path" versus "this
LMDB wallet path", not as a storage-engine microbenchmark.

The same accounting explains shutdown.  Berkeley DB has already paid its
synchronization costs during insertion; LMDB's close includes the final flush.
Taken as one unit, inserting 2,000 transactions and shutting down took about
16.75 s on BDB and 0.20 s on LMDB.  The in-memory lookup measures the loaded
`mapWallet` and wrapper overhead rather than either backend.

Database sizes need similar care.  The Berkeley DB whole-directory figure
includes its preallocated `database/` logs.  The LMDB directory still contains
the retained source `wallet.dat` and the Berkeley DB environment used for
migration, so only the wallet files are directly comparable.  Immediately
after migration, LMDB occupied 4.97 MB versus the 6.43 MB Berkeley DB source
because migration compacts the records; after the additional writes it had
grown to 7.68 MB, slightly below the 7.79 MB Berkeley DB wallet.

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
