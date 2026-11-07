# LMDB chain index backend

Phoenixcoin stores the block index, the transaction/UTXO index and the wallet
in LMDB.  LMDB is the only supported backend; Berkeley DB support has been
removed.  Address storage (`peers.dat`) is unaffected.

A data directory from the Berkeley DB era must be converted offline before
this daemon will start.  The converter was archived after the migration
window; see [`archive/bdb-migration.md`](archive/bdb-migration.md) for the
operator procedure, backup and disk-space requirements, verification steps and
failure recovery.  The daemon itself never reads a Berkeley DB file.

## Chain index backend

The chain index lives in `<datadir>/blkindex/`.  On startup:

- a missing index is created empty;
- an existing non-empty index is opened;
- the LMDB environment itself is authoritative.  Current builds do not write a
  backend marker; a complete existing `blkindex/` is used, while an incomplete
  one fails rather than being silently replaced;
- `<datadir>/blkindex.backend` is legacy state left by a migration-window
  build.  If it says `lmdb`, a missing or empty `blkindex/` is treated as data
  loss and startup fails;
- a legacy `bdb` marker means the data directory has not been converted.
  Startup fails and points at the archived converter; it never opens the
  legacy `blkindex.dat` as an empty LMDB index;
- a legacy `blkindex.dat` without an LMDB index also fails explicitly and
  points at the archived converter.

The daemon no longer imports a Berkeley DB chain index at startup, and there is
no option to select a backend.  The archived converter wrote the marker only
after it had verified the new environment, so an interrupted conversion is
never adopted as a live index.

## Wallet backend

The wallet lives in `<datadir>/wallet/` and follows the same rules.  It is an
LMDB environment directory, not a single file.  Current builds do not create a
`wallet.backend` marker; the LMDB environment is authoritative.  A legacy
Berkeley DB `wallet.dat` is never read by the daemon; only the archived
converter can read it, and it leaves the file unchanged.

An incomplete LMDB wallet, or a legacy marker that says `lmdb` while the wallet
is missing or empty, fails startup instead of creating an empty wallet.  A
legacy `bdb` marker, or a legacy `wallet.dat` without an LMDB wallet, also fails
explicitly and points at the converter.

`-salvagewallet` and the removed Berkeley DB backend options
(`-walletbackend`, `-dbbackend`, `-detachdb`, `-privdb`, `-dbcache`,
`-dblogsize`) fail explicitly with `Berkeley DB support has been removed.` and
the instruction to run `phoenix-db-migrate`.

An LMDB wallet is an environment directory, so `backupwallet <destination>`
writes a directory, not a single file.  If `<destination>` is an existing
directory the copy is written to `<destination>/wallet`; otherwise
`<destination>` names the new backup directory.  The target must not exist yet
or must be empty; an existing non-empty target is refused instead of being
overwritten.

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

3. Verify the restored environment offline before starting:

   ```
   phoenixcoind -checklmdb=$HOME/.phoenixcoin/wallet -checklmdbdeep
   ```

4. Start the node:

   ```
   phoenixcoind
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

There is no online chain-index backup command.  To back up `blkindex/` and
`blk0001.dat` consistently, stop the node first and copy the whole data
directory.  If the installation has a legacy `blkindex.backend` marker, keep it
with the backup.  A live `cp`/`rsync` of `blkindex/` is subject to the same
torn-copy risk as the wallet.  If only the wallet matters, `backupwallet` is
safe while the node runs.

If the chain index is lost or incomplete, restore a stopped-node backup.  There
is no `-reindex` mode in this codebase; if no backup exists, remove `blkindex/`
(and any legacy `blkindex.backend`) and let the node download the chain again.

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
- `-lmdbnosync=<0|1>` — default `0`.  Each commit fsyncs, using LMDB's
  strongest normal durability mode.  Set to `1` to skip fsync and avoid an
  fsync per block during initial sync; transactions remain atomic and
  consistent, but a system crash may lose the most recent commits.  A clean
  shutdown always flushes the environment.  `MDB_WRITEMAP`, `MDB_MAPASYNC` and
  `MDB_NOMETASYNC` are never enabled.  This option applies to both LMDB
  environments.
- `-lmdbwalletsize=<MiB>` — initial size of the LMDB wallet map, default
  4096 MiB on 64-bit platforms and 256 MiB elsewhere.  It is validated like
  `-lmdbmapsize`, enlarged automatically when the existing wallet needs more
  room, and grows automatically at runtime subject to `-lmdbmaxwalletsize`.
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
`data.mdb`.

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
      "nosync" : false
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

- `configured_backend` is `lmdb`; `active_backend` and `lmdb_enabled` describe
  what startup actually opened.
- `marker` reports a legacy `blkindex.backend` / `wallet.backend` file when one
  is present.  Current builds do not create these files, so `present: false` is
  normal.  `matches_backend` is true when no legacy marker exists or when it
  says `lmdb`; it is false for a `bdb` or unknown marker, which is a startup
  problem rather than a healthy state.
- `opened_cleanly` is true when both the LMDB environment and its main
  database handle opened successfully.  `environment_open`, `database_open`
  and `error` narrow down a false value.
- `data_file` is the on-disk inspection that startup uses before opening the
  environment.  `present` and `bytes` describe `data.mdb`, `lock_present`
  reports `lock.mdb`, and `complete` is false for an empty, missing or
  truncated file.  `reason` explains an incomplete state, for example
  `data.mdb is missing` or `data.mdb is only 4096 bytes, too small to contain
  two LMDB meta pages`.  A healthy live backend has `complete: true` and an
  empty `reason`.
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
entry whose database record was rolled back.  This applies to the chain index
and the wallet.

### Bulk block import

`-loadblock` (and a `bootstrap.dat` file at startup) normally writes each block
in its own transaction.  While the node is below the checkpoint estimate, the
importer groups consecutive best-chain blocks into one chain-index
transaction.  A batch only starts when all of the following hold:

- the chain index is open in read-write mode;
- the node is in initial block download and `nBestHeight` is below
  `Checkpoints::GetTotalBlocksEstimate()`;
- the mempool and both orphan pools are empty;
- the next block extends the current best tip.

This keeps the batch on the linear startup import path and away from the
height where `ConnectInputs()` starts performing full signature checks.  A
batch is capped at 1000 blocks or 64 MiB of serialized block data, whichever
comes first.  A side chain, a reorganisation, a non-contiguous file or the end
of the checkpoint-free window commits the open batch and then uses the normal
per-block path.

The in-memory block index, `pindexBest`, `nBestHeight`, `bnBestChainWork` and
the `pnext` links still advance block by block, so the next block in the file
validates against the correct predecessor.  If a block is rejected, or the
batch commit fails, the whole uncommitted unit is aborted: every block-index
entry added since the batch began is removed from `mapBlockIndex` and deleted,
the saved globals and `pnext` link are restored, and the import stops.
`LoadExternalBlockFile()` counts only blocks whose transaction committed.

Wallet notifications keep the per-block order. After the batch transaction
commits, the importer calls `UpdatedTransaction()` for the coinbase of the
block that preceded the batch and then for each intermediate block's coinbase;
the final block's coinbase is stored for the next best-block announcement.
Nothing is announced from an aborted or failed batch.

Blocks are appended to `blkNNNN.dat` before their index transaction, so an
aborted batch leaves unreferenced raw block bytes behind, exactly like a failed
single-block write.  A restart ignores them because only the chain index is
loaded.  `ConnectBlock()` still updates the wallet one transaction at a time
through its own database; a failure can therefore leave wallet history ahead
of the rolled-back chain index, the same limitation as the pre-existing
per-block failure path.  Batching does not relax durability: the batch commit
fsyncs with the default `-lmdbnosync=0`.

Re-importing a file that was partially processed skips blocks already present
in `mapBlockIndex` and continues scanning.  A genuinely rejected block stops
the import instead of retrying the same file position forever.

## Recovery

LMDB never overwrites committed pages in place, so an interrupted process leaves
the last committed transaction intact.  With `-lmdbnosync=1` a system crash or
power loss may lose the most recent commits, but the environment stays
consistent and is reconciled on the next start.

There is no `-reindex` mode in this codebase, and blocks are not replayed from
the `blk0001.dat` files.  If the index is lost, remove the chain index
(`blkindex/`, plus any legacy `blkindex.backend`) and the node creates a fresh
index containing only the genesis block, then downloads the chain again.

If a legacy marker says `lmdb` but the LMDB index is missing or empty, restore
`blkindex/` from a backup.  Removing the marker does not make the daemon read a
legacy `blkindex.dat`; the daemon never imports Berkeley DB data.  Use the
archived converter described in
[`archive/bdb-migration.md`](archive/bdb-migration.md) to rebuild an LMDB
index from a legacy source, or resynchronise from the network.

## Validation

The chain-index backend was validated on Linux x86-64 with a build configured
with `-fsanitize=address,undefined -fno-omit-frame-pointer` and LTO disabled.

- `kvdb_tests` passed 48/48 test cases in the normal build.  The chain-index
  subset that existed at the time (24 cases, 1238 assertions) also passed under
  AddressSanitizer and UndefinedBehaviorSanitizer with no sanitizer reports;
  that sanitizer run predates the later wallet, backup and runtime-growth
  suites.
- `regression_lmdb_import_batch.sh` passed 62/62 checks in the normal build:
  a four-block `-loadblock` import commits as one batch and survives a
  restart while announcing the pre-batch tip and each intermediate coinbase,
  a re-import skips known blocks and creates no second batch, a corrupted
  middle block rolls the uncommitted batch back to genesis without announcing
  any transaction, and an injected final commit failure restores the tip and
  block index in memory, leaves no batch entries after a restart and still
  allows a later clean import to reach the correct tip.
- The full unit suite passed 173 test cases with no errors in the normal build.
  Under sanitizers, on the earlier 153-case tree, it passed 140/141 test cases
  (40534/40535 assertions).  The only failure was the timing-sensitive
  `DoS_tests/DoS_checkSig` under sanitizer slowdown.  There were no
  AddressSanitizer errors.  The eight UndefinedBehaviorSanitizer reports were
  all in pre-existing non-LMDB code (`Hash160` on an empty vector,
  base32/base64 decoding, and empty-vector handling in `EvalScript`).

Crash recovery was checked with three `SIGKILL`/restart cycles during initial
sync at and above height 202135.  Every restart reopened the last committed tip
or a later one.  The tip block and its coinbase transaction remained readable
after every restart, and syncing continued to height 227811 with 665129
records.

The wallet tests in `kvdb_tests` cover the wallet marker, the startup action
matrix (existing, missing, migration required, new), `CWalletDB` routing,
commit/abort, persistence across an environment restart, and prefix scans
through `CDBScan`.  A dedicated regression covers the authority cases: with a
`bdb` marker, an existing `wallet.dat`, and a real LMDB environment left in
`wallet/`, startup is refused, the marker stays `bdb`, and the stale environment
is not adopted or modified.

`wallet_persistence_tests` compares wallet semantics, not record counts.  It
builds a wallet containing compressed and uncompressed keys, key metadata,
watch-only and redeem scripts, address labels, a default key, a populated
keypool, hybrid keys, hybrid address labels, and transactions with block
association, timestamps, order positions, labels, spent outputs and
abandoned/conflicted metadata.  After the LMDB environment is reopened it
requires:

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

Wallet write atomicity is covered by twelve failure-injection tests in
`wallet_persistence_tests`.  They use the test-only hooks
`SetTestWalletWriteFailure` and `SetTestWalletCommitFailure`, which make one
matching LMDB wallet write or wallet commit fail after an optional skip count.
The hooks are one-shot, inert until armed, and never affect
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
`wallet_atomic_hybrid_keypool_rollback` does the same for a hybrid keypool
top-up, failing the first, second and third `hyb` write; a final uninjected
top-up must commit the whole pool.

The ordinary ECDSA keypool has the same guarantee, with separate coverage for
each refill shape.  `wallet_atomic_ecdsa_new_key_pool_rollback` fails a
`keymeta` write, a `key` write and the refill commit in `NewKeyPool()`; the
pool was already cleared before the batch, but the failed batch must add no key
or metadata in memory, leave no records from the aborted batch, and match that
state after a restart.  `wallet_atomic_ecdsa_top_up_key_pool_rollback` does the
same for `TopUpKeyPool()`, where the entire wallet and database must remain
unchanged.  Both tests then run the same refill without injection and verify
the persisted pool entries, keys and metadata after another restart.

`wallet_atomic_add_to_wallet_new_and_update` covers the transaction write path
itself.  It fails the `orderposnext` write, the `tx` write and the commit of a
new `AddToWallet()` call, requiring the in-memory wallet and the record set to
match the pre-call state before and after a restart, then lets the identical
insert commit and verifies that the order position and transaction are
persisted together.  It also fails an update that merges block data, at both
the update's `tx` write and its commit; either failure must restore the
previous in-memory entry rather than leave it ahead of the rolled-back
database.  `wallet_atomic_add_to_wallet_default_key_rotation` pays the
current default key and fails the replacement `defaultkey` and `name` writes;
the old default key, address book, order position and transaction must all
remain unchanged apart from the already-consumed keypool entry, and the retried
call must commit the transaction, replacement key and label together.  (The
rotation test injects record failures rather than a commit failure because the
key selection's own keypool transactions consume the one-shot commit hook.)

`wallet_atomic_add_to_wallet_spent_batch` covers a transaction that both
arrives in the wallet and spends one of its coins.  It fails the
`orderposnext` write, the new `tx` write, the spent-coin `tx` write and the
commit.  After each failure the new transaction must be absent,
`nOrderPosNext` must keep its old value, the spent flag must remain clear, and
the record set must match the pre-call state before and after a restart.  The
retried call must persist the transaction, its order position and the spent
flag together and keep them after another restart.  Before the spent-coin
staging this case left the new transaction committed with the input unspent.

`wallet_atomic_commit_transaction_spent_batch` covers the send path.  It fails
the `orderposnext` write, the new `tx` write, each spent-coin `tx` write in a
two-input transaction and the commit of one `CommitTransaction()` call.  In
every case the new entry must disappear again, `nOrderPosNext` must return to
its old value, both an already-spent and an unspent input must keep their
previous flags, and the record set must match the pre-call state before and
after a restart.  The retried call must persist the new transaction, its order
position and both spent flags in one batch; spending the already-spent coin
again must still succeed.  The unit test chain has no index entry for these
coins, so the broadcast is rejected after the wallet batch and the test checks
persistence, not the return value.

`wallet_atomic_commit_single_input_change_retry` covers the single-input and
change shape.  It first lets the new `tx` record be staged and then fails the
spent-coin record, and separately fails a final commit for a second input.
After each failure no new `tx` record, order position or spent flag may
remain, in memory or after a restart.  The test then retries the identical
`CWalletTx` and requires exactly one new transaction record, the source
output's spent flag, and the persisted change marker, before and after a
final restart.  Together with the two-record batch this pins the invariant
that a logical wallet operation never persists its transaction record while
its spent-coin or required metadata updates are missing.

`wallet_commit_failure_does_not_broadcast` covers the send path's network
boundary.  It drives a spent-coin write failure after the new `tx` record was
staged and a final commit failure, both with a reserved change key held.  The
test-only broadcast counter hooks around the no-argument
`CMerkleTx::AcceptToMemoryPool()` and `CWalletTx::RelayWalletTransaction()`
must stay at zero, `mapRequestCount` must not gain the transaction, and the
wallet must neither persist a transaction nor mark the input spent before or
after a restart.  The reserved key's pool record must also survive, so a
failed send returns the key to the pool.  A final uninjected send shows that
the observation is live: mempool acceptance is attempted and the key is
consumed by the successful batch.  This pins the rule that a failed wallet
batch returns `false` before mempool acceptance and relay, so the network can
never receive a payment the wallet could not record.

`wallet_atomic_commit_transaction_default_key_rotation` pays the default key
from the send path.  It fails the replacement `defaultkey` write, then the
spent-coin write after the replacement key and label have already been staged;
the old default key, address book, order position, transaction and spent flag
must all roll back together, apart from the already-consumed keypool entry.
The retried commit must persist the transaction, spent flag, replacement key
and label together and survive a restart.  As in the `AddToWallet()` rotation
case, record failures are used because key selection's own keypool
transactions would consume a one-shot commit injection.

The keypool top-up path itself was made atomic for these tests:
`CWallet::EnsureHybridKeyPool` now generates and encrypts the whole batch
first, writes the ECDSA records and hybrid records in one database transaction,
and only registers the keys in memory after that transaction commits.  A
failure at any point leaves no partial pool behind.  The ordinary refill uses
`CWallet::StageNewKey()` and `CWallet::AddStagedKeyToMemory()` for the same
stage-commit-register sequence.

These suites pass in the normal build together with the rest of the unit suite.

`regression_lmdb_wallet_e2e.sh` passed 107/107 checks.  It drives a real
daemon through the full LMDB wallet lifecycle:

- imported coinbase keys, labelled receiving addresses, a watch-only address,
  a multisig script, a signed message, keypool state and labelled hybrid keys;
- real wallet transactions, including a hybrid-signed spend that reaches the
  mempool;
- `encryptwallet`, the shutdown it triggers, and an encrypted restart with
  wrong-passphrase, lock and unlock checks;
- additional keypool and hybrid state while the wallet is unlocked;
- a restart that verifies every key, label, transaction, signature, hybrid key
  and keypool path through RPC;
- normal use of the wallet: new addresses and labels, message signing, new
  hybrid keys, a keypool refill and a brand new hybrid-signed transaction;
- one final restart that proves the new state persisted.

This codebase has no regtest mode, and spending a mainnet coinbase normally
needs 101 confirmations.  The test therefore submits a fixed six-block chain
fragment.  Blocks 5 and 6 were mined once under the same consensus rules and
pay keys whose WIFs are embedded in the test; the test daemons are started
with `PHOENIX_TEST_COINBASE_MATURITY=0`.  The hook in `LoadBlockIndex` changes
`nBaseMaturity` only when that environment variable is present and parses as a
value between 0 and `BASE_MATURITY`; it is inert otherwise, applies only to the
test daemon process, and is not set by any normal startup path.

A daemon smoke test on a temporary data directory also covered the stage-3
wiring: the first start created `wallet/` (no backend marker is written) and
printed `Wallet database: LMDB`; `getnewaddress` worked, the address survived a
clean restart, and the keypool was refilled through the LMDB wallet;
`backupwallet` produced an environment that loaded the same addresses when
restored into a fresh data directory; and `encryptwallet` compacted and rewrote
the environment, with the encrypted wallet reopening and unlocking after
restart.

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
  `LMDB wallet ... is incomplete` error, and no backend marker creation;
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
the wallet lifecycle, crash and batch-import regressions.

## Wallet backend performance

`src/test/wallet_perf.cpp` is a standalone benchmark binary.  It is kept out
of `test_phoenixcoin` because the unit-test fixture deliberately uses a
throw-away data directory and smaller workloads; on-disk timings and database
sizes are only meaningful with a real environment.  Build it with:

```
cd src
make -j4 DYNAMIC=1 -f Makefile.linux wallet_perf
```

The benchmark has two phases.  `seed` creates one realistic LMDB wallet and
`lmdb` runs the measured operations on a copy of it:

```
src/wallet_perf seed /tmp/wallet-perf/seed
cp -a /tmp/wallet-perf/seed /tmp/wallet-perf/lmdb
src/wallet_perf lmdb /tmp/wallet-perf/lmdb
```

The seed used below contained 10,000 transactions (one to three inputs and two
to three outputs each), 1,000 legacy keys, 200 redeem scripts, 200 watch-only
scripts, 200 address book labels and a 100-key keypool.  After seeding, each
measured run inserted 2,000 more transactions, generated 500 keys, performed
1,000,000 in-memory lookups and 5,000 direct record reads, added 500 of each
script/label record, and refilled a 100-key keypool.

The table below is a historical comparison recorded before Berkeley DB support
was removed.  The numbers are medians of three runs on an Intel Xeon E3-1220L
(four threads) with an ext4 filesystem on NVMe, so they include real writeback.
Both backends ran with their normal no-sync commit setting; the final flush is
included in shutdown.  The LMDB column remains representative of the current
backend; the Berkeley DB column is retained for context only.

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

The transaction insertion, key insertion and keypool refill rows were measured
before the write batching described below, when `AddToWallet`, each key record
and each pool key committed separately; the current code issues fewer commits
for the same work.  A reduced insertion run (1,000 transactions against a
4,000-transaction seed) after `AddToWallet()` batching measured 19,457 tx/s on
the same host.

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

### Batched wallet writes

Wallet writes are grouped by logical operation instead of committing once per
record.  `CWalletDB::WriteKey` keeps `keymeta` and `key` in one transaction;
`WriteCryptedKey` keeps `keymeta`, `ckey` and the removal of any plaintext
`key`/`wkey` copies in one transaction.  Both join an already open transaction
instead of starting a nested one.

A keypool refill batches further.  `CWallet::NewKeyPool` commits the cleared
pool and the new pool as one transaction per phase, and
`CWallet::TopUpKeyPool` commits the whole batch at once.  Keys generated during
the refill are persisted through the refill's existing `CWalletDB` handle, so
the batch shares one LMDB writer rather than opening a second one for each key.
They are also staged outside the in-memory keystore and inserted only after the
batch commits.  A failed `keymeta`/`key` write or a failed commit therefore
leaves no orphaned key or metadata behind in the running wallet, matching the
rolled-back on-disk state.

`CWallet::AddToWallet` commits a complete wallet update at once.  A new
transaction writes `orderposnext` and its `tx` record in one transaction;
when the transaction pays the current default receiving key, the replacement
`defaultkey` and its empty address-book `name` entry join the same transaction.
Wallet-owned coins spent by the incoming transaction are marked and their
`tx` records rewritten in that transaction too, replacing the separate
`WalletUpdateSpent()` write that used to follow the commit.  Records keep their
previous order, so replay sees the same sequence as the old individually
committed writes.  A failed write or commit restores an existing entry, the
order position, the default key, the address book and every spent flag instead
of leaving a merged copy in memory.  The replacement key is selected before
the transaction opens: `GetKeyFromPool()` may top up or trim the keypool, and
those paths open their own writer, so a consumed pool key remains the only
state that a later failure does not roll back.

`CWallet::CommitTransaction` uses the same staging helpers to commit the send
path as one update.  The new transaction's `orderposnext` and `tx` records,
any replacement `defaultkey` and `name` pair, and every spent-coin `tx` record
share one transaction.  Outputs that were already spent are rewritten exactly
as before.  The in-memory transaction, order position, default key and spent
flags change only after the commit succeeds.  A failed write or commit
restores them, returns `false` and stops before mempool acceptance or relay,
so the network never receives a payment the wallet could not record.  The
reserved change key is kept only after the batch commits, so a failed send
returns it to the keypool instead of consuming it.

`CWalletTx::WriteToDisk()` still supports its standalone form.  Callers that
do not batch -- `WalletUpdateSpent`, `ReacceptWalletTransactions` and
`ZapWalletTransactions` -- keep writing one record per commit.  The batched
callers pass the handle of the transaction they opened, so a write never
starts a nested transaction or commits ahead of the surrounding batch.

Batching removes redundant commits; it does not relax durability.  With the
default `-lmdbnosync=0` every remaining commit still fsyncs, and the crash
regression keeps its per-record coverage: `wallet-write-before-commit:<type>`
fires while a record is staged, and `wallet-write-after-commit:<type>` is
deferred until the whole transaction is durable.

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
environment or stop the process.  It never disables LMDB: the LMDB environment
remains authoritative (a legacy `wallet.backend` marker, if present, still says
`lmdb`), and a Berkeley DB fallback would accept writes that the next LMDB
start could not see.  The failure paths are:

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

`wallet_persistence_tests/wallet_encryption_rewrite_failure_is_not_success`
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
| `kvdb_tests/wallet_*`, `wallet_persistence_tests`, `accounting_tests` | 15 cases, 12441 assertions |
| `regression_lmdb_wallet_e2e.sh` | 107/107 |
| `regression_lmdb_wallet_crash.sh` | 359/359 |
| full wallet suite (the unit cases above plus `wallet_tests`) | 17 cases, 21550 assertions |
| full unit suite | 158 cases |

These runs were recorded on the 158-case tree that existed when the wallet
backend was validated, before Berkeley DB was removed; the script totals are
from that version. The current normal-build suite is 173 cases, and the crash
regression now covers normal operation and the encryption rewrite only.

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
wallet, never to the chain index.

The crash points cover the wallet lifecycle:

- per-record writes: `wallet-write-{before,after}-commit:<type>`, where the
  type is the record family (`tx`, `name`, `key`, `pool`, `hyb`, ...), so a
  case can target one write without counting unrelated records;
- explicit transactions: `wallet-txn-{before,after}-commit` (hybrid import,
  keypool top-up, `AddToWallet`, `CommitTransaction` and encryption rewrite);
- the encryption rewrite: `wallet-rewrite-{after-copy,after-old-rename,
  after-install}`.

The script builds a reference LMDB wallet on the same fixed mainnet fragment
and gives every case its own datadir copy, so no case can influence another
and the user's real datadir is never touched.  The cases fall into two groups:

- **A. Normal operation.**  Sends, receiving (`importprivkey`), labels,
  keypool refills, hybrid imports and `encryptwallet` are killed on either
  side of their commit.  Before the commit the operation must be absent
  after restart and remain repeatable; after it the operation and its
  effects must be complete and intact.  Because `AddToWallet` and
  `CommitTransaction` write `orderposnext`, the transaction, any replacement
  default-key/label records and the spent flags in one transaction, a kill on
  either side of the commit cannot leave the order position ahead of the
  transaction, a rotated default key without its label, or a transaction
  without the spent state of its inputs.
- **B. Encryption rewrite.**  The three rewrite boundaries above must take a
  deterministic startup path: an interrupted rewrite is completed, and a
  committed environment is adopted.

Interrupted `RewriteWalletLMDB` is repaired by
`RecoverInterruptedWalletRewrite`, called from
`InitLMDBWalletDBInternal`: if `wallet/` is missing it installs the staged
`wallet.rewrite` environment or restores `wallet.old`, otherwise it removes
the staging directories, and it removes a stale legacy `wallet.backend.tmp`.
`CWallet::ReacceptWalletTransactions` also repairs spent flags from the
wallet's own transactions before consulting the chain index, so a wallet
that committed a send but was killed before that bookkeeping still reports
the correct balance.
