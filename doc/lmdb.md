# LMDB chain index backend

Phoenixcoin stores the block index and the transaction/UTXO index in the chain
database.  Berkeley DB (`blkindex.dat`) remains the default backend; LMDB can be
selected explicitly with `-dbbackend=lmdb`.

Wallet and address storage are not affected.  `wallet.dat` stays on Berkeley DB
and is not migrated.

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
  same reason.

## Returning to Berkeley DB

Back up the data directory, then remove both `<datadir>/blkindex` and
`<datadir>/blkindex.backend`.  Phoenixcoin will start with Berkeley DB again and
use the untouched `blkindex.dat`.  Any blocks imported while LMDB was active
must be re-downloaded or re-imported, because that work only exists in the LMDB
index.

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

## Recovery

LMDB never overwrites committed pages in place, so an interrupted process leaves
the last committed transaction intact.  With `-lmdbnosync=1` a system crash or
power loss may lose the most recent commits, but the environment stays
consistent and is reconciled on the next start.

There is no `-reindex` mode in this codebase, and blocks are not replayed from
the `blk0001.dat` files.  If the index is lost, remove the chain index
(`blkindex/` and `blkindex.backend` for LMDB, or `blkindex.dat` for Berkeley DB)
and the node creates a fresh index containing only the genesis block, then
downloads the chain again.  Keeping `blkindex.dat` after removing the LMDB
directory only re-imports the index as it was at migration time.
