# Migrating Berkeley DB databases to LMDB

`phoenix-db-migrate` converts a legacy Berkeley DB (BDB) data directory to the
LMDB layout used by current Phoenixcoin releases.

It handles the two persistent BDB databases:

| Scope | Legacy source | LMDB target | Marker |
|---|---|---|---|
| Wallet | `<datadir>/wallet.dat` | `<datadir>/wallet/` | `<datadir>/wallet.backend` |
| Chain index | `<datadir>/blkindex.dat` | `<datadir>/blkindex/` | `<datadir>/blkindex.backend` |

`peers.dat` is a plain serialized address file, not a Berkeley DB database, and
is not touched.

The converter is a standalone executable. It links Berkeley DB because it reads
the old files, but the daemon and GUI do not. It is intended for the transition
release and will be retired after the migration window.

---

## Before you start

1. **Stop Phoenixcoin completely.** Do not run the converter against a live
   data directory.
2. **Make a full copy of the data directory and verify the copy.** The
   original is never modified, but a verified backup is the only way to recover
   from an unrelated disk or operator error.
3. **Check free space.** The converter writes a complete second copy. Plan for
   at least **2×** the combined size of `wallet.dat` and `blkindex.dat`, and
   preferably **3×** so the verified backup, the source and the staging
   environment all fit. The LMDB map is sparse; the file grows as records are
   written.
4. **Expect downtime proportional to the copy.** Wallet migration normally
   takes seconds. Chain-index migration is proportional to the index size and
   can take minutes on slow disks. Both scopes copy under one lock, so the node
   must stay stopped until the command completes.

The source files keep their contents, permissions and modification times. The
converter opens them read-only and never deletes, renames or rewrites them.

---

## Basic migration

```bash
phoenix-db-migrate --datadir=/path/to/datadir
```

With no scope flags it migrates every BDB source that exists and skips the
missing one. To migrate a single scope:

```bash
phoenix-db-migrate --datadir=/path/to/datadir --wallet
phoenix-db-migrate --datadir=/path/to/datadir --chain
```

Useful options:

```text
--dry-run              Validate the sources and report record counts; write nothing
--verbose              Print progress every 100000 records
--map-size=<MiB>       Override the automatically chosen LMDB map size
--version              Print the converter version
--help                 Print the full option list
```

Exit codes: `0` success (including an already-migrated directory), `1`
migration failed and the sources are untouched, `2` invalid command line.

---

## What the converter verifies

For each scope it:

1. runs the Berkeley DB verifier on the source and aborts on any error;
2. checks that every record key starts with a valid serialized string, that
   `tx` and `blockindex` keys carry a 32-byte hash, and that the source contains
   a `version` record;
3. copies every raw key/value pair into one LMDB transaction, preserving the
   on-disk byte representation exactly;
4. reads every record back inside the same transaction and compares both key
   and value byte-for-byte;
5. counts the LMDB records and requires the count to match the source;
6. commits, reopens the environment read-only in a fresh handle, and counts
   again;
7. writes a completion sidecar, renames the verified staging environment into
   place, and only then writes the `lmdb` authority marker.

Unknown record prefixes are preserved and reported once. This lets wallets and
chain indexes written by older or newer releases migrate without the converter
needing to understand every record type.

The daemon performs the full application-level load on first start, so keys,
encrypted keys, HD/hybrid metadata, keypool entries, transactions, spent-output
state, address-book entries, watch-only entries, redeem scripts, labels,
ordering and chain-index records are additionally validated by the normal
startup path.

---

## Interrupted or repeated runs

The converter is restartable:

- a crash before the LMDB commit leaves only a stale staging directory, which
  the next run removes;
- a crash after the commit but before the install re-runs the copy;
- a crash after the install rename but before the marker is written is detected
  by the completion sidecar: the next run verifies the installed environment
  and writes the marker without recopying;
- a run against an already-migrated directory reports `already migrated` and
  changes nothing.

Re-running is always safe. Running with `--dry-run` and then for real is the
recommended first conversion on a production backup.

---

## Verify the result

Do not delete the BDB files immediately.

1. Confirm the markers and environments:

   ```bash
   cat /path/to/datadir/wallet.backend     # lmdb
   cat /path/to/datadir/blkindex.backend   # lmdb
   ls -l /path/to/datadir/wallet/data.mdb /path/to/datadir/blkindex/data.mdb
   ```

2. Start Phoenixcoin normally (LMDB is the default) and check:

   - balances and recent transactions;
   - `getaddressesbyaccount`, `listhybridaddresses`, `validateaddress` against
     known addresses;
   - `getinfo` keypool size and wallet version;
   - `getblockcount` and the chain tip;
   - `getdbinfo` reports `lmdb` for both scopes with a matching marker.

3. Use the node for a while before retiring the backup. Keep the original
   `wallet.dat`, `blkindex.dat` and the verified backup until you are
   confident.

---

## Failure and recovery

| Symptom | Meaning | Action |
|---|---|---|
| `needs Berkeley DB recovery and cannot be opened read-only` | The data directory was not shut down cleanly. | Stop any running node. Restore a verified backup, or copy the whole data directory, run `db_recover` on the copy, and migrate the copy. Never run recovery on the original in place. |
| `marker says LMDB, but the LMDB environment ... is missing` | The marker says LMDB is authoritative but the environment is gone. | Restore a verified backup. Do not delete the marker to force a re-import. |
| `target ... already exists and is not empty; refusing to overwrite` | A different LMDB environment already occupies the target and there is no completion marker. | Inspect it. If it belongs to another installation, move it aside deliberately; if you have a verified backup, restore and retry. |
| `marker ... contains an unsupported value` | The marker file is corrupt. | Restore the marker from a backup, or stop and investigate before deleting anything. |
| `Berkeley DB verification failed` | The source is corrupt. | Restore a verified backup and retry. The converter never creates a target from a failed source. |
| `record count mismatch` or `read-back does not match` | The copy did not verify (disk error, truncated source, concurrent writer). | Ensure no daemon is running, free disk space, and retry. The source is untouched. |

The converter never falls back to opening a BDB database as an empty LMDB
database. A marker that says LMDB requires a non-empty, readable environment; a
marker that says BDB is treated as authoritative until a successful migration
replaces it.

---

## After the migration window

Once LMDB-only releases are established, the source `wallet.dat` and
`blkindex.dat` can be archived and removed according to your normal backup
policy. Do not remove them before the LMDB installation has been used and
verified.
