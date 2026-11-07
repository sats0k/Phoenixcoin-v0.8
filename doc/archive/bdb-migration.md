# Historical Berkeley DB migration guide

Status: **historical**. Phoenixcoin no longer contains a Berkeley DB (BDB)
runtime, converter source, fixtures or migration tests. This guide is retained
for operators who still hold a pre-LMDB data directory and need to recover or
convert it with the archived converter release.

Related historical record:
[`bdb-removal-inventory.md`](bdb-removal-inventory.md).

---

## 1. Current behaviour

The daemon, GUI and standard test binaries use LMDB only and do not link
Berkeley DB. There is no implicit fallback and no build option that restores a
BDB runtime.

A data directory that still depends on Berkeley DB is refused at startup:

| On-disk state | Behaviour |
|---|---|
| `wallet/` and `blkindex/` present, markers say `lmdb` | Starts normally |
| No wallet or chain database | Creates empty LMDB environments |
| `wallet.dat` and/or `blkindex.dat` present, marker says `bdb` or is absent | Refuses to start and reports that the directory must be converted |
| `lmdb` marker but the LMDB environment is missing or empty | Refuses to start; restore a verified backup |
| Conflicting or corrupt markers | Refuses to start; investigate or restore a backup |

The obsolete options `-walletbackend=bdb`, `-dbbackend=bdb` and
`-salvagewallet` fail with:

```text
Berkeley DB support has been removed.
Please migrate your database to LMDB using phoenix-db-migrate.
```

Never delete a marker to force a BDB directory open as an empty LMDB database.
A `bdb` marker is authoritative until a verified conversion replaces it.

---

## 2. Getting the archived converter

The converter was published separately from the daemon during the migration
release cycle as a converter-only bundle:

```text
phoenix-db-migrate-<version>-<platform>/
    phoenix-db-migrate
    LICENCE
    CHANGELOG.md
    SHA256SUMS
    doc/
        db-migrate.md
        db-migrate-design.md
        lmdb-only-release.md
```

Use the archived binary, verify its published checksum and keep a copy of the
bundle with your backups. The converter source, test fixture and compatibility
tests have been removed from this tree; the last migration-window revision is
preserved in repository history and the published bundle is the recovery
artifact.

The converter links Berkeley DB and LMDB. It may need the Berkeley DB runtime
used by the machine that wrote the data directory; see section 4. The daemon
does not need Berkeley DB at runtime.

---

## 3. Migration procedure

1. **Stop Phoenixcoin completely.** Do not run the converter against a live
   data directory. Both scopes copy under one lock, so the node must stay
   stopped until the command completes.
2. **Make a full copy of the data directory and verify the copy.** The
   converter never modifies the sources, but a verified backup is the only
   recovery from disk faults or operator error.
3. **Check free space.** The converter writes a complete second copy. Plan for
   at least **2×** the combined size of `wallet.dat` and `blkindex.dat`, and up
   to **3×** when an old on-disk format must be upgraded on a temporary copy.
4. **Dry run first.**

   ```bash
   phoenix-db-migrate --datadir=/path/to/datadir --dry-run
   ```

   A dry run writes no target or marker. It may create and delete a temporary
   upgrade copy when the source uses an old Berkeley DB format.

5. **Convert.**

   ```bash
   phoenix-db-migrate --datadir=/path/to/datadir
   ```

   Use `--wallet` or `--chain` to convert a single scope. Without a scope flag
   every BDB source that exists is converted. `--verbose` prints progress, and
   `--map-size=<MiB>` overrides the automatically chosen LMDB map size.

6. **Verify the result.**

   ```bash
   phoenix-db-migrate --version
   cat /path/to/datadir/wallet.backend     # lmdb
   cat /path/to/datadir/blkindex.backend   # lmdb
   ls -l /path/to/datadir/wallet/data.mdb /path/to/datadir/blkindex/data.mdb
   ```

   Start the daemon and check balances, recent transactions,
   `getaddressesbyaccount`, `listhybridaddresses`, `validateaddress`, keypool
   size, `getblockcount`, the chain tip, and `getdbinfo` (both scopes must
   report `lmdb` with a matching marker).

7. **Keep the originals.** Do not delete `wallet.dat`, `blkindex.dat` or the
   verified backup until the LMDB installation has been used and backed up at
   least once.

The converter writes the `lmdb` marker only after the LMDB environment is
copied, verified and installed. Interrupted runs are restartable: a later run
removes stale staging state, verifies an environment completed by an earlier
run, or repeats the copy. A run against an already-migrated directory reports
`already migrated` and changes nothing.

### What the converter verified

For each scope it ran the Berkeley DB verifier, validated record keys, copied
every raw key/value pair in one LMDB transaction, read every record back
byte-for-byte, compared record counts inside and after the commit, reopened the
environment read-only, and only then installed it and wrote the marker. Unknown
record prefixes were preserved. The daemon's normal startup then performed the
full wallet and chain-index load.

---

## 4. Berkeley DB version compatibility

Data directories were written by different Berkeley DB releases. The converter
reports what it links:

```text
phoenix-db-migrate <version>
Berkeley DB library: 6.2.32 (compiled against 6.2.32)
LMDB library: 0.9.35
```

- A Berkeley DB library can read and verify a database written by the same or
  an older release. A newer library may upgrade an older on-disk format.
- A library older than the database's on-disk format cannot verify it. The
  converter then fails before writing a target and names the linked version.
  Use (or build) a converter linked against the writer's Berkeley DB version
  or newer.
- When an on-disk upgrade is needed, the converter copies the source to a
  hidden temporary file, upgrades and converts the copy, then deletes the copy.
  The original is never modified.
- A source written by a Berkeley DB newer than the linked library is not
  readable by that converter. Do not upgrade the original file in place; use a
  newer converter against the preserved source.
- The optional `check-db-migrate-compat` test built a fixture with an older
  `libdb_cxx` and verified the shipped converter could read it. It is no longer
  part of this tree, but the archived release notes record the combinations
  tested during the migration window.

---

## 5. Failure and recovery

| Symptom | Meaning | Action |
|---|---|---|
| `needs Berkeley DB recovery and cannot be opened read-only` | The data directory was not shut down cleanly. | Stop any node. Restore a verified backup, or copy the whole data directory, run `db_recover` on the copy, and convert the copy. Never run recovery on the original in place. |
| `marker says LMDB, but the LMDB environment ... is missing` | The marker says LMDB is authoritative but the environment is gone. | Restore a verified backup. Do not delete the marker to force a re-import. |
| `target ... already exists and is not empty; refusing to overwrite` | An LMDB environment occupies the target without a completion marker. | Inspect it and move it aside deliberately, or restore a verified backup and retry. |
| `Berkeley DB verification failed` | The source is corrupt, or it was written by a newer Berkeley DB than the converter links. | Restore a verified backup and retry. If the message names an older linked library, use a newer converter. No target is written from a failed source. |
| `cannot upgrade the temporary Berkeley DB copy` | The source needs an on-disk upgrade the linked Berkeley DB cannot perform. | Use a converter linked against a newer Berkeley DB. The original is unchanged. |
| `record count mismatch` or `read-back does not match` | The copy did not verify (disk error, truncated source, concurrent writer). | Ensure no daemon is running, free disk space, and retry. The source is untouched. |

The converter never opened a BDB database as an empty LMDB database. A marker
that says LMDB requires a non-empty, readable environment; a marker that says
BDB remained authoritative until a successful conversion replaced it.

If no suitable converter is available, the supported alternatives are to
restore a verified LMDB backup or, for the chain index, remove `blkindex/` and
`blkindex.backend` to create a fresh index and resynchronise from the network.
Wallet records cannot be recreated from the chain, so keep a verified wallet
backup.

---

## 6. Rollback and retention

Conversion is additive: the BDB source was never removed. Rollback means
restoring the data directory from the verified pre-conversion backup, not
running an old daemon against a half-converted directory.

- Keep the pre-conversion backup until the LMDB installation is proven.
- Keep the original `wallet.dat` and `blkindex.dat` until the LMDB environment
  has been backed up at least once.
- A restored backup must contain markers that match its contents. Do not mix a
  restored LMDB environment with a stale `bdb` marker or vice versa.
- If a conversion is interrupted, re-run the archived converter; do not delete
  markers or staging directories by hand unless the failure table above says
  to.
- Retire the archived converter and the original BDB files under your normal
  retention policy only after the LMDB installation has been used successfully.

---

## 7. Validation record

The conversion path was exercised end to end during the migration-window
release cycle. The last revision containing the converter source, the BDB
fixture and the converter regressions is commit `6fd6a948`; Phase 6 removed
them in commit `b9b95f60`.

On `6fd6a948`, the full `nightly-lmdb` target passed:

| Suite | Result |
|---|---|
| Boost unit suite | 173/173 test cases |
| `regression_db_migrate.sh` | 59/59 checks |
| `regression_db_migrate_compat.sh` | 8/8 checks |
| `regression_lmdb_wallet_backup.sh` | passed |
| `regression_lmdb_wallet_e2e.sh` | 99/99 checks |
| `regression_lmdb_wallet_crash.sh` | 237/237 checks |
| `regression_lmdb_import_batch.sh` | 62/62 checks |

The converter suite covered:

- plain, encrypted and hybrid wallets, and a four-block chain index;
- source hashes and record counts unchanged before and after conversion;
- both `lmdb` markers written only after a verified install;
- an encrypted wallet remaining encrypted and readable after conversion, and
  hybrid ECDSA/ML-DSA records surviving intact;
- dry runs, an already-migrated directory, ambiguous markers, a missing target
  and a corrupt source;
- interruption after N records, after the LMDB commit and after the install
  rename, each restartable without destroying the source.

The compatibility suite converted a fixture written by an older `libdb_cxx`
(for example 5.3) and verified the marker, the installed environment, the
converted record and the unchanged source.

To rebuild and re-run the archived converter from the migration-window
revision (Berkeley DB headers and libraries are required for this checkout
only):

```bash
git worktree add /tmp/phoenix-migrate 6fd6a948
cd /tmp/phoenix-migrate/src
make -f Makefile.linux DYNAMIC=1 check-db-migrate check-db-migrate-compat
```

Delete the worktree with `git worktree remove /tmp/phoenix-migrate` when
finished. The current tree does not build, link or test the converter.

---

## 8. Final state of the removal

Phase 6 completed the removal:

- the daemon, GUI, normal test binary and build system no longer reference
  Berkeley DB;
- the converter source, test-only BDB fixture and converter regression scripts
  were removed;
- the live converter and migration-window documentation was replaced by this
  historical guide;
- no build target installs or links `libdb_cxx`;
- the LMDB backend and its fail-closed marker behaviour remain unchanged.

Current builds do not create `blkindex.backend` or `wallet.backend`; the LMDB
environment is authoritative.  A marker written by the archived converter or a
migration-window build is still read, and a `bdb` or unknown marker still fails
closed.

The archived converter release is kept separately for recovery only. It is not
rebuilt, retested or supported as part of current development.
