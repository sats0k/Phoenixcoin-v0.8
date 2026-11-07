# LMDB-only release guide

Status: Phase 5. The daemon, GUI and normal test binary use LMDB only. The
standalone `phoenix-db-migrate` converter is shipped separately for one release
cycle so existing Berkeley DB installations can convert before upgrading.

Related documents:

- [`db-migrate.md`](db-migrate.md) — operator procedure for the converter.
- [`db-migrate-design.md`](db-migrate-design.md) — converter architecture and
  verification guarantees.
- [`lmdb.md`](lmdb.md) — LMDB runtime behaviour, backup and recovery.
- [`bdb-removal-inventory.md`](bdb-removal-inventory.md) — historical inventory
  and phase plan.

---

## 1. What changed in this release

| Area | Before | LMDB-only release |
|---|---|---|
| New installations | LMDB default | LMDB only |
| Existing LMDB installations | Upgrade normally | Upgrade normally, no conversion |
| Existing Berkeley DB installations | Could start and migrate in-process | Must convert before the first start; the daemon refuses a BDB data directory |
| Daemon / GUI / test binary | Linked Berkeley DB | Never link Berkeley DB |
| Converter | Build-time tool in the source tree | Built and published as a separate bundle |

The application version remains **0.8.4**. The converter reports the same
version so an operator can match it with the release notes.

The obsolete options `-walletbackend=bdb` and `-dbbackend=bdb` fail at startup
with:

```text
Berkeley DB support has been removed.
Please migrate your database to LMDB using phoenix-db-migrate.
```

They are never silently ignored. Other migration-era options (`-salvagewallet`,
`-detachdb`, `-dbcache`, `-dblogsize`, `-privdb`) have no BDB behaviour left;
see the release notes for their current status.

---

## 2. Upgrade matrix

| On-disk state | Daemon behaviour | Required action |
|---|---|---|
| `wallet/` and `blkindex/` present, `*.backend` says `lmdb` | Starts normally | None |
| No wallet or chain database (new data directory) | Creates empty LMDB environments | None |
| `wallet.dat` and/or `blkindex.dat` present, `*.backend` says `bdb` or is absent | Refuses to start; reports that migration is required | Run `phoenix-db-migrate` before starting |
| BDB source and an existing LMDB environment without a marker | Refuses to start; reports an ambiguous state | Inspect the directory, keep the authoritative copy, restore a verified backup |
| `*.backend` says `lmdb` but the LMDB environment is missing or empty | Refuses to start; reports the missing environment | Restore a verified backup |
| `*.backend` contains an unsupported value | Refuses to start; reports the corrupt marker | Restore the marker or a verified backup |
| Only one scope is still BDB | Refuses to start until both scopes are migrated | Convert with `--wallet`, `--chain` or the default combined run |

There is no automatic fallback and no path that opens a Berkeley DB source as
an empty LMDB database. A marker is authoritative: `lmdb` means LMDB must be
used, `bdb` means the legacy file remains authoritative until a successful
conversion replaces it.

### Recommended upgrade sequence

1. Stop Phoenixcoin completely.
2. Make a full copy of the data directory and verify the copy.
3. Run the separately distributed converter against the stopped directory:

   ```bash
   phoenix-db-migrate --datadir=/path/to/datadir --dry-run
   phoenix-db-migrate --datadir=/path/to/datadir
   ```

4. Confirm `wallet.backend` and `blkindex.backend` contain `lmdb` and that the
   `wallet/` and `blkindex/` environments are non-empty.
5. Start the LMDB-only release and verify balances, addresses, keypool size and
   chain height as described in [`db-migrate.md`](db-migrate.md).
6. Keep the original BDB files and the verified backup until the new
   installation has been used and checked.

Do not start the new release first and then run the converter: the daemon will
refuse the data directory by design. Convert first.

---

## 3. Separate converter distribution

`make -f Makefile.linux dist-db-migrate` produces:

```text
src/dist/phoenix-db-migrate-<version>-<platform>/
    phoenix-db-migrate
    LICENCE
    CHANGELOG.md
    SHA256SUMS
    doc/
        db-migrate.md
        db-migrate-design.md
        lmdb-only-release.md
```

The bundle contains no daemon and no GUI. It is the only artifact that may link
Berkeley DB. Publish it beside the normal release, clearly labelled for
operators of pre-LMDB installations, and verify `SHA256SUMS` before use. On
platforms without the target, assemble the same contents with the native
checksum tool (`shasum -a 256` on macOS) and keep the directory layout and
file names identical.

The converter and the daemon may be built on different machines. The converter
only needs its own Berkeley DB and LMDB libraries; it does not load the daemon.

### Retiring the bundle

Keep the bundle available for the whole migration cycle, including the previous
release notes and checksums. After Phase 6 removes the converter source, keep
the last published converter binary and this guide in the archive so a user who
finds an old data directory can still migrate.

---

## 4. Berkeley DB version compatibility

Phoenixcoin data directories were written over many years and therefore by
several Berkeley DB releases. Do not assume a single BDB version.

The converter reports what it is actually using:

```text
$ phoenix-db-migrate --version
phoenix-db-migrate 0.8.4
Berkeley DB library: 6.2.32 (compiled against 6.2.32)
LMDB library: 0.9.35
```

Rules that follow from Berkeley DB itself:

- A Berkeley DB library can read and verify a database written by the same or
  an older release. A newer library may upgrade an older on-disk format.
- A Berkeley DB library older than the database's on-disk format cannot verify
  it. The converter then fails with a message naming the linked version and
  advises rebuilding against the writer's version or newer. It does not write a
  target.
- When the source needs an on-disk upgrade, the converter copies it to a hidden
  temporary file, upgrades the copy, converts the copy, and deletes the copy.
  The original `wallet.dat` / `blkindex.dat` is never modified.
- The temporary upgrade copy lives beside the source. Reserve free space for
  the original, the temporary copy and the LMDB target: up to **3×** the
  source size when an on-disk upgrade is needed, otherwise about 2×.
- The converter does not decode wallet or chain semantics; it copies serialized
  records byte-for-byte. Berkeley DB version differences are therefore a
  read/verify concern only.

### Release check

The default converter links the newest Berkeley DB available on the build
machine. Before publishing, run the optional cross-version check against the
oldest Berkeley DB users actually used:

```bash
make -f Makefile.linux check-db-migrate-compat
# or select a library explicitly:
PXC_OLD_BDB_LIB=/usr/lib/libdb_cxx-5.3.so \
    make -f Makefile.linux check-db-migrate-compat
```

The check compiles a small fixture writer against the older library, writes a
database in that older format, converts it with the normal converter, and
verifies the marker, the converted record and the unchanged source. It reports
`SKIP` when no older library is installed, so it is safe in ordinary CI. Run it
at least once against 5.3 (and 4.8 if that is in the supported range) before a
release, and record the tested combinations in the release notes.

If a user reports a database that the shipped converter cannot open, ask for
the `--version` output and the exact error. Rebuild the converter against a
Berkeley DB equal to or newer than the one that wrote the database; do not ask
the user to upgrade the original file in place.

---

## 5. Monitoring during the release cycle

Track the following. A single report is not necessarily a defect, but a trend
or a repeatable case is. Keep the original data directory and the converter log
for every report (`--verbose` adds record progress).

### Migration failures

- Converter exit code and the full stderr/stdout log.
- Source file sizes and `phoenix-db-migrate --version` output.
- Whether the run was `--wallet`, `--chain` or combined.
- Whether the failure is a read/verify failure, an old/new Berkeley DB version
  mismatch, a disk-space error, a lock error, or a target/marker conflict.
- Whether re-running after removing a stale staging directory succeeds.

### Missing or mismatched wallet records

- `version` record present; keypool size before and after conversion.
- Addresses, labels, accounts, transactions, spent-output state, default key,
  address book, watch-only entries, redeem scripts and ordering.
- For encrypted wallets: locked and unlocked balances, `listhybridaddresses`,
  and a successful unlock. For hybrid wallets: `checkhybridkeys` (including
  `checkhybridkeys deep` after unlocking).
- Record counts printed by the converter for the source, the copy and the
  installed environment.

### Chain-index mismatches

- `getblockcount` and the chain tip before and after conversion.
- `getblockhash` for the tip and a few earlier heights.
- `getdbinfo` backend, marker and record counts.
- Reindex or startup errors that mention the chain environment.

### Encrypted and hybrid wallet reports

- Conversion of a wallet that was already encrypted, and conversion followed by
  `encryptwallet`.
- Hybrid key round trip: `gethybridaddress`, `dumphybridkey`,
  `importhybridkey` and `checkhybridkeys`.
- Any report that a key exists but is unusable after restart.

### Backup and restore failures

- `backupwallet` on the migrated wallet, offline `checklmdb` on the copy, and a
  restore into a clean data directory.
- Restores that reject copied, truncated or non-empty destinations.
- Restores that leave no marker or an ambiguous marker.

### Startup and recovery problems

- Fail-closed startup messages for missing, conflicting or corrupt markers.
- Any accidental start of a BDB directory by the new binary (should be
  impossible; report immediately if observed).
- Stale staging directories after an interrupted run, and whether the next run
  cleans them up.
- Map-size, disk-space and permission errors during first start.

### Triage checklist

For every report, capture:

1. Release version and converter version.
2. Operating system, architecture, Berkeley DB and LMDB versions.
3. Data-directory listing (file names, sizes, markers) with private material
   redacted.
4. Exact commands and full output.
5. Whether a verified backup exists.
6. Whether the original BDB files are still present and unchanged.

---

## 6. Rollback and retention

The conversion is additive: the BDB source is never removed. Rollback means
restoring the data directory from the verified backup, not running an old
daemon against a half-converted directory.

- Keep the pre-conversion backup until the new installation has been used and
  verified.
- Keep the original `wallet.dat` and `blkindex.dat` until the LMDB environment
  has been backed up at least once.
- A restored backup must contain the markers that match its contents. Do not
  mix a restored LMDB environment with a stale `bdb` marker or vice versa.
- If a migration is interrupted, re-run the converter; do not delete markers or
  staging directories by hand unless the failure table in
  [`db-migrate.md`](db-migrate.md) says to.
- Retire the backup only under the operator's normal retention policy, after
  the LMDB installation is proven.

---

## 7. Phase 6 exit criteria

Phase 5 ends and Phase 6 can remove the converter when:

- One full release cycle has shipped with an LMDB-only daemon and GUI.
- No open migration failure is caused by a converter defect; remaining reports
  are user error, unsupported Berkeley DB versions (with a documented rebuild
  path) or disk/hardware faults.
- No open wallet-record, chain-index, encrypted/hybrid, backup/restore or
  startup regression is attributable to the conversion.
- The converter has been tested against every Berkeley DB version seen in
  user reports, in addition to the oldest version in the supported range.
- The last converter bundle, its checksums and the migration guide are archived
  and linked from the release notes.
- Documentation states that Berkeley DB installations must use the archived
  converter before upgrading, and that the current release will refuse them.
- The repository no longer needs `db_cxx` for any executable except the
  archived converter build, and the daemon, GUI, tests and fixtures link LMDB
  only.

Phase 6 then removes the converter source, the Berkeley DB build variables and
fixture helper, and the live migration documentation, while keeping the
historical guide and the archived converter release.
