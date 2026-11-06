# `phoenix-db-migrate` — standalone Berkeley DB to LMDB converter

Status: design accepted for implementation (Phase 2).
Scope: extract the existing in-daemon BDB→LMDB migrations into a separate
executable that may link Berkeley DB while the Phoenix daemon, GUI and normal
test binary do not.

Related inventory: [`bdb-removal-inventory.md`](bdb-removal-inventory.md).

---

## 1. Goals

1. Convert a legacy BDB `wallet.dat` into the daemon's LMDB wallet
   (`<datadir>/wallet/`, database `main`).
2. Convert a legacy BDB `blkindex.dat` into the daemon's LMDB chain index
   (`<datadir>/blkindex/`, database `main`).
3. Preserve every record byte-for-byte. The daemon's LMDB representation is the
   same serialized key/value pairs as the BDB representation; no record may be
   re-encoded.
4. Verify the source, the copy, the record count and the LMDB database before
   installing the result.
5. Keep the original BDB files untouched, including permissions and mtime.
6. Write the authoritative markers (`wallet.backend`, `blkindex.backend`) only
   after the LMDB environment is installed and verified.
7. Be restartable after interruption without ever exposing a partial LMDB
   environment as authoritative.
8. Never link Berkeley DB into `phoenixcoind`, the Qt GUI, `test_phoenixcoin`
   or `wallet_perf`.

## 2. Non-goals

- Replacing the daemon's normal LMDB startup path.
- Migrating `peers.dat` (it is not BDB).
- Changing LMDB durability defaults.
- Removing BDB from the runtime (Phase 3).
- Making the converter part of the daemon or the Qt application.
- Automatic deletion or rewriting of the source BDB files.

---

## 3. Architecture and link boundary

```text
phoenix-db-migrate
├── bdb_source.cpp      reads BDB with db_cxx (read-only)
├── lmdb_target.cpp     writes LMDB with liblmdb
├── stream_keys.cpp     minimal serialized-key parser (VarInt + bytes)
└── db_migrate.cpp      CLI, validation, state machine, markers
```

The converter is self-contained. It does **not** include `db.h`, `walletdb.h`,
`wallet.h`, `main.h`, `lmdbdb.h` or any daemon object. It links:

- `libdb_cxx` (converter only);
- `liblmdb` (shared with the daemon);
- the C++ standard library.

This boundary is intentional: it lets Phase 3 delete `bdb_kv.*`, `CDBEnv` and
all BDB branches from the daemon without deleting the converter.

The daemon's BDB and LMDB record encodings are identical by construction:
`CDB` serializes a key and value with `CDataStream(SER_DISK, CLIENT_VERSION)`
and stores the resulting byte strings. The LMDB backend stores the same byte
strings in database `main`. The converter therefore copies raw bytes and does
not need the wallet/chain serializers.

---

## 4. Command-line interface

```text
phoenix-db-migrate --datadir=<dir> [options]

Options:
  --datadir=<dir>          Data directory containing wallet.dat / blkindex.dat
  --wallet                 Migrate wallet.dat only
  --chain                  Migrate blkindex.dat only
                           (default: migrate every source that exists)
  --wallet-source=<file>   Override <datadir>/wallet.dat (testing)
  --chain-source=<file>    Override <datadir>/blkindex.dat (testing)
  --wallet-target=<dir>    Override <datadir>/wallet (testing)
  --chain-target=<dir>     Override <datadir>/blkindex (testing)
  --map-size=<MiB>         Initial LMDB map size (default: derived from source)
  --dry-run                Validate and report; write nothing
  --verbose                Print per-record progress every 100000 records
  --version                Print converter version
  --help                   Print this help
```

Exit codes:

- `0` — migration succeeded, or the scope was already migrated and valid.
- `1` — migration failed; source untouched.
- `2` — invalid command line.

`--datadir` is required unless both explicit source/target pairs are supplied.
A scope is selected if `--wallet`/`--chain` is present; with neither, every
existing source is migrated.

### 4.1 Default paths

| Scope | Source | Target | Marker |
|---|---|---|---|
| Wallet | `<datadir>/wallet.dat` | `<datadir>/wallet/` | `<datadir>/wallet.backend` |
| Chain | `<datadir>/blkindex.dat` | `<datadir>/blkindex/` | `<datadir>/blkindex.backend` |

`peers.dat` is ignored.

### 4.2 Map sizing

The LMDB map must be at least as large as the imported data. The default is:

```text
max(64 MiB, source_file_size * 2 + 16 MiB)
```

rounded up to the system page size. This is deliberately generous: BDB B-tree
pages and log overhead are not the same as LMDB pages. `--map-size` overrides
it. The map is a virtual/sparse mapping; the converter does not preallocate
the full size on disk.

On 32-bit systems the default is capped at 2 GiB minus one page and the
converter fails with a clear message if the source cannot fit. A 64-bit build
has no practical cap.

---

## 5. Migration state machine

For each selected scope:

```text
read marker
   |
   +-- marker == "lmdb"
   |      +-- target is complete and valid -> report already migrated (success)
   |      +-- target missing/empty/invalid -> fail closed (data loss; restore backup)
   |
   +-- marker == "bdb" or absent
          |
          +-- target exists non-empty
          |      +-- target was installed by an interrupted converter -> verify,
          |      |   write marker, success
          |      +-- otherwise -> fail (do not overwrite an existing LMDB target)
          |
          +-- source exists
                 |
                 +-- validate source BDB
                 +-- create staging directory beside target
                 +-- copy every record into one LMDB transaction
                 +-- read back every record, compare bytes, count
                 +-- scan the LMDB transaction, compare total count
                 +-- verify required records and key shapes
                 +-- commit LMDB transaction
                 +-- write completion sidecar in staging
                 +-- atomically rename staging -> target
                 +-- atomically write marker = "lmdb"
                 +-- source left untouched
```

### 5.1 Staging directory

Staging lives in the target's parent directory:

```text
<parent>/.phoenix-db-migrate-<scope>-<pid>-<timestamp>/
```

It is created with the same filesystem so the final install is a single
`rename()`. It is removed on any failure before installation. Stale staging
directories from a crashed run are removed at the start of the next run; they
are never treated as a target.

### 5.2 Completion sidecar

After the LMDB transaction commits and the pre-install verification passes, the
converter writes a small file inside the staging directory:

```text
.phoenix-migration-complete
```

containing the scope, source record count, converter version and timestamp.
The sidecar is written **before** the rename. If the process dies between the
rename and the marker write, the next run sees a non-empty target with the
sidecar and no marker, re-verifies the target, and completes the marker write.
A partial staging directory never contains the sidecar because it is written
only after the transaction commits and the full scan succeeds.

The daemon ignores unknown files inside an LMDB environment directory.

### 5.3 Marker writing

The marker is written exactly like the daemon writes it:

1. write `<marker>.tmp` with `lmdb\n`;
2. flush and fsync;
3. rename over `<marker>`, removing an existing marker first on platforms
   where rename does not replace.

A marker is written only after the LMDB target is installed and verified.
`wallet.backend` and `blkindex.backend` are independent; a failed wallet
migration never touches the chain marker and vice versa.

---

## 6. Source validation

### 6.1 File checks

- The source must exist, be a regular file, be readable and non-empty.
- The source must not be a symlink loop or a directory.
- The source is opened with `DB_RDONLY`; the converter never opens it for
  writing and never calls `DB_RECOVER` on the original.
- If BDB reports that the file needs recovery, the converter fails with:

  ```text
  <file> needs Berkeley DB recovery and cannot be opened read-only.
  Stop Phoenixcoin cleanly and retry. If the data directory was not shut down
  cleanly, restore a verified backup, or run db_recover on a copy of the whole
  data directory and migrate that copy.
  ```

  The original is never modified. A future optional mode may copy the whole
  data directory to staging and recover the copy; that mode is not part of the
  first implementation.

### 6.2 BDB-level validation

- Run BDB `Db::verify()` with no salvage flags. A non-zero result aborts the
  migration before any LMDB data is created.
- Open the database with logical name `main`, type `DB_BTREE`, `DB_RDONLY`.
- Read every record with a cursor. A cursor error aborts the migration.

### 6.3 Record-level validation

Keys are serialized with the daemon's `CDataStream` format. The converter
parses only the leading serialized string (Bitcoin CompactSize + bytes):

- The key must contain a complete, bounded string; otherwise the source is
  corrupt and the migration aborts.
- Known wallet prefixes: `version`, `minversion`, `key`, `wkey`, `ckey`,
  `mkey`, `keymeta`, `defaultkey`, `pool`, `tx`, `name`, `acc`, `acentry`,
  `watch`, `cscript`, `orderposnext`, `setting`, `hyb`, `hybaddr`, `hybused`.
- Known chain prefixes: `version`, `blockindex`, `tx`, `hashBestChain`,
  `bnBestInvalidWork`, `hashSyncCheckpoint`, `strCheckpointPubKey`.
- Unknown prefixes are preserved and reported once as warnings. They are not
  rejected, so records from future/legacy releases survive.
- `tx` and `blockindex` keys must carry a 32-byte hash after the prefix.
- The wallet source must contain a `version` record.
- The chain source must contain a `version` record; if it contains
  `blockindex`, it must also contain `hashBestChain`.
- An empty source (zero records) is an error for both scopes.

Per-prefix counts are printed in the final report. They are also the
content-level check operators can compare with the old daemon's logs or
`db_dump` output.

### 6.4 What is not decoded

The converter does not decode `CWalletTx`, `CDiskBlockIndex`, hybrid key
material or scripts. Raw byte equality plus the BDB verifier proves that the
destination is a faithful copy; the LMDB-only daemon performs the full
application-level load and semantic validation on first start. This is
intentional: decoding those types would pull the wallet/chain object graph
into the converter and blur the link boundary.

If a future requirement needs converter-side semantic validation, it can be
added as an optional linked validation library without changing the migration
format.

---

## 7. LMDB target validation

For every record:

1. `mdb_put()` into database `main` inside one write transaction.
2. `mdb_get()` the same key inside the same transaction.
3. Require byte-identical key and value.
4. On mismatch, abort the transaction, remove staging, fail.

After the loop:

1. Iterate the LMDB transaction from first to last with a cursor.
2. Require the cursor to end cleanly.
3. Require `lmdb_count == bdb_count`.
4. Commit the transaction.

After commit:

1. Reopen the environment read-only.
2. Open database `main` and iterate it again.
3. Require the cursor to end cleanly and the count to match.
4. Run `mdb_env_stat` / `mdb_stat` sanity checks (page size non-zero, entries
   match).
5. Write the completion sidecar.

The final read-only reopen proves the committed environment is readable by a
fresh process, not just by the writing transaction.

---

## 8. Failure and restart matrix

| Interruption point | On-disk state | Next run |
|---|---|---|
| Before staging | source only | normal retry |
| During BDB read | source only, staging removed or empty | remove stale staging, retry |
| During LMDB transaction | source only, staging has uncommitted LMDB | remove staging, retry |
| After LMDB commit, before sidecar | staging has committed LMDB, no sidecar | remove staging, retry |
| After sidecar, before rename | complete staging, no target | either install staging after verification or remove and retry |
| After rename, before marker | complete target with sidecar, no marker | verify target, write marker, success |
| After marker | complete target + marker | report already migrated (success) |
| Source modified during migration | not expected; source is read-only | BDB cursor/verify error or byte mismatch aborts |
| Disk full | staging incomplete, no target/marker | remove staging, retry after freeing space |

The source BDB files are never removed, renamed or rewritten.

---

## 9. Authority-marker policy

The converter obeys the same invariants as the daemon:

| Marker | Target | Converter action |
|---|---|---|
| absent | absent | migrate source, install target, write `lmdb` |
| `bdb` | absent | migrate source, install target, replace marker with `lmdb` |
| `bdb` | non-empty | fail: ambiguous; restore backup / remove stale target |
| `lmdb` | complete and valid | report already migrated, success |
| `lmdb` | missing/empty/invalid | fail closed: data loss, restore backup |
| unknown value | any | fail: unsupported marker |
| absent | non-empty with completion sidecar | verify and write `lmdb` (interrupted converter) |
| absent | non-empty without sidecar | fail: do not overwrite an existing LMDB target |

The daemon must never silently open a BDB database as an empty LMDB database.
The converter has the same rule in the opposite direction: it never overwrites
a non-empty LMDB target without a completion sidecar from an interrupted run.

---

## 10. Build integration

### 10.1 New source

- `src/db_migrate.cpp` — implementation (may be split later if it grows).

### 10.2 Linux

Add:

```make
MIGRATEOBJS = obj/db_migrate.o

phoenix-db-migrate: $(MIGRATEOBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(MIGRATELIBS)
```

where `MIGRATELIBS` contains only BDB, LMDB, `-lpthread` and the platform
libraries needed by those two. It must not contain Boost, OpenSSL, secp256k1 or
miniUPnP.

Mirror the daemon's `DYNAMIC`/`STATIC` suffix handling for BDB and LMDB only.

### 10.3 macOS and MinGW

Add the same target and object list. MinGW uses the existing hard-coded BDB
paths. The converter is a console executable, not a GUI target.

### 10.4 Qt project

Do not add the converter to `phoenixcoin-qt.pro`. The GUI must not link BDB
after Phase 3; the converter is built by the makefiles only.

### 10.5 Clean target

Add `phoenix-db-migrate` to the `clean` target in each makefile.

---

## 11. Test plan

### 11.1 Converter regression script

New `src/test/regression_db_migrate.sh`:

1. Build `phoenixcoind` and `phoenix-db-migrate`.
2. Create a temporary datadir.
3. Start the current daemon with `-walletbackend=bdb -dbbackend=bdb` to create
   real BDB fixtures (this step disappears when the daemon is LMDB-only; then
   use archived fixtures or a fixture-builder utility).
4. Create keys, hybrid keys, encrypted wallet state, keypool entries,
   transactions, labels and watch-only scripts; mine/import a few blocks.
5. Stop the daemon cleanly.
6. Record SHA-256 and sizes of `wallet.dat` and `blkindex.dat`.
7. Run `phoenix-db-migrate --datadir=<dir>`.
8. Check both markers contain `lmdb`, both target directories exist, and the
   source hashes are unchanged.
9. Start the daemon with default LMDB settings and verify the same addresses,
   keys, balances, keypool and chain tip.
10. Run the converter again; it must report already migrated and change
    nothing.
11. Run with a corrupted/truncated source; it must fail without a marker.
12. Run with an `lmdb` marker and a missing target; it must fail closed.
13. Run with a `bdb` marker and a non-empty target; it must fail.
14. Run `--dry-run`; it must not create a target or marker.

### 11.2 Crash/restart tests

Use a test-only environment variable in the converter:

```text
PHOENIX_DB_MIGRATE_TEST_KILL_AFTER_RECORDS=<n>
PHOENIX_DB_MIGRATE_TEST_KILL_AFTER_COMMIT=1
PHOENIX_DB_MIGRATE_TEST_KILL_AFTER_RENAME=1
```

The first exits with `_exit(137)` after `n` records; the second after the
LMDB commit but before the sidecar; the third after the rename but before the
marker. Each test must show:

- the source hashes are unchanged;
- no marker exists unless the run reached the marker step;
- a rerun succeeds and produces a valid target;
- the daemon never starts from a partial LMDB environment.

The hooks are inert unless the environment variable is set and are compiled
into the converter only.

### 11.3 Fixtures

Required fixtures:

- plain wallet with legacy `key` records;
- encrypted wallet (`ckey` + `mkey`);
- hybrid wallet (`hyb`, `hybaddr`, `hybused`);
- partially used keypool;
- wallet with labels, watch-only and redeem scripts;
- non-trivial chain index with blocks, transactions and checkpoints;
- interrupted staging directory.

They are generated by the regression script while the BDB daemon still exists.
After Phase 3 they must be checked in as small archived fixtures or generated
by a dedicated fixture builder.

### 11.4 Unit-level tests

If the converter remains self-contained, its key parser and state-machine
helpers can be compiled into a small test target. The primary coverage is the
end-to-end regression script because it exercises real BDB files.

---

## 12. Operational documentation

The converter must ship with a user-facing procedure:

1. Stop Phoenixcoin.
2. Make a full copy of the data directory and verify the copy.
3. Ensure enough free space: at least **2×** the size of `wallet.dat` +
   `blkindex.dat`, preferably 3× for the backup and staging copy.
4. Run `phoenix-db-migrate --datadir=<dir>`.
5. Start the LMDB-only daemon and verify balances, addresses, keypool and chain
   tip.
6. Keep the original BDB files and the verified backup until the new
   installation has been used successfully.
7. Do not delete the BDB files automatically.

Expected downtime: stop-the-world for the duration of the copy. Wallet
migration is normally seconds; chain-index migration is proportional to the
index size and can take minutes. Disk I/O is the limiting factor.

---

## 13. Implementation order

1. Add `src/db_migrate.cpp` with CLI, BDB reader, LMDB writer, validation and
   marker handling.
2. Add the Linux build target and compile it.
3. Add the macOS/MinGW targets.
4. Add `src/test/regression_db_migrate.sh` and a fixture lifecycle test.
5. Run the converter against a real BDB wallet and chain index; confirm the
   daemon starts from the result.
6. Add crash/restart hooks and tests.
7. Document the procedure in `doc/db-migrate.md` and link it from
   `doc/lmdb.md`/`README.md` during Phase 1.
8. Only then begin Phase 3 runtime removal.

---

## 14. Open questions for review

1. **Source recovery.** The first version opens the source read-only and fails
   if BDB needs recovery. Is a `--recover-copy` mode (copy the whole datadir,
   recover the copy) required in the first release?
2. **Converter-side semantic validation.** Raw byte equality plus the BDB
   verifier is the first version's proof. Is that sufficient, or must the
   converter decode and validate every wallet/chain value before writing the
   marker?
3. **Existing non-empty target without a sidecar.** The first version fails
   closed. Is an explicit `--replace` escape hatch needed for operators who
   already have a stale LMDB target?
4. **Map size on 32-bit.** The default cap is 2 GiB. Is that acceptable, or
   should the converter require an explicit `--map-size` for large indexes?
5. **Binary name.** `phoenix-db-migrate` is used throughout. Confirm before
   the build target and documentation are finalized.
