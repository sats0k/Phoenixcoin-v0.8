# Berkeley DB Removal — Phase 0 Dependency and Data-Format Inventory

Status: **historical. Phases 0-6 complete.** No part of the Phoenix source tree
or standard build environment depends on Berkeley DB.
Branch: `remove-bdb` (created from `master` at `e6e95c33`).
Version: `0.8.4` (unchanged).
Scope: every tracked source file, build file, runtime option, on-disk database,
test/script/fixture and document that still depended on Berkeley DB (BDB).

> **Historical note:** Phases 1-6 are implemented on this branch. The runtime
> is LMDB-only, `wallet_migration_tests.cpp` was renamed to
> `wallet_persistence_tests.cpp`, and the conversion tools and tests have since
> been retired. Phase 5 shipped the daemon/GUI separately from a converter-only
> bundle and kept the converter compatible with older Berkeley DB releases.
> Phase 6 removed the converter source, the test-only fixture, the converter
> regressions and the live migration documentation. Operators who still need to
> recover a pre-LMDB data directory use the archived converter release described
> in [`bdb-migration.md`](bdb-migration.md). This document is retained as the
> Phase 0 inventory; the per-file action columns describe the plan at that time,
> not the final tree.

This document is the gate for Phase 1/2. No BDB implementation is deleted
until this inventory is reviewed.

---

## Executive findings

1. **Only two persistent databases use BDB**: `wallet.dat` and
   `blkindex.dat`. Both are BDB BTREE databases with logical database name
   `main`. No auxiliary application database, legacy metadata database, or
   test-only production database uses BDB.
2. **`peers.dat` is not BDB.** `CAddrDB` writes a flat, checksummed stream
   with a network magic header. It lives in `db.cpp`, which is why it looks
   like a database dependency, but it does not call BDB.
3. **BDB is a hard dependency even when LMDB is selected.** `db.h` includes
   `<db_cxx.h>` and exposes `DbEnv`, `Db`, `Dbt`, `Dbc` and `DbTxn` members.
   `init.cpp` unconditionally calls `bitdb.Open(GetDataDir())` and prints
   `DbEnv::version()`. Normal builds link `-ldb_cxx`.
4. **An in-daemon migration already exists** (`CTxDB::MigrateToLMDB()` and
   `MigrateWalletToLMDB()`), and the authoritative-marker policy is already
   implemented. Phase 2 is therefore an extraction/hardening job, not a
   from-scratch design.
5. **The wallet migration is stronger than the chain migration today.** The
   wallet copies records, reads each one back inside the LMDB transaction,
   counts the result, aborts on failure and writes the marker only after
   commit. The chain migration copies raw records and commits, but does not
   read back or compare record counts; consistency is only proven later when
   the block index is loaded.
6. **The unit-test fixture is built on an in-memory mock BDB environment**
   (`bitdb.MakeMock()`), so removing BDB requires replacing the global fixture
   with a temporary LMDB environment.
7. **Several regression scripts use the BDB daemon to create fixtures.** They
   are migration tests today, but will need fixtures produced by a standalone
   converter or archived BDB files once the daemon stops linking BDB.
8. **No repository-tracked CI/packaging configuration contains BDB.** The
   only tracked build definitions that reference BDB are
   `src/Makefile.linux`, `src/Makefile.mac`, `src/Makefile.mingw` and
   `phoenixcoin-qt.pro`. The top-level `Makefile` is a generated, untracked
   qmake artifact. `CMakeLists.txt` exists but only builds crypto/fuzz test
   targets and does not reference BDB or LMDB.

Search evidence at the time of writing:

| Measure | Count |
|---|---|
| Tracked files containing a BDB token | 29 |
| Source-only (`src/**/*.cpp`, `src/**/*.h`) token matches | 226 |
| All raw matches including generated objects | 430 |
| Direct `<db_cxx.h>` includers | 3 (`db.h`, `bdb_kv.h`, `qt/rpcconsole.cpp`) |
| Direct `db.h` includers (transitively see `<db_cxx.h>`) | 15 |
| Persistent BDB databases | 2 |

---

## 1. Persistent database and file inventory

### 1.1 `wallet.dat` — BDB BTREE

| Property | Value |
|---|---|
| Path | `<datadir>/wallet.dat` |
| Format | Berkeley DB BTREE, logical database `main` |
| Owner code | `CWalletDB` (derived from `CDB`), `CWallet` |
| Created by | `CDB::CDB("wallet.dat", "r+"/"c")` in `src/db.cpp` |
| Alternative owner | `<datadir>/wallet/` LMDB environment when `-walletbackend=lmdb` (default) |
| Authority marker | `<datadir>/wallet.backend` containing `lmdb` or `bdb` |
| Migration source | Opened read-only by `CWalletMigrationSource` / `MigrateWalletToLMDB()` |
| Backup path | `BackupWalletDB()` copies the file; `BackupLMDBWallet()` copies the environment |
| Recovery | `CDBEnv::Verify()`, `CDBEnv::Salvage()`, `CWalletDB::Recover()` |

Wallet record types observed in the reader (`ReadKeyValue`) and writers:

| Key prefix | Key shape | Value | Notes |
|---|---|---|---|
| `version` | scalar | `int` client version | Written on create/upgrade |
| `minversion` | scalar | `int` | Minimum reader version |
| `key` | public key bytes | plaintext private key | Legacy/plaintext key |
| `wkey` | public key bytes | encrypted key, legacy format | Read for compatibility; erased when re-encrypting |
| `ckey` | public key bytes | encrypted key | Current encrypted key |
| `mkey` | master-key id | `CMasterKey` | Encryption master key |
| `keymeta` | public key bytes | `CKeyMetadata` | Creation time / HD metadata |
| `defaultkey` | scalar | public key bytes | Default receiving key |
| `pool` | pool index | keypool entry | Keypool |
| `tx` | txid | `CWalletTx` | Wallet transaction |
| `name` | address | string | Address-book label |
| `acc` | account name | `CAccount` | Account metadata |
| `acentry` | `(account, entry number)` | `CAccountingEntry` | Accounting entries |
| `watch` | destination | `'1'` | Watch-only destination |
| `cscript` | script hash | `CScript` | Redeem script |
| `orderposnext` | scalar | `int64` | Transaction ordering |
| `setting` | setting name | serialized value | Generic wallet setting |
| `hyb` | `CHybridKeyID` | `CHybridKeyDisk` | Hybrid key at rest |
| `hybaddr` | `CHybridKeyID` | hybrid address book entry | Hybrid labels/metadata |
| `hybused` | scalar | set of used hybrid IDs | Prevents re-issuing addresses |

The migration copies **raw serialized key/value records**, so every prefix
above is preserved without the converter needing to understand it. Semantic
tests must still cover encrypted keys (`ckey`/`mkey`), hybrid records
(`hyb`/`hybaddr`/`hybused`), partially used keypools (`pool`), legacy `wkey`,
`keymeta`, `setting`, `orderposnext` and all transaction/spent-output state.

### 1.2 `blkindex.dat` — BDB BTREE

| Property | Value |
|---|---|
| Path | `<datadir>/blkindex.dat` |
| Format | Berkeley DB BTREE, logical database `main` |
| Owner code | `CTxDB` (derived from `CDB`) |
| Created by | `CDB::CDB("blkindex.dat", ...)` in `src/db.cpp` |
| Alternative owner | `<datadir>/blkindex/` LMDB environment when `-dbbackend=lmdb` (default) |
| Authority marker | `<datadir>/blkindex.backend` containing `lmdb` or `bdb` |
| Migration source | Opened read-only by `CTxDB db("r")` inside `MigrateToLMDB()` |
| Backup path | Copied as part of a datadir backup; no online BDB chain backup RPC |

Chain-index record types:

| Key prefix | Key shape | Value | Notes |
|---|---|---|---|
| `version` | scalar | `int` client version | Written on create |
| `blockindex` | block hash | `CDiskBlockIndex` | Height, parent, status, file/position, chain work inputs |
| `tx` | txid | `CTxIndex` | Transaction position / spent-output state |
| `hashBestChain` | scalar | `uint256` | Best-chain tip |
| `bnBestInvalidWork` | scalar | `CBigNum` | Invalid-work watermark |
| `hashSyncCheckpoint` | scalar | `uint256` | Sync checkpoint |
| `strCheckpointPubKey` | scalar | `std::string` | Checkpoint public key |

Auxiliary chain-index records are therefore only the two checkpoint records
and `bnBestInvalidWork`; they are copied by the generic record loop.

### 1.3 `peers.dat` — **not BDB**

| Property | Value |
|---|---|
| Path | `<datadir>/peers.dat` |
| Format | Flat serialized `CAddrMan` with network magic and SHA-256 checksum |
| Owner code | `CAddrDB` in `src/db.cpp` |
| BDB usage | None. Uses `CDataStream`, `CAutoFile`, `FileCommit`, `RenameOver` |
| Action during removal | Move `CAddrDB` out of the BDB-oriented `db.cpp` (or keep it) but do not delete it |

### 1.4 BDB environment artifacts

`CDBEnv::Open()` creates a BDB environment in the datadir:

| Artifact | Created by | Notes |
|---|---|---|
| `<datadir>/database/` | `CDBEnv::Open()` | BDB log directory |
| `<datadir>/db.log` | `CDBEnv::Open()` | BDB error file, opened in append mode |
| `<datadir>/__db.*` | BDB runtime | Environment region files; absent when `-privdb=1` (the default), where regions are private to the process |
| `<datadir>/database/log.*` | BDB runtime | BDB transaction log files in the log directory |
| `<datadir>/blkindex.backend` | `WriteChainBackendMarker()` | Text `lmdb`/`bdb` |
| `<datadir>/wallet.backend` | `WriteWalletBackendMarker()` | Text `lmdb`/`bdb` |
| `<datadir>/blkindex/` | `CLMDBEnv` | LMDB chain environment |
| `<datadir>/wallet/` | `CLMDBEnv` | LMDB wallet environment |
| `wallet.<timestamp>.bak` | `CWalletDB::Recover()` | Salvage backup of a corrupt `wallet.dat` |

Because `init.cpp` opens the BDB environment unconditionally before backend
selection, a normal LMDB-only run currently still creates `database/` and
`db.log` and runs `DB_RECOVER`. Phase 3 must remove that startup path, not just
the `-dbbackend=bdb` branch.

### 1.5 Databases confirmed **not** present

A repository-wide search found no other `CDB` instantiation, no other
`Db::open()` filename, and no other BDB-backed file. In particular:

- no BDB address database (`peers.dat` is flat);
- no BDB settings database (`setting` records live inside `wallet.dat`);
- no BDB test-only production database (unit tests use mock BDB or temporary
  LMDB environments);
- no BDB block/undo file store (block files are flat `blk0001.dat`-style files,
  not BDB).

---

## 2. Source dependency map

### 2.1 BDB-owned implementation

| File | BDB dependency | Phase 3 action |
|---|---|---|
| `src/db.h` | `#include <db_cxx.h>`; `CDBEnv` owns `DbEnv`; `CDB` owns `Db*`, `DbTxn*`, `Dbc*`; BDB branches in `Read`/`Write`/`Erase`/`Exists`/`GetCursor`/`ReadAtCursor`/`Txn*`; `CDBEnv::Verify/Salvage/CheckpointLSN/TxnBegin`; `CDB::Rewrite` | Remove BDB types/branches; keep `CDB` as the LMDB-facing record wrapper or collapse it; move `CAddrDB` declaration |
| `src/db.cpp` | `CDBEnv` open/close/flush/salvage/verify/checkpoint; `CDB` BDB open and operations; `CDB::Rewrite`; BDB `BackupWalletDB`/`FlushWalletDB` branches; `CTxDB::MigrateToLMDB`; `CWalletMigrationSource`; `CheckWalletDatabaseAtStartup`; `CAddrDB` | Split migration into the standalone converter; make startup LMDB-only; keep `CAddrDB` |
| `src/bdb_kv.h` | `#include <db_cxx.h>`; `CBDBIterator`, `CBDBTransaction`, `CBDBDatabase` | Delete |
| `src/bdb_kv.cpp` | BDB KV backend implementation | Delete |
| `src/walletdb.cpp` | `CWalletDB::Recover()`; BDB salvage/rename/rewrite; `CheckWalletDatabaseAtStartup()` | Delete the BDB recovery path; keep record loading and LMDB behaviour |
| `src/walletdb.h` | Includes `db.h`; `CWalletDB : public CDB`; `DBErrors` enum uses `DB_*` names | Remove the `db.h` dependency; keep the record API; keep or rename the backend-neutral error enum |
| `src/init.cpp` | `-dbbackend`/`-walletbackend` validation; `-salvagewallet`; `-detachdb`; `bitdb.Open()`; `DbEnv::version()`; BDB `DBErrors` handling | Reject obsolete options with the required message; remove BDB env/version; keep LMDB diagnostics |
| `src/qt/rpcconsole.cpp` | `#include <db_cxx.h>`; `DbEnv::version()` in the Information tab | Remove the BDB version line or replace with LMDB version/build info |
| `src/rpcmain.cpp` | Includes `db.h`; `getdbinfo` reports `bdb`/`lmdb` configured/active backend and marker state | Keep `getdbinfo`, but remove the `bdb` state or make it impossible |
| `src/main.cpp`, `src/checkpoints.cpp`, `src/net.cpp`, `src/hs/walletdb_hybrid.cpp`, `src/rpcrawtransaction.cpp`, `src/qt/transactiondesc.cpp` | Include `db.h` only for `CTxDB`/`CWalletDB`/`CDB` types | No direct BDB logic; recompile after `db.h` stops including `<db_cxx.h>` |

### 2.2 Backend-neutral interfaces to keep

| File | Role |
|---|---|
| `src/db_kv.h` | `CDBKey`, `CDBValue`, `CDBScan`, `CDBIterator`, `CDBTransaction`, `CDBBackend` interfaces; no BDB include |
| `src/lmdb_kv.h/.cpp` | `CLMDBDatabase`, `CLMDBTransaction`, `CLMDBIterator`; LMDB implementation |
| `src/lmdbdb.h/.cpp` | `CLMDBEnv`, `CLMDBDatabase`, statistics, verification, map growth; comments mention BDB only as behavioural reference |
| `src/walletdb.cpp` | `ReadKeyValue()` record decoder and `LoadWallet()` are backend-neutral once `CWalletDB` no longer derives from a BDB-owning `CDB` |

### 2.3 Direct `<db_cxx.h>` includers

Only three files include the BDB C++ header directly:

1. `src/db.h` — transitive dependency for every `db.h` consumer.
2. `src/bdb_kv.h` — BDB KV backend.
3. `src/qt/rpcconsole.cpp` — only for `DbEnv::version()`.

### 2.4 Direct `db.h` includers

`src/checkpoints.cpp`, `src/db.cpp`, `src/hs/walletdb_hybrid.cpp`,
`src/init.cpp`, `src/main.cpp`, `src/net.cpp`, `src/qt/rpcconsole.cpp`,
`src/qt/transactiondesc.cpp`, `src/rpcmain.cpp`,
`src/rpcrawtransaction.cpp`, `src/test/kvdb_tests.cpp`,
`src/test/test_bitcoin.cpp`, `src/test/wallet_migration_tests.cpp`,
`src/test/wallet_perf.cpp`, `src/walletdb.h`.

`walletdb.h` is in turn included by `src/hs/rpchybrid.cpp`,
`src/hs/walletdb_hybrid.cpp`, `src/hs/wallethybrid.cpp`,
`src/test/accounting_tests.cpp`, `src/test/kvdb_tests.cpp`,
`src/test/wallet_migration_tests.cpp`, `src/test/wallet_perf.cpp`,
`src/wallet.cpp`, `src/walletdb.cpp`, `src/wallet.h`.

### 2.5 BDB function inventory

Environment and handle management:

- `CDBEnv::CDBEnv`, `~CDBEnv`, `EnvShutdown`, `Open`, `Close`, `MakeMock`,
  `Verify`, `Salvage`, `Flush`, `CheckpointLSN`, `CloseDb`, `RemoveDb`,
  `TxnBegin`, `SetDetach`.
- `CDB::CDB`, `~CDB`, `Close`, `Rewrite`, `GetCursor`, `ReadAtCursor`,
  `TxnBegin`, `TxnCommit`, `TxnAbort`, and the BDB branches of
  `Read`/`Write`/`Erase`/`Exists`.

Wallet:

- `CWalletDB::Recover` (two overloads).
- `CheckWalletDatabaseAtStartup`.
- `BackupWalletDB` BDB branch.
- `FlushWalletDB` BDB branch.
- `CDB::Rewrite` used by `CWallet::EncryptWallet` when the wallet is BDB.

Chain:

- `CTxDB::MigrateToLMDB`.
- `CTxDB::LoadBlockIndexGuts` (BDB cursor path).
- `CTxDB` record accessors (`ReadTxIndex`, `UpdateTxIndex`, `AddTxIndex`,
  `EraseTxIndex`, `ContainsTx`, `ReadDiskTx`, `WriteBlockIndex`,
  `ReadHashBestChain`, `WriteHashBestChain`, `ReadBestInvalidWork`,
  `WriteBestInvalidWork`, `ReadSyncCheckpoint`, `WriteSyncCheckpoint`,
  `ReadCheckpointPubKey`, `WriteCheckpointPubKey`). These are
  backend-neutral via `CDB` and survive removal.

Diagnostics:

- `CollectDBBackendDiagnostics`, `GetDBDiagnostics`, `DBBackendName`,
  `InspectLMDBEnvironmentOnDisk`, marker readers/writers.
- `getdbinfo` RPC and Qt Information tab.

Test hooks (not BDB-specific but used by migration/crash tests):

- `TestWalletCrashPoint`, `SetTestWalletWriteFailure`,
  `SetTestWalletCommitFailure`, `SetTestChainCommitFailure`,
  `SetTestWalletRewriteFailure`, `SetTestWalletRewriteAbort`.

---

## 3. Build dependency map

### 3.1 `src/Makefile.linux`

| Lines | Dependency |
|---|---|
| 44–46 | `BDB_LIB_SUFFIX`, `BDB_INCLUDE_PATH`, `BDB_LIB_PATH` |
| 61 | `BDB_INCLUDE_PATH` in `INCS` |
| 65 | `BDB_LIB_PATH` in `LIBS` |
| 72 | `-l:libdb_cxx.so$(BDB_LIB_SUFFIX)` (dynamic) |
| 82 | `-l:libdb_cxx$(BDB_LIB_SUFFIX).a` (static) |
| 91 | `-ldb_cxx$(BDB_LIB_SUFFIX)` (default) |
| 120 | `obj/db.o` |
| 146 | `obj/bdb_kv.o` |
| 205–234 | test object list, including `obj-test/kvdb_tests.o`, `obj-test/wallet_migration_tests.o`, `obj-test/wallet_perf.o` (not in `TESTOBJS`; separate target) |

### 3.2 `src/Makefile.mac`

| Lines | Dependency |
|---|---|
| 36–38 | BDB variables |
| 52 | BDB include path |
| 56 | BDB library path |
| 64 | `-ldb_cxx$(BDB_LIB_SUFFIX)` |
| 88 | `obj/db.o` |
| 114 | `obj/bdb_kv.o` |

### 3.3 `src/Makefile.mingw`

| Lines | Dependency |
|---|---|
| 39–41 | BDB variables, hard-coded `/home/Administrator/db-5.3.28/build_unix` include/lib paths |
| 55 | BDB include path |
| 59 | BDB library path |
| 67 | `-ldb_cxx$(BDB_LIB_SUFFIX)` |
| 96 | `obj/db.o` |
| 122 | `obj/bdb_kv.o` |

### 3.4 `phoenixcoin-qt.pro`

| Lines | Dependency |
|---|---|
| 43–49 | Commented/documented BDB include/library variables and hard-coded Win32 BDB paths |
| 207–208 | `src/bdb_kv.h` in `HEADERS` |
| 298–299 | `src/bdb_kv.cpp` in `SOURCES` |
| 430–432 | BDB include path and `-ldb_cxx$$BDB_LIB_SUFFIX` link flag |

### 3.5 Top-level `Makefile`

Generated by qmake from `phoenixcoin-qt.pro`; **not tracked by git**. It
currently contains `-ldb_cxx` in `LIBS`. It will be regenerated after the
`.pro` change; no source edit belongs in this file.

### 3.6 `CMakeLists.txt`

Tracked, but it only defines the crypto library and fuzz/encryption test
targets (`src/key.cpp`, `src/hs/hybrid_*`, `src/test/fuzz/*`,
`src/test/test_encrypted_keys.cpp`). It does not build the daemon, GUI,
wallet database or chain index, and contains no BDB reference. No Phase 3
build change is required there.

### 3.7 Actual linkage today

On the current Linux build, `src/phoenixcoind` links both:

```text
libdb_cxx-6.2.so => /usr/lib/libdb_cxx-6.2.so
liblmdb.so       => /usr/lib/liblmdb.so
```

The Phase 3 acceptance check must show no `libdb_cxx` entry in `ldd`/`readelf`
for `phoenixcoind`, `test_phoenixcoin`, the Qt GUI and `wallet_perf`
(if retained). Static builds must not contain BDB symbols either.

---

## 4. Runtime option and diagnostic map

### 4.1 BDB-only or BDB-defaulted options

| Option | Default | Current behaviour | Removal requirement |
|---|---|---|---|
| `-dbbackend=<bdb\|lmdb>` | `lmdb` | Selects chain backend | `bdb` must fail with the exact removal message |
| `-walletbackend=<bdb\|lmdb>` | `lmdb` | Selects wallet backend | `bdb` must fail with the exact removal message |
| `-salvagewallet` | false | BDB salvage of corrupt `wallet.dat`; rejected when wallet backend is LMDB | Remove or replace with an LMDB-safe recovery path; do not silently ignore |
| `-detachdb` | false | `CDBEnv::SetDetach`; detaches BDB files at shutdown | Remove; Qt `detachDB` setting must be dropped |
| `-privdb` | true | Adds `DB_PRIVATE` to BDB environment | Remove |
| `-dbcache` | 25 MiB | BDB cache size | Remove; LMDB has its own map-size options |
| `-dblogsize` | 100 MiB | BDB checkpoint/log size | Remove |
| `-flushwallet` | true | Runs the wallet flush loop; BDB branch flushes `wallet.dat`, LMDB branch syncs LMDB | Keep the LMDB behaviour; remove the BDB branch |

### 4.2 Options that must stay (LMDB)

- `-lmdbmapsize`, `-lmdbmaxmapsize`, `-lmdbwalletsize`,
  `-lmdbmaxwalletsize`, `-lmdbruntimegrow`, `-lmdbnosync`.
- `-checklmdb`, `-checklmdbdeep` (offline LMDB verification).
- `-upgradewallet`, `-rescan` (wallet format upgrade, not BDB-specific).

### 4.3 Startup diagnostics today

| Diagnostic | Location | Notes |
|---|---|---|
| `Using BerkeleyDB release: ...` | `init.cpp:668` | Printed unconditionally; remove |
| `Chain index backend: LMDB` / `Berkeley DB` | `InitLMDBChainDB`, `db.cpp:1298` | Keep for LMDB; BDB line disappears |
| `Wallet backend: LMDB` / `Berkeley DB` | `InitLMDBWalletDB`, `db.cpp:2066` | Keep for LMDB; BDB line disappears |
| `Chain index database: LMDB (...)` | `db.cpp:1387` | Keep |
| `Wallet database: LMDB (...)` | `db.cpp:1729` | Keep |
| `Migrating chain index from blkindex.dat to LMDB...` | `db.cpp:1236` | Moves to converter; daemon should never print it |
| `Migrating wallet from wallet.dat to LMDB...` | `db.cpp:1451` | Moves to converter; daemon should never print it |
| `getdbinfo` JSON | `rpcmain.cpp:330` | Keep; `configured_backend` becomes `lmdb`, `active_backend` LMDB, BDB statistics disappear |
| Qt Information database version | `qt/rpcconsole.cpp` | Remove BDB version; optionally show LMDB library version |

### 4.4 Required failure text

When a user supplies `-walletbackend=bdb` or `-dbbackend=bdb`, startup must
fail (not warn, not ignore) with:

```text
Berkeley DB support has been removed.
Please migrate your database to LMDB using phoenix-db-migrate.
```

The check must run before any database environment is opened or any file is
created.

---

## 5. Test, script and fixture map

### 5.1 Unit tests

| File | BDB dependency | Phase 4 action |
|---|---|---|
| `src/test/test_bitcoin.cpp` | Global fixture calls `bitdb.MakeMock()` and `bitdb.Flush(true)` | Replace with a temporary LMDB wallet/chain setup; no mock BDB |
| `src/test/kvdb_tests.cpp` | BDB KV cases (`bdb_kvdb_basic_crud`, `transactions`, `iteration`, `persistence`, `repeated_read_transactions`, `prefix_iteration`, `large_value_iteration`); BDB marker/authority/migration/backend tests (`wallet_bdb_marker_authority`, BDB branches of `chain_backend_marker`, `wallet_backend_marker`, migration tests) | Delete BDB implementation-detail cases; keep LMDB equivalents and marker-authority behaviour; add converter tests |
| `src/test/wallet_migration_tests.cpp` | The suite runs under the global mock BDB fixture; most cases create a source wallet through `CWalletDB` and call `MigrateMockWallet()` to invoke the in-daemon migration | Retarget to archived BDB fixtures or converter input; keep semantic coverage (keys, encryption, hybrid, keypool, transactions, ordering, labels, scripts) |
| `src/test/wallet_perf.cpp` | Separate benchmark with `bdb`, `lmdb`, `seed` modes; uses BDB environment and `CWalletDB` | Remove `bdb` mode or repurpose as converter benchmark; keep LMDB mode |
| `src/test/accounting_tests.cpp` | Includes `walletdb.h` (BDB header transitively) | Recompile only |
| `src/test/wallet_tests.cpp` | Incidental `bdb` substring only | No action |

### 5.2 Regression scripts

| Script | BDB fixture / dependency | Phase 4 action |
|---|---|---|
| `src/test/regression_lmdb_chain_migration.sh` | Starts daemon with `-dbbackend=bdb -walletbackend=bdb`, creates real `blkindex.dat`, then migrates | Convert to standalone converter fixture; daemon must reject `bdb` |
| `src/test/regression_lmdb_wallet_migration.sh` | Starts daemon with `-walletbackend=bdb`, creates real `wallet.dat`, then migrates | Same |
| `src/test/regression_lmdb_wallet_e2e.sh` | Full BDB wallet lifecycle, encrypted BDB restart, then migration | Same; preserve encrypted/hybrid coverage |
| `src/test/regression_lmdb_wallet_crash.sh` | Builds BDB wallet and kills during migration | Same; test converter restartability |
| `src/test/regression_lmdb_wallet_parity.sh` | Builds BDB and independently migrated LMDB wallets, compares canonical records | Same; converter must produce the LMDB side |
| `src/test/regression_lmdb_import_batch.sh` | Uses `-walletbackend=bdb` to keep the wallet out of the batch test | Replace with LMDB wallet or no wallet; no BDB daemon |
| `src/test/regression_lmdb_wallet_backup.sh` | LMDB-only today | Keep; extend only if backup paths change |
| `src/test/README.md` | Documents the above | Update after Phase 4 |

`make -f Makefile.linux nightly-lmdb` currently runs the backup, wallet
migration, chain migration and import-batch suites. It must be updated to run
the LMDB-only suite plus the standalone converter suite.

### 5.3 Fixtures

- Shell scripts create BDB fixtures by running the daemon with
  `-walletbackend=bdb` / `-dbbackend=bdb` and use `db_dump` to count records.
- `wallet_migration_tests.cpp` creates an in-memory mock BDB wallet and a
  temporary wallet file.
- There are no checked-in binary BDB fixtures in the repository.
- Phase 2/4 needs at least: a plain BDB wallet, an encrypted wallet, a hybrid
  wallet, a partially used keypool wallet, a legacy-record wallet, a BDB chain
  index and an interrupted-migration fixture. They can be generated once with
  the archive converter/db tools and stored under `src/test/data/bdb/` or
  produced by a scripted builder.

### 5.4 Current nightly target

`src/Makefile.linux:258`:

```make
nightly-lmdb: check-lmdb-backup
	./test/regression_lmdb_wallet_migration.sh ./phoenixcoind
	./test/regression_lmdb_chain_migration.sh ./phoenixcoind
	./test/regression_lmdb_import_batch.sh ./phoenixcoind
```

---

## 6. Documentation map

| File | BDB content | Phase |
|---|---|---|
| `doc/lmdb.md` | Backend selection, BDB migration, markers, returning to BDB, wallet backend | Rewrite as LMDB-only plus converter guide |
| `README.md` | Database backends, BDB compatibility, software requirements, build variables | Remove BDB requirement; document converter |
| `PROJECT_STATUS.md` | Hybrid storage wording, BDB migration claims, test descriptions | Update |
| `CHANGELOG.md` | Historical BDB/LMDB migration entries | Add removal entry; keep history |
| `src/test/README.md` | BDB migration test descriptions | Update |
| `doc/bdb-removal-inventory.md` | This document | Keep as historical Phase 0 record |

No `SECURITY.md`, translation catalog, or `contrib/` file contains a BDB
dependency.

---

## 7. Current migration paths and invariants

### 7.1 Chain-index migration today

`InitLMDBChainDB()` → `GetChainIndexStartupAction()` →
`CHAIN_INDEX_MIGRATE_BDB` → `CTxDB::MigrateToLMDB()`:

1. If `blkindex.dat` does not exist, return success.
2. Open `CTxDB db("r")` (read-only BDB).
3. Open a BDB cursor.
4. Begin one LMDB write transaction.
5. For each BDB record: read key/value, `txn->Write(key, value, true)`.
6. Abort on read/write failure; commit once at the end.
7. Print the number of copied records.
8. Close the BDB handle.
9. `InitLMDBChainDB()` writes `blkindex.backend = lmdb` after the switch.
10. `blkindex.dat` is left untouched.

Current gaps versus the Phase 2 specification:

- No per-record read-back comparison.
- No explicit final record-count comparison (only a printed count).
- No standalone process; the daemon must link BDB.
- BDB is opened inside the daemon, which already opened the BDB environment.
- Consistency is only proven later by `LoadBlockIndex`.

### 7.2 Wallet migration today

`InitLMDBWalletDBInternal()` → `GetWalletStartupAction()` →
`WALLET_MIGRATE_BDB` → `MigrateWalletToLMDB(dir)`:

1. If `wallet.dat` does not exist, return success.
2. Open `CWalletMigrationSource` = `CDB("wallet.dat", "r")`.
3. Open a BDB cursor.
4. Begin one LMDB write transaction.
5. For each record: write it, read it back inside the same transaction, compare
   bytes, increment the count.
6. After the loop: scan the LMDB transaction and require `nStored == nRecords`.
7. Abort if zero records, a write/read-back mismatch, or a count mismatch.
8. Commit once.
9. `InitLMDBWalletDBInternal()` writes `wallet.backend = lmdb` after the switch.
10. On failure, close and remove the newly created empty LMDB `wallet/`
    directory, leave `wallet.dat` untouched, and fail startup.
11. `wallet.dat` is opened read-only and left unchanged.

This is already close to the required sequence. Phase 2 should move the same
logic into `phoenix-db-migrate`, add semantic validation and an explicit
consistency check, and keep the original BDB untouched.

### 7.3 Marker policy (hard invariant — keep)

| On-disk state | Configured backend | Result |
|---|---|---|
| `*.backend = lmdb` | LMDB | LMDB authoritative; empty/missing LMDB is data loss, fail |
| `*.backend = lmdb` | BDB | Fail: this datadir uses LMDB |
| `*.backend = bdb` | BDB | BDB authoritative |
| `*.backend = bdb` | LMDB | Fail: this datadir uses BDB |
| No marker, non-empty LMDB | LMDB | Treat LMDB as authoritative (legacy dev build) |
| No marker, non-empty LMDB | BDB | Fail: LMDB index/wallet found |
| No marker, LMDB empty, BDB exists | LMDB | One-shot migration, then write marker |
| No marker, LMDB empty, no BDB | LMDB | Create new empty wallet / index |
| No marker, marker conflict/partial | Any | Explicit error, never automatic fallback |

After Phase 3, the `bdb` marker cases become recovery/error cases. The daemon
must never open a BDB marker as empty LMDB, and must never silently fall back.

### 7.4 Backup and recovery paths

| Path | BDB-specific | Phase 3 action |
|---|---|---|
| `backupwallet` RPC → `BackupWalletDB` | BDB branch copies `wallet.dat`; LMDB branch uses `BackupLMDBWallet` | Keep LMDB verified copy; remove BDB branch |
| `-salvagewallet` → `CWalletDB::Recover` | BDB verify/salvage/rename | Remove or replace with LMDB-only recovery |
| `CDBEnv::Verify` / `Salvage` | BDB `db.verify()` | Remove |
| `CDB::Rewrite` | BDB rewrite on encryption | Replace with `RewriteWalletLMDB` exclusively |
| Wallet flush loop | BDB `CloseDb`/`CheckpointLSN`; LMDB sync | Keep LMDB sync only |
| `-detachdb` / Qt `detachDB` | BDB detach | Remove |
| `-checklmdb` / `checklmdb` RPC | LMDB-only | Keep |

---

## 8. Phase mapping and proposed commit boundaries

### Phase 0 — this document

Completed inventory. No behaviour change.

### Phase 1 — deprecate BDB and prepare users

- Add startup warning when `-dbbackend=bdb` or `-walletbackend=bdb` is
  selected: BDB support will be removed, backup first, see converter docs.
- Add explicit startup diagnostic for configured and active backend plus
  on-disk marker/format (extend the existing `Chain index backend` /
  `Wallet backend` lines, or print marker/format lines).
- Document the converter procedure, verified backup requirement, disk-space
  and downtime.
- Keep LMDB default and current durability defaults.
- Add exact obsolete-option failure text (can be introduced in Phase 1 as a
  warning, then made fatal in Phase 3; the final state must be fatal).
- Do not delete BDB yet.

Files: `src/init.cpp`, `src/db.cpp`, `doc/lmdb.md`, `README.md`,
`PROJECT_STATUS.md`, `CHANGELOG.md`, `src/test/README.md`.

### Phase 2 — standalone `phoenix-db-migrate`

- New executable target linking BDB, **not** linked by `phoenixcoind`, the GUI
  or `test_phoenixcoin`.
- Inputs: BDB `wallet.dat`, BDB `blkindex.dat`, target datadir/LMDB paths.
- Open source read-only; validate; create temporary LMDB environment; import
  transactionally; read back and compare; verify counts/consistency; write
  marker only after success; leave source untouched.
- Restartable: partial temp LMDB is discarded or resumed deterministically;
  no marker means not migrated.
- Preserve every wallet and chain record listed in section 1.
- Add converter-specific tests and real BDB fixtures.

Files: new `src/db_migrate.cpp` (or `src/tools/`), `src/bdb_kv.*` retained only
for the converter, build files, new docs.

### Phase 3 — remove BDB from the runtime (focused commits)

1. Remove BDB wallet backend implementation (`CWalletDB`/`CDB` BDB branches,
   `CWalletDB::Recover`, BDB backup/flush, salvage).
2. Remove BDB chain-index backend implementation (`CTxDB::LoadBlockIndexGuts`
   BDB path, `CTxDB::MigrateToLMDB`, `CDBEnv` chain use).
3. Remove backend selection/fallback (`-dbbackend`, `-walletbackend`, BDB
   compatibility branches); reject obsolete options with the exact text.
4. Remove BDB environment/transaction abstractions (`CDBEnv`, `CDB` BDB
   members, `bdb_kv.*` from the daemon; keep only if needed by converter).
5. Remove BDB-specific backup/recovery paths from the runtime.
6. Remove BDB build dependencies from the three Makefiles and the Qt project.
7. Update docs/configuration/diagnostics; remove `DbEnv::version()` and the
   Qt BDB version display.

### Phase 4 — LMDB-only guarantees

- Replace the mock BDB fixture with a temporary LMDB fixture.
- Delete BDB implementation-detail tests; keep LMDB persistence, encryption,
  hybrid, keypool, atomic transaction, backup/restore, chain sync/reindex,
  import batching, crash recovery, map growth and corruption tests.
- Add the standalone converter suite (plain/encrypted/hybrid/legacy/keypool
  wallets, chain index, interrupted migration).
- Update `nightly-lmdb` to run LMDB-only suites plus converter suites.

### Phase 5 — LMDB-only release

- Ship LMDB-only daemon/GUI. **Done:** `e686f804`, `8a4cf3dc`, `5cc4575f`.
- Ship `phoenix-db-migrate` separately for one release cycle. **Done:** the
  `dist-db-migrate` target writes a converter-only bundle with documentation
  and checksums; the daemon and GUI are never included.
- Document that BDB installations must convert before upgrading. **Done:** the
  migration-window release guide and operator procedure (retired; see
  [`bdb-migration.md`](bdb-migration.md)).
- Keep the converter compatible with the Berkeley DB versions users actually
  used. **Done:** `--version` reports the converter, linked Berkeley DB and
  LMDB libraries; older on-disk formats are upgraded on a temporary copy;
  newer-than-converter sources fail with the linked version and a rebuild
  recommendation; `check-db-migrate-compat` exercises an older `libdb_cxx`.
- Monitor migration failures, wallet/chain mismatches, encrypted/hybrid
  reports, backup/restore failures and startup/recovery problems for the whole
  cycle. **Completed during the migration-window release cycle.**

### Phase 6 — final BDB removal

- Remove converter source, BDB dependency, fixtures and live migration docs.
  **Done.**
- Keep a historical migration guide and archived converter release. **Done:**
  [`bdb-migration.md`](bdb-migration.md) documents recovery with the archived
  converter bundle.
- Enter Phase 6 only after the Phase 5 exit criteria are met. **Done.**

---

## 9. Risks and decisions required before Phase 2

1. **`CDB` is both the BDB wrapper and the record API.** The cleanest removal
   keeps a narrow LMDB-only record class (or reuses `CLMDBDatabase` directly)
   and deletes the BDB fields/branches. Avoid leaving BDB types behind in
   `db.h`.
2. **`CAddrDB` must survive.** It is not BDB. Move it to `addrman.cpp` or a
   small `addrdb.cpp` rather than deleting it with BDB code.
3. **The unit-test fixture is the largest test migration.** Replace
   `bitdb.MakeMock()` with `InitLMDBWalletDBForTest()` (or an equivalent
   temporary environment) and ensure `LoadBlockIndex(true)` works with LMDB.
4. **The converter's link boundary is the key architectural constraint.**
   `bdb_kv.*` may stay for the converter, but it must not enter
   `phoenixcoind`, the GUI or the normal test binary. Consider a separate
   object list/target to prevent accidental linkage.
5. **`-salvagewallet` has no LMDB equivalent yet.** Decide whether to remove
   it, implement LMDB salvage, or point users at `-checklmdb` + backups.
6. **`DBErrors` enum names look like BDB but are backend-neutral.** Decide
   whether to rename them (`WalletLoadResult`) or keep them to minimize churn.
7. **BDB version diversity.** The converter must work with the BDB versions
   users actually used (the current build here links BDB 6.2; old wallets may
   come from 5.x). Do not assume one BDB version.
8. **No CI/packaging files exist in the repository.** Confirm where release
   packaging is defined outside this tree before claiming "release packages
   do not include BDB".
9. **Phase 1 warning vs. Phase 3 fatal.** The final behavior must be fatal.
   If a warning is added in Phase 1, it must be clearly temporary and the
   Phase 3 commit must replace it with the exact error text.
10. **`-flushwallet` is not BDB-only.** Keep the LMDB sync loop; remove only
    the BDB branch.

---

## Appendix A — Search commands used

```bash
# BDB-ish tokens, tracked files only
git grep -lE 'bdb_kv|db_cxx|DB_ENV|DB_TXN|DB_PRIVATE|DB_RECOVER|DB_AUTO_COMMIT|DBBackend|DB_BACKEND_BDB|CDBEnv|CBDBDatabase|CBDBTransaction|CBDBIterator|walletbackend|dbbackend|Berkeley ?DB|BerkeleyDB|libdb'

# Direct BDB header and library use
grep -rInE '#include *[<"](db_cxx|db)\.h[>"]' src
grep -rInE 'ldb_cxx|db_cxx|libdb' src/Makefile.* phoenixcoin-qt.pro Makefile

# BDB API use outside the abstraction
grep -rnE '\b(Db|DbEnv|DbTxn|Dbc|Dbt|DB_[A-Z_]+)\b' src --include=*.cpp --include=*.h

# Persistent database names
grep -rnE 'CDB\("|CWalletDB\(|CTxDB\(|blkindex\.dat|wallet\.dat|peers\.dat' src --include=*.cpp --include=*.h

# Runtime options
grep -rnE 'Get(Bool)?Arg\("-(dbbackend|walletbackend|salvagewallet|detachdb|privdb|dbcache|dblogsize|flushwallet)' src

# Tests and scripts
grep -rnE 'bdb|BDB|Berkeley|dbbackend|walletbackend|blkindex\.dat|wallet\.dat|db_dump' src/test
```

## Appendix B — Current linked BDB version (reference machine)

```text
libdb_cxx-6.2.so => /usr/lib/libdb_cxx-6.2.so
liblmdb.so       => /usr/lib/liblmdb.so
```

This is the build environment's version, not a constraint on the converter's
input compatibility.
