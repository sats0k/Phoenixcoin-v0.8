// Copyright (c) 2026 The Phoenixcoin developers
// Distributed under the MIT/X11 software licence, see the accompanying
// file LICENCE or http://opensource.org/license/mit

// Standalone Berkeley DB to LMDB converter.
//
// This utility is deliberately independent of the daemon object graph: it
// links db_cxx and liblmdb only, copies raw serialized records byte-for-byte,
// and never includes db.h, walletdb.h, wallet.h or main.h.  That keeps BDB
// out of the daemon after the runtime removal while preserving a migration
// path for existing installations.

#include <db.h>
#include <db_cxx.h>
#include <lmdb.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <csignal>

#ifdef _WIN32
#include <io.h>
#include <process.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace {

constexpr const char* CONVERTER_VERSION = "0.8.4";
constexpr const char* LMDB_DB_NAME = "main";
constexpr unsigned int LMDB_MAX_DBS = 64;
constexpr const char* COMPLETION_SIDECAR = ".phoenix-migration-complete";
constexpr const char* LOCK_FILE = ".phoenix-db-migrate.lock";
constexpr size_t PROGRESS_INTERVAL = 100000;

std::string FormatVersion(int major, int minor, int patch)
{
    return std::to_string(major) + "." + std::to_string(minor) + "." +
           std::to_string(patch);
}

std::string LinkedBdbVersion()
{
    int major = 0;
    int minor = 0;
    int patch = 0;
    db_version(&major, &minor, &patch);
    return FormatVersion(major, minor, patch);
}

std::string CompiledBdbVersion()
{
    return FormatVersion(DB_VERSION_MAJOR, DB_VERSION_MINOR,
                         DB_VERSION_PATCH);
}

std::string LinkedLmdbVersion()
{
    int major = 0;
    int minor = 0;
    int patch = 0;
    mdb_version(&major, &minor, &patch);
    return FormatVersion(major, minor, patch);
}

volatile sig_atomic_t g_interrupted = 0;

void SignalHandler(int) { g_interrupted = 1; }

unsigned long GetPid()
{
#ifdef _WIN32
    return static_cast<unsigned long>(_getpid());
#else
    return static_cast<unsigned long>(getpid());
#endif
}

bool IsInterrupted()
{
    return g_interrupted != 0;
}

void PrintError(const std::string& message)
{
    std::fprintf(stderr, "phoenix-db-migrate: error: %s\n", message.c_str());
}

void PrintUsage()
{
    std::printf(
        "phoenix-db-migrate %s\n"
        "Convert legacy Berkeley DB wallet.dat / blkindex.dat databases to LMDB.\n"
        "\n"
        "Usage: phoenix-db-migrate --datadir=<dir> [options]\n"
        "\n"
        "Options:\n"
        "  --datadir=<dir>          Data directory\n"
        "  --wallet                 Migrate wallet.dat only\n"
        "  --chain                  Migrate blkindex.dat only\n"
        "                           (default: every source that exists)\n"
        "  --wallet-source=<file>   Override <datadir>/wallet.dat\n"
        "  --chain-source=<file>    Override <datadir>/blkindex.dat\n"
        "  --wallet-target=<dir>    Override <datadir>/wallet\n"
        "  --chain-target=<dir>     Override <datadir>/blkindex\n"
        "  --map-size=<MiB>         Initial LMDB map size\n"
        "  --dry-run                Validate and report; write no target or marker\n"
        "  --verbose                Print progress while copying\n"
        "  --version                Print the converter and library versions\n"
        "  --help                   Print this help\n"
        "\n"
        "The original Berkeley DB files are opened read-only and are never\n"
        "modified, renamed or deleted.  Markers are written only after the\n"
        "LMDB environment has been copied, verified and installed.\n"
        "\n"
        "Berkeley DB library: %s (compiled against %s)\n"
        "LMDB library: %s\n",
        CONVERTER_VERSION, LinkedBdbVersion().c_str(),
        CompiledBdbVersion().c_str(), LinkedLmdbVersion().c_str());
}

struct Options
{
    fs::path datadir;
    bool migrateWallet = false;
    bool migrateChain = false;
    bool scopeExplicit = false;
    fs::path walletSource;
    fs::path chainSource;
    fs::path walletTarget;
    fs::path chainTarget;
    size_t mapSizeMiB = 0;
    bool dryRun = false;
    bool verbose = false;
};

bool ParseSizeMiB(const std::string& value, size_t& out)
{
    if (value.empty())
        return false;
    char* end = nullptr;
    errno = 0;
    unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (errno != 0 || end == value.c_str() || *end != '\0' || parsed == 0)
        return false;
    if (parsed > (std::numeric_limits<size_t>::max() / (1024ULL * 1024ULL)))
        return false;
    out = static_cast<size_t>(parsed);
    return true;
}

bool ParseArgs(int argc, char** argv, Options& options, std::string& error)
{
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        std::string key = arg;
        std::string value;
        const size_t eq = arg.find('=');
        if (eq != std::string::npos)
        {
            key = arg.substr(0, eq);
            value = arg.substr(eq + 1);
        }

        auto takeValue = [&](const char* name) -> bool {
            if (eq != std::string::npos)
                return true;
            if (i + 1 >= argc)
            {
                error = std::string("missing value for ") + name;
                return false;
            }
            value = argv[++i];
            return true;
        };

        if (key == "--help" || key == "-h")
        {
            PrintUsage();
            std::exit(0);
        }
        else if (key == "--version")
        {
            std::printf("phoenix-db-migrate %s\n", CONVERTER_VERSION);
            std::printf("Berkeley DB library: %s (compiled against %s)\n",
                        LinkedBdbVersion().c_str(),
                        CompiledBdbVersion().c_str());
            std::printf("LMDB library: %s\n", LinkedLmdbVersion().c_str());
            std::exit(0);
        }
        else if (key == "--wallet")
        {
            options.migrateWallet = true;
            options.scopeExplicit = true;
        }
        else if (key == "--chain")
        {
            options.migrateChain = true;
            options.scopeExplicit = true;
        }
        else if (key == "--dry-run")
        {
            options.dryRun = true;
        }
        else if (key == "--verbose")
        {
            options.verbose = true;
        }
        else if (key == "--map-size")
        {
            if (!takeValue("--map-size"))
                return false;
            if (!ParseSizeMiB(value, options.mapSizeMiB))
            {
                error = "--map-size must be a positive integer number of MiB";
                return false;
            }
        }
        else if (key == "--datadir")
        {
            if (!takeValue("--datadir"))
                return false;
            options.datadir = value;
        }
        else if (key == "--wallet-source")
        {
            if (!takeValue("--wallet-source"))
                return false;
            options.walletSource = value;
        }
        else if (key == "--chain-source")
        {
            if (!takeValue("--chain-source"))
                return false;
            options.chainSource = value;
        }
        else if (key == "--wallet-target")
        {
            if (!takeValue("--wallet-target"))
                return false;
            options.walletTarget = value;
        }
        else if (key == "--chain-target")
        {
            if (!takeValue("--chain-target"))
                return false;
            options.chainTarget = value;
        }
        else
        {
            error = "unknown option: " + arg;
            return false;
        }
    }

    if (!options.migrateWallet && !options.migrateChain)
    {
        options.migrateWallet = true;
        options.migrateChain = true;
    }

    if (options.datadir.empty() &&
        (options.walletSource.empty() || options.walletTarget.empty()) &&
        (options.chainSource.empty() || options.chainTarget.empty()))
    {
        error = "--datadir is required (or provide explicit source and target paths)";
        return false;
    }

    return true;
}

std::string Trim(std::string value)
{
    while (!value.empty() &&
           (value.back() == '\r' || value.back() == '\n' ||
            value.back() == ' ' || value.back() == '\t'))
        value.pop_back();
    while (!value.empty() &&
           (value.front() == ' ' || value.front() == '\t'))
        value.erase(value.begin());
    return value;
}

enum class MarkerState
{
    Absent,
    Lmdb,
    Bdb,
    Unknown,
};

MarkerState ReadMarker(const fs::path& path, std::string& value)
{
    value.clear();
    std::ifstream file(path);
    if (!file)
        return MarkerState::Absent;
    std::getline(file, value);
    value = Trim(value);
    if (value == "lmdb")
        return MarkerState::Lmdb;
    if (value == "bdb")
        return MarkerState::Bdb;
    return MarkerState::Unknown;
}

bool SyncFile(FILE* file)
{
    if (std::fflush(file) != 0)
        return false;
#ifdef _WIN32
    return _commit(_fileno(file)) == 0;
#else
    return fsync(fileno(file)) == 0;
#endif
}

bool WriteMarkerAtomic(const fs::path& path, const std::string& value,
                       std::string& error)
{
    const fs::path tmp = path.string() + ".tmp";
    FILE* file = std::fopen(tmp.string().c_str(), "wb");
    if (!file)
    {
        error = "cannot create " + tmp.string() + ": " + std::strerror(errno);
        return false;
    }
    const bool wrote = std::fprintf(file, "%s\n", value.c_str()) > 0 && SyncFile(file);
    const int closeResult = std::fclose(file);
    if (!wrote || closeResult != 0)
    {
        std::error_code ec;
        fs::remove(tmp, ec);
        error = "cannot write " + tmp.string();
        return false;
    }

    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec)
    {
        // Windows does not replace an existing file with rename().
        std::error_code removeEc;
        fs::remove(path, removeEc);
        ec.clear();
        fs::rename(tmp, path, ec);
    }
    if (ec)
    {
        std::error_code removeEc;
        fs::remove(tmp, removeEc);
        error = "cannot install " + path.string() + ": " + ec.message();
        return false;
    }
    return true;
}

class MigrationLock
{
public:
    ~MigrationLock()
    {
#ifdef _WIN32
        if (m_handle != INVALID_HANDLE_VALUE)
            CloseHandle(m_handle);
#else
        if (m_fd >= 0)
            close(m_fd);
#endif
    }

    bool Acquire(const fs::path& path, std::string& error)
    {
#ifdef _WIN32
        m_handle = CreateFileA(path.string().c_str(),
                               GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (m_handle == INVALID_HANDLE_VALUE)
        {
            error = "another migration appears to be running (cannot lock " +
                    path.string() + ")";
            return false;
        }
#else
        m_fd = open(path.string().c_str(), O_CREAT | O_RDWR, 0644);
        if (m_fd < 0)
        {
            error = "cannot open lock file " + path.string() + ": " +
                    std::strerror(errno);
            return false;
        }
        if (flock(m_fd, LOCK_EX | LOCK_NB) != 0)
        {
            error = "another migration appears to be running (cannot lock " +
                    path.string() + ")";
            return false;
        }
#endif
        return true;
    }

private:
#ifdef _WIN32
    HANDLE m_handle = INVALID_HANDLE_VALUE;
#else
    int m_fd = -1;
#endif
};

bool IsRegularNonEmptyFile(const fs::path& path, uintmax_t& size,
                           std::string& error)
{
    std::error_code ec;
    const fs::file_status status = fs::status(path, ec);
    if (ec)
    {
        error = "cannot inspect " + path.string() + ": " + ec.message();
        return false;
    }
    if (!fs::is_regular_file(status))
    {
        error = path.string() + " is not a regular file";
        return false;
    }
    size = fs::file_size(path, ec);
    if (ec)
    {
        error = "cannot read the size of " + path.string() + ": " + ec.message();
        return false;
    }
    if (size == 0)
    {
        error = path.string() + " is empty";
        return false;
    }
    return true;
}

size_t GetPageSize()
{
#ifdef _WIN32
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return static_cast<size_t>(info.dwPageSize);
#else
    const long pageSize = sysconf(_SC_PAGESIZE);
    return pageSize > 0 ? static_cast<size_t>(pageSize) : static_cast<size_t>(4096);
#endif
}

bool ChooseMapSize(uintmax_t sourceBytes, size_t overrideMiB, size_t& mapSize,
                   std::string& error)
{
    const size_t pageSize = GetPageSize();
    const bool is32Bit = sizeof(void*) < 8;
    const uintmax_t maxMap = is32Bit
        ? (uintmax_t(2) * 1024 * 1024 * 1024 - pageSize)
        : (uintmax_t(std::numeric_limits<size_t>::max()) -
           (std::numeric_limits<size_t>::max() % pageSize));

    uintmax_t wanted = 0;
    if (overrideMiB != 0)
    {
        wanted = uintmax_t(overrideMiB) * 1024ULL * 1024ULL;
    }
    else
    {
        const uintmax_t minimum = uintmax_t(64) * 1024ULL * 1024ULL;
        const uintmax_t extra = uintmax_t(16) * 1024ULL * 1024ULL;
        if (sourceBytes > (std::numeric_limits<uintmax_t>::max() - extra) / 2)
        {
            error = "source file is too large to size the LMDB map safely";
            return false;
        }
        wanted = sourceBytes * 2 + extra;
        if (wanted < minimum)
            wanted = minimum;
    }

    if (is32Bit && wanted > maxMap)
    {
        error = "the source needs an LMDB map larger than the 32-bit limit; "
                "build a 64-bit converter to migrate this data directory";
        return false;
    }
    if (wanted > maxMap)
    {
        error = "the requested LMDB map is too large for this platform";
        return false;
    }

    wanted = (wanted + pageSize - 1) / pageSize * pageSize;
    if (wanted > maxMap)
        wanted = maxMap;
    mapSize = static_cast<size_t>(wanted);
    return true;
}

bool ReadCompactSize(const unsigned char* data, size_t size, size_t& position,
                     uint64_t& value)
{
    if (position >= size)
        return false;
    const unsigned char first = data[position++];
    if (first < 253)
    {
        value = first;
        return true;
    }
    const size_t bytes = first == 253 ? 2 : (first == 254 ? 4 : 8);
    if (position + bytes > size)
        return false;
    uint64_t result = 0;
    for (size_t i = 0; i < bytes; ++i)
        result |= uint64_t(data[position + i]) << (8 * i);
    position += bytes;
    value = result;
    return true;
}

bool ParseKeyPrefix(const unsigned char* data, size_t size, std::string& prefix,
                    size_t& headerSize, std::string& error)
{
    size_t position = 0;
    uint64_t length = 0;
    if (!ReadCompactSize(data, size, position, length))
    {
        error = "record key does not start with a valid serialized string";
        return false;
    }
    if (length > size - position)
    {
        error = "record key string length exceeds the key size";
        return false;
    }
    prefix.assign(reinterpret_cast<const char*>(data + position),
                  static_cast<size_t>(length));
    headerSize = position + static_cast<size_t>(length);
    return true;
}

bool IsKnownWalletPrefix(std::string_view prefix)
{
    static const char* const known[] = {
        "version", "minversion", "key", "wkey", "ckey", "mkey",
        "keymeta", "defaultkey", "pool", "tx", "name", "acc",
        "acentry", "watch", "cscript", "orderposnext", "setting",
        "hyb", "hybaddr", "hybused",
    };
    for (const char* value : known)
    {
        if (prefix == value)
            return true;
    }
    return false;
}

bool IsKnownChainPrefix(std::string_view prefix)
{
    static const char* const known[] = {
        "version", "blockindex", "tx", "hashBestChain",
        "bnBestInvalidWork", "hashSyncCheckpoint", "strCheckpointPubKey",
    };
    for (const char* value : known)
    {
        if (prefix == value)
            return true;
    }
    return false;
}

struct MigrationStats
{
    size_t records = 0;
    std::map<std::string, size_t> prefixes;
    std::vector<std::string> unknownPrefixes;
};

bool ValidateRecordKey(bool wallet, const Dbt& key, MigrationStats& stats,
                       std::string& error)
{
    if (key.get_size() == 0 || key.get_data() == nullptr)
    {
        error = "found a record with an empty key";
        return false;
    }

    std::string prefix;
    size_t headerSize = 0;
    if (!ParseKeyPrefix(static_cast<const unsigned char*>(key.get_data()),
                        key.get_size(), prefix, headerSize, error))
        return false;

    const bool known = wallet ? IsKnownWalletPrefix(prefix)
                              : IsKnownChainPrefix(prefix);
    if (!known)
    {
        if (std::find(stats.unknownPrefixes.begin(), stats.unknownPrefixes.end(),
                      prefix) == stats.unknownPrefixes.end())
            stats.unknownPrefixes.push_back(prefix);
    }

    if ((prefix == "tx" || prefix == "blockindex") &&
        key.get_size() != headerSize + 32)
    {
        error = "record key for '" + prefix + "' does not contain a 32-byte hash";
        return false;
    }

    ++stats.prefixes[prefix];
    return true;
}

class BdbSource
{
public:
    ~BdbSource()
    {
        if (!m_upgraded.empty())
        {
            std::error_code ec;
            fs::remove(m_upgraded, ec);
        }
    }

    // Berkeley DB refuses to open databases written by an older release with
    // DB_OLD_VERSION.  Upgrade a temporary copy so the original source stays
    // byte-for-byte untouched and read-only.
    bool Prepare(const fs::path& source, std::string& error)
    {
        m_source = source;

        Db probe(nullptr, DB_CXX_NO_EXCEPTIONS);
        int rc = probe.open(nullptr, source.string().c_str(), LMDB_DB_NAME,
                            DB_BTREE, DB_RDONLY, 0);
        if (rc == 0)
        {
            probe.close(0);
            return true;
        }
        if (rc != DB_OLD_VERSION)
        {
            error = "cannot open " + source.string() + " read-only: " +
                    db_strerror(rc) +
                    ". If the database needs recovery, stop Phoenixcoin "
                    "cleanly and retry; never run recovery on the original.";
            return false;
        }

        const fs::path parent = source.parent_path().empty()
                                    ? fs::path(".")
                                    : source.parent_path();

        // Remove upgrade copies left by an interrupted earlier run.  The
        // datadir lock already excludes a concurrent conversion of the same
        // scope; these files are disposable by construction.
        const std::string stalePrefix =
            "." + source.filename().string() +
            ".phoenix-db-migrate-upgrade-";
        std::error_code staleEc;
        for (const auto& entry : fs::directory_iterator(parent, staleEc))
        {
            if (staleEc)
                break;
            const std::string name = entry.path().filename().string();
            if (name.rfind(stalePrefix, 0) == 0 &&
                entry.is_regular_file(staleEc))
            {
                std::error_code removeEc;
                fs::remove(entry.path(), removeEc);
            }
        }

        m_upgraded = parent /
            ("." + source.filename().string() +
             ".phoenix-db-migrate-upgrade-" + std::to_string(GetPid()) + "-" +
             std::to_string(static_cast<long long>(std::time(nullptr))));

        std::error_code ec;
        fs::remove(m_upgraded, ec);
        fs::copy_file(source, m_upgraded, fs::copy_options::overwrite_existing,
                      ec);
        if (ec)
        {
            const std::string message =
                "the source was written by an older Berkeley DB and a "
                "temporary copy for upgrading could not be created at " +
                m_upgraded.string() + ": " + ec.message();
            m_upgraded.clear();
            error = message;
            return false;
        }

        std::printf("Berkeley DB: upgrading a temporary copy of %s "
                    "(the source is not modified)\n",
                    source.filename().string().c_str());

        // DB->upgrade() takes the database file name and works without an
        // environment.  DB_UPGRADE on DB->open() is rejected for a standalone
        // named database file, so do not use it here.
        Db upgrader(nullptr, DB_CXX_NO_EXCEPTIONS);
        rc = upgrader.upgrade(m_upgraded.string().c_str(), 0);
        if (rc != 0)
        {
            const std::string message =
                "cannot upgrade the temporary Berkeley DB copy " +
                m_upgraded.string() + ": " + db_strerror(rc) +
                ". This converter links Berkeley DB " + LinkedBdbVersion() +
                "; the source may require a newer library.";
            fs::remove(m_upgraded, ec);
            m_upgraded.clear();
            error = message;
            return false;
        }
        return true;
    }

    const fs::path& Path() const
    {
        return m_upgraded.empty() ? m_source : m_upgraded;
    }

private:
    fs::path m_source;
    fs::path m_upgraded;
};

class BdbReader
{
public:
    ~BdbReader() { Close(); }

    bool Open(const fs::path& path, std::string& error)
    {
        const int rc = m_db.open(nullptr, path.string().c_str(), LMDB_DB_NAME,
                                 DB_BTREE, DB_RDONLY, 0);
        if (rc != 0)
        {
            error = "cannot open " + path.string() + " read-only: " +
                    db_strerror(rc) +
                    ". If the database needs recovery, stop Phoenixcoin "
                    "cleanly and retry; never run recovery on the original.";
            return false;
        }
        m_open = true;
        return true;
    }

    bool Verify(const fs::path& path, std::string& error)
    {
        Db verifier(nullptr, DB_CXX_NO_EXCEPTIONS);
        const int rc = verifier.verify(path.string().c_str(), LMDB_DB_NAME,
                                       nullptr, 0);
        if (rc != 0)
        {
            error = "Berkeley DB verification failed for " + path.string() +
                    ": " + db_strerror(rc) +
                    ". This converter links Berkeley DB " +
                    LinkedBdbVersion() +
                    "; a source written by a newer Berkeley DB needs a "
                    "converter built against that version or newer.";
            return false;
        }
        return true;
    }

    bool OpenCursor(std::string& error)
    {
        const int rc = m_db.cursor(nullptr, &m_cursor, 0);
        if (rc != 0)
        {
            error = std::string("cannot open a Berkeley DB cursor: ") +
                    db_strerror(rc);
            return false;
        }
        return true;
    }

    void CloseCursor()
    {
        if (m_cursor)
        {
            m_cursor->close();
            m_cursor = nullptr;
        }
    }

    bool Next(bool& done, std::string& error)
    {
        FreeBuffers();
        m_key.set_flags(DB_DBT_MALLOC);
        m_value.set_flags(DB_DBT_MALLOC);
        const int rc = m_cursor->get(&m_key, &m_value, DB_NEXT);
        if (rc == DB_NOTFOUND)
        {
            done = true;
            return true;
        }
        if (rc != 0)
        {
            error = std::string("Berkeley DB cursor read failed: ") +
                    db_strerror(rc);
            return false;
        }
        if (m_key.get_data() == nullptr || m_value.get_data() == nullptr)
        {
            error = "Berkeley DB returned a record with missing data";
            return false;
        }
        done = false;
        return true;
    }

    const Dbt& Key() const { return m_key; }
    const Dbt& Value() const { return m_value; }

    void FreeBuffers()
    {
        if (m_key.get_data() != nullptr)
        {
            std::free(m_key.get_data());
            m_key.set_data(nullptr);
            m_key.set_size(0);
        }
        if (m_value.get_data() != nullptr)
        {
            std::free(m_value.get_data());
            m_value.set_data(nullptr);
            m_value.set_size(0);
        }
    }

    void Close()
    {
        CloseCursor();
        FreeBuffers();
        if (m_open)
        {
            m_db.close(0);
            m_open = false;
        }
    }

private:
    Db m_db{nullptr, DB_CXX_NO_EXCEPTIONS};
    Dbc* m_cursor = nullptr;
    Dbt m_key;
    Dbt m_value;
    bool m_open = false;
};

bool CountBdbRecords(const fs::path& source, MigrationStats& stats,
                     bool wallet, std::string& error)
{
    BdbReader reader;
    if (!reader.Open(source, error))
        return false;
    if (!reader.OpenCursor(error))
        return false;

    bool done = false;
    while (!done)
    {
        if (!reader.Next(done, error))
            return false;
        if (done)
            break;
        if (!ValidateRecordKey(wallet, reader.Key(), stats, error))
            return false;
        ++stats.records;
        if (IsInterrupted())
        {
            error = "interrupted";
            return false;
        }
    }
    return true;
}

void PrintStats(const std::string& scope, const MigrationStats& stats)
{
    std::printf("%s records: %zu", scope.c_str(), stats.records);
    for (const auto& item : stats.prefixes)
        std::printf(" %s=%zu", item.first.c_str(), item.second);
    std::printf("\n");
    if (!stats.unknownPrefixes.empty())
    {
        std::printf("%s: preserving unknown record types:", scope.c_str());
        for (const std::string& prefix : stats.unknownPrefixes)
            std::printf(" '%s'", prefix.c_str());
        std::printf("\n");
    }
}

class LmdbWriter
{
public:
    ~LmdbWriter() { Close(); }

    bool Open(const fs::path& directory, size_t mapSize, std::string& error)
    {
        std::error_code ec;
        fs::create_directories(directory, ec);
        if (ec)
        {
            error = "cannot create staging directory " + directory.string() +
                    ": " + ec.message();
            return false;
        }

        int rc = mdb_env_create(&m_env);
        if (rc != 0)
        {
            error = std::string("mdb_env_create failed: ") + mdb_strerror(rc);
            return false;
        }
        rc = mdb_env_set_maxdbs(m_env, LMDB_MAX_DBS);
        if (rc != 0)
        {
            error = std::string("mdb_env_set_maxdbs failed: ") +
                    mdb_strerror(rc);
            Close();
            return false;
        }
        rc = mdb_env_set_mapsize(m_env, mapSize);
        if (rc != 0)
        {
            error = std::string("mdb_env_set_mapsize failed: ") +
                    mdb_strerror(rc);
            Close();
            return false;
        }
        rc = mdb_env_open(m_env, directory.string().c_str(), MDB_NOTLS, 0644);
        if (rc != 0)
        {
            error = "mdb_env_open(" + directory.string() + ") failed: " +
                    mdb_strerror(rc);
            Close();
            return false;
        }
        m_directory = directory;
        return true;
    }

    bool Begin(std::string& error)
    {
        int rc = mdb_txn_begin(m_env, nullptr, 0, &m_txn);
        if (rc != 0)
        {
            error = std::string("mdb_txn_begin failed: ") + mdb_strerror(rc);
            return false;
        }
        rc = mdb_dbi_open(m_txn, LMDB_DB_NAME, MDB_CREATE, &m_dbi);
        if (rc != 0)
        {
            error = std::string("mdb_dbi_open failed: ") + mdb_strerror(rc);
            mdb_txn_abort(m_txn);
            m_txn = nullptr;
            return false;
        }
        return true;
    }

    bool PutAndVerify(const Dbt& key, const Dbt& value, std::string& error)
    {
        MDB_val lmdbKey;
        lmdbKey.mv_size = key.get_size();
        lmdbKey.mv_data = key.get_data();
        MDB_val lmdbValue;
        lmdbValue.mv_size = value.get_size();
        lmdbValue.mv_data = value.get_data();

        int rc = mdb_put(m_txn, m_dbi, &lmdbKey, &lmdbValue, 0);
        if (rc != 0)
        {
            error = std::string("mdb_put failed: ") + mdb_strerror(rc);
            return false;
        }

        MDB_val stored;
        rc = mdb_get(m_txn, m_dbi, &lmdbKey, &stored);
        if (rc != 0)
        {
            error = std::string("mdb_get after write failed: ") +
                    mdb_strerror(rc);
            return false;
        }
        if (stored.mv_size != value.get_size() ||
            std::memcmp(stored.mv_data, value.get_data(), stored.mv_size) != 0)
        {
            error = "LMDB read-back does not match the Berkeley DB record";
            return false;
        }
        return true;
    }

    bool CountInTransaction(size_t& count, std::string& error)
    {
        count = 0;
        MDB_cursor* cursor = nullptr;
        int rc = mdb_cursor_open(m_txn, m_dbi, &cursor);
        if (rc != 0)
        {
            error = std::string("mdb_cursor_open failed: ") +
                    mdb_strerror(rc);
            return false;
        }
        MDB_val key;
        MDB_val value;
        rc = mdb_cursor_get(cursor, &key, &value, MDB_FIRST);
        while (rc == 0)
        {
            ++count;
            rc = mdb_cursor_get(cursor, &key, &value, MDB_NEXT);
        }
        mdb_cursor_close(cursor);
        if (rc != MDB_NOTFOUND)
        {
            error = std::string("LMDB cursor scan failed: ") +
                    mdb_strerror(rc);
            return false;
        }
        return true;
    }

    bool Commit(std::string& error)
    {
        if (!m_txn)
        {
            error = "no LMDB transaction is active";
            return false;
        }
        const int rc = mdb_txn_commit(m_txn);
        m_txn = nullptr;
        if (rc != 0)
        {
            error = std::string("mdb_txn_commit failed: ") +
                    mdb_strerror(rc);
            return false;
        }
        return true;
    }

    void Abort()
    {
        if (m_txn)
        {
            mdb_txn_abort(m_txn);
            m_txn = nullptr;
        }
    }

    void Close()
    {
        Abort();
        if (m_env)
        {
            mdb_env_close(m_env);
            m_env = nullptr;
        }
    }

private:
    MDB_env* m_env = nullptr;
    MDB_txn* m_txn = nullptr;
    MDB_dbi m_dbi = 0;
    fs::path m_directory;
};

bool OpenLmdbReadOnly(const fs::path& directory, MDB_env*& env,
                      std::string& error)
{
    int rc = mdb_env_create(&env);
    if (rc != 0)
    {
        error = std::string("mdb_env_create failed: ") + mdb_strerror(rc);
        return false;
    }
    rc = mdb_env_set_maxdbs(env, LMDB_MAX_DBS);
    if (rc != 0)
    {
        error = std::string("mdb_env_set_maxdbs failed: ") +
                mdb_strerror(rc);
        mdb_env_close(env);
        env = nullptr;
        return false;
    }
    rc = mdb_env_open(env, directory.string().c_str(),
                      MDB_RDONLY | MDB_NOTLS, 0644);
    if (rc != 0)
    {
        error = "mdb_env_open(" + directory.string() + ") failed: " +
                mdb_strerror(rc);
        mdb_env_close(env);
        env = nullptr;
        return false;
    }
    return true;
}

bool CountLmdbRecords(const fs::path& directory, size_t& count,
                      std::string& error)
{
    count = 0;
    MDB_env* env = nullptr;
    if (!OpenLmdbReadOnly(directory, env, error))
        return false;

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
    if (rc != 0)
    {
        error = std::string("mdb_txn_begin failed: ") + mdb_strerror(rc);
        mdb_env_close(env);
        return false;
    }

    MDB_dbi dbi = 0;
    rc = mdb_dbi_open(txn, LMDB_DB_NAME, 0, &dbi);
    if (rc != 0)
    {
        error = std::string("LMDB database '") + LMDB_DB_NAME +
                "' is missing: " + mdb_strerror(rc);
        mdb_txn_abort(txn);
        mdb_env_close(env);
        return false;
    }

    MDB_cursor* cursor = nullptr;
    rc = mdb_cursor_open(txn, dbi, &cursor);
    if (rc != 0)
    {
        error = std::string("mdb_cursor_open failed: ") + mdb_strerror(rc);
        mdb_txn_abort(txn);
        mdb_env_close(env);
        return false;
    }

    MDB_val key;
    MDB_val value;
    rc = mdb_cursor_get(cursor, &key, &value, MDB_FIRST);
    while (rc == 0)
    {
        ++count;
        rc = mdb_cursor_get(cursor, &key, &value, MDB_NEXT);
    }
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    mdb_env_close(env);
    if (rc != MDB_NOTFOUND)
    {
        error = std::string("LMDB cursor scan failed: ") + mdb_strerror(rc);
        return false;
    }
    return true;
}

bool CompareBdbAndLmdb(const fs::path& source, const fs::path& target,
                       size_t& count, std::string& error)
{
    BdbReader reader;
    if (!reader.Open(source, error))
        return false;
    if (!reader.OpenCursor(error))
        return false;

    MDB_env* env = nullptr;
    if (!OpenLmdbReadOnly(target, env, error))
        return false;

    MDB_txn* txn = nullptr;
    int rc = mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn);
    if (rc != 0)
    {
        error = std::string("mdb_txn_begin failed: ") + mdb_strerror(rc);
        mdb_env_close(env);
        return false;
    }
    MDB_dbi dbi = 0;
    rc = mdb_dbi_open(txn, LMDB_DB_NAME, 0, &dbi);
    if (rc != 0)
    {
        error = std::string("LMDB database '") + LMDB_DB_NAME +
                "' is missing: " + mdb_strerror(rc);
        mdb_txn_abort(txn);
        mdb_env_close(env);
        return false;
    }
    MDB_cursor* cursor = nullptr;
    rc = mdb_cursor_open(txn, dbi, &cursor);
    if (rc != 0)
    {
        error = std::string("mdb_cursor_open failed: ") + mdb_strerror(rc);
        mdb_txn_abort(txn);
        mdb_env_close(env);
        return false;
    }

    count = 0;
    bool bdbDone = false;
    MDB_val lmdbKey;
    MDB_val lmdbValue;
    rc = mdb_cursor_get(cursor, &lmdbKey, &lmdbValue, MDB_FIRST);
    bool lmdbDone = (rc == MDB_NOTFOUND);
    if (rc != 0 && rc != MDB_NOTFOUND)
    {
        error = std::string("LMDB cursor scan failed: ") + mdb_strerror(rc);
        mdb_cursor_close(cursor);
        mdb_txn_abort(txn);
        mdb_env_close(env);
        return false;
    }

    while (!bdbDone || !lmdbDone)
    {
        if (!bdbDone && !reader.Next(bdbDone, error))
        {
            mdb_cursor_close(cursor);
            mdb_txn_abort(txn);
            mdb_env_close(env);
            return false;
        }
        if (bdbDone != lmdbDone)
        {
            error = "Berkeley DB and LMDB record counts differ";
            mdb_cursor_close(cursor);
            mdb_txn_abort(txn);
            mdb_env_close(env);
            return false;
        }
        if (bdbDone)
            break;

        if (reader.Key().get_size() != lmdbKey.mv_size ||
            std::memcmp(reader.Key().get_data(), lmdbKey.mv_data,
                        lmdbKey.mv_size) != 0)
        {
            error = "Berkeley DB and LMDB keys differ";
            mdb_cursor_close(cursor);
            mdb_txn_abort(txn);
            mdb_env_close(env);
            return false;
        }
        if (reader.Value().get_size() != lmdbValue.mv_size ||
            std::memcmp(reader.Value().get_data(), lmdbValue.mv_data,
                        lmdbValue.mv_size) != 0)
        {
            error = "Berkeley DB and LMDB values differ";
            mdb_cursor_close(cursor);
            mdb_txn_abort(txn);
            mdb_env_close(env);
            return false;
        }

        ++count;
        rc = mdb_cursor_get(cursor, &lmdbKey, &lmdbValue, MDB_NEXT);
        lmdbDone = (rc == MDB_NOTFOUND);
        if (rc != 0 && rc != MDB_NOTFOUND)
        {
            error = std::string("LMDB cursor scan failed: ") +
                    mdb_strerror(rc);
            mdb_cursor_close(cursor);
            mdb_txn_abort(txn);
            mdb_env_close(env);
            return false;
        }
    }

    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    mdb_env_close(env);
    reader.Close();
    return true;
}

fs::path ParentOrCurrent(const fs::path& path)
{
    const fs::path parent = path.parent_path();
    return parent.empty() ? fs::path(".") : parent;
}

fs::path MakeStagingPath(const fs::path& target)
{
    const std::string name = "." + target.filename().string() +
        ".phoenix-migrate-" + std::to_string(GetPid()) + "-" +
        std::to_string(static_cast<long long>(std::time(nullptr)));
    return ParentOrCurrent(target) / name;
}

void RemoveStaleStaging(const fs::path& target)
{
    const fs::path parent = ParentOrCurrent(target);
    const std::string prefix = "." + target.filename().string() +
                               ".phoenix-migrate-";
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(parent, ec))
    {
        if (ec)
            break;
        const std::string name = entry.path().filename().string();
        if (name.rfind(prefix, 0) == 0 && entry.is_directory(ec))
        {
            std::error_code removeEc;
            fs::remove_all(entry.path(), removeEc);
        }
    }
}

bool WriteCompletionSidecar(const fs::path& staging, const std::string& scope,
                            size_t records, std::string& error)
{
    const fs::path path = staging / COMPLETION_SIDECAR;
    FILE* file = std::fopen(path.string().c_str(), "wb");
    if (!file)
    {
        error = "cannot create " + path.string() + ": " +
                std::strerror(errno);
        return false;
    }
    const bool wrote = std::fprintf(
        file, "scope=%s\nrecords=%zu\nconverter=%s\ntime=%lld\n",
        scope.c_str(), records, CONVERTER_VERSION,
        static_cast<long long>(std::time(nullptr))) > 0 && SyncFile(file);
    const int closeResult = std::fclose(file);
    if (!wrote || closeResult != 0)
    {
        std::error_code ec;
        fs::remove(path, ec);
        error = "cannot write " + path.string();
        return false;
    }
    return true;
}

bool HasCompletionSidecar(const fs::path& target)
{
    std::error_code ec;
    return fs::exists(target / COMPLETION_SIDECAR, ec) &&
           fs::is_regular_file(target / COMPLETION_SIDECAR, ec);
}

void MaybeKillAfterRecords(size_t records)
{
    const char* value = std::getenv(
        "PHOENIX_DB_MIGRATE_TEST_KILL_AFTER_RECORDS");
    if (value == nullptr || *value == '\0')
        return;
    const unsigned long long target = std::strtoull(value, nullptr, 10);
    if (target != 0 && records >= target)
    {
        std::fprintf(stderr,
                     "test hook: killed after %zu records\n", records);
        std::fflush(stderr);
#ifdef _WIN32
        _exit(137);
#else
        _exit(137);
#endif
    }
}

void MaybeKillAt(const char* variable)
{
    const char* value = std::getenv(variable);
    if (value == nullptr || *value == '\0' ||
        std::strcmp(value, "0") == 0)
        return;
    std::fprintf(stderr, "test hook: killed at %s\n", variable);
    std::fflush(stderr);
    _exit(137);
}

struct ScopePaths
{
    std::string name;
    fs::path source;
    fs::path target;
    fs::path marker;
    bool wallet = false;
};

bool MigrateScope(const ScopePaths& paths, const Options& options,
                  std::string& error)
{
    const std::string& scope = paths.name;

    uintmax_t sourceSize = 0;
    std::error_code ec;
    const bool sourceExists = fs::exists(paths.source, ec);
    if (!sourceExists)
    {
        std::string markerValue;
        const MarkerState marker = ReadMarker(paths.marker, markerValue);
        if (marker == MarkerState::Lmdb)
        {
            std::error_code targetEc;
            if (!fs::exists(paths.target, targetEc) ||
                !fs::is_directory(paths.target, targetEc))
            {
                error = scope + " marker says LMDB, but the LMDB environment " +
                        paths.target.string() +
                        " is missing; restore a verified backup";
                return false;
            }
            size_t count = 0;
            if (!CountLmdbRecords(paths.target, count, error))
                return false;
            std::printf("%s: already migrated to LMDB (%zu records); "
                        "Berkeley DB source is absent\n",
                        scope.c_str(), count);
            return true;
        }
        if (marker == MarkerState::Bdb)
        {
            error = scope + " marker says Berkeley DB, but " +
                    paths.source.string() + " does not exist";
            return false;
        }

        // With no explicit scope selection, a missing source is simply not
        // part of this data directory.
        if (!options.scopeExplicit)
        {
            std::printf("%s: skipped (no %s)\n", scope.c_str(),
                        paths.source.filename().string().c_str());
            return true;
        }
        error = scope + " source " + paths.source.string() +
                " does not exist";
        return false;
    }

    if (!IsRegularNonEmptyFile(paths.source, sourceSize, error))
        return false;

    std::string markerValue;
    const MarkerState marker = ReadMarker(paths.marker, markerValue);
    if (marker == MarkerState::Unknown)
    {
        error = scope + " marker " + paths.marker.string() +
                " contains an unsupported value '" + markerValue + "'";
        return false;
    }

    if (marker == MarkerState::Lmdb)
    {
        std::error_code targetEc;
        if (!fs::exists(paths.target, targetEc) ||
            !fs::is_directory(paths.target, targetEc))
        {
            error = scope + " marker says LMDB, but the LMDB environment " +
                    paths.target.string() +
                    " is missing; restore a verified backup";
            return false;
        }
        size_t count = 0;
        if (!CountLmdbRecords(paths.target, count, error))
            return false;
        if (count == 0)
        {
            error = scope + " marker says LMDB, but " + paths.target.string() +
                    " is empty; restore a verified backup";
            return false;
        }
        // Once the marker says LMDB, the daemon may have advanced the
        // environment since the original conversion (keypool refills, new
        // chain state).  The Berkeley DB source is historical evidence, not
        // a live equality requirement.
        std::printf("%s: already migrated to LMDB (%zu records)\n",
                    scope.c_str(), count);
        return true;
    }

    // Berkeley DB can read databases written by older releases, but a library
    // older than the source refuses to verify it.  Prepare the readable source
    // before the adopt/compare paths below touch it; an old-format source is
    // upgraded on a temporary copy, never in place.
    BdbSource bdbSource;
    if (!bdbSource.Prepare(paths.source, error))
        return false;
    const fs::path& readableSource = bdbSource.Path();

    const bool targetExists = fs::exists(paths.target, ec);
    bool targetIsEmpty = false;
    if (targetExists)
    {
        if (!fs::is_directory(paths.target, ec))
        {
            error = scope + " target " + paths.target.string() +
                    " exists and is not a directory";
            return false;
        }
        targetIsEmpty = fs::is_empty(paths.target, ec);
        if (!targetIsEmpty)
        {
            if (HasCompletionSidecar(paths.target))
            {
                size_t count = 0;
                if (!CompareBdbAndLmdb(readableSource, paths.target, count,
                                       error))
                {
                    error = scope + " target has a completion marker but does "
                            "not match the Berkeley DB source: " + error;
                    return false;
                }
                if (!WriteMarkerAtomic(paths.marker, "lmdb", error))
                    return false;
                std::error_code removeEc;
                fs::remove(paths.target / COMPLETION_SIDECAR, removeEc);
                std::printf("%s: completed an interrupted migration "
                            "(%zu records verified)\n",
                            scope.c_str(), count);
                return true;
            }
            error = scope + " target " + paths.target.string() +
                    " already exists and is not empty; refusing to overwrite "
                    "it.  Restore a verified backup or remove the target "
                    "deliberately, then retry.";
            return false;
        }
    }

    if (options.dryRun)
    {
        MigrationStats stats;
        if (!BdbReader().Verify(readableSource, error))
            return false;
        if (!CountBdbRecords(readableSource, stats, paths.wallet, error))
            return false;
        std::printf("%s: dry run OK; source is valid\n", scope.c_str());
        PrintStats(scope, stats);
        return true;
    }

    MigrationStats stats;
    std::printf("%s: validating %s (%llu bytes)\n", scope.c_str(),
                paths.source.string().c_str(),
                static_cast<unsigned long long>(sourceSize));
    {
        BdbReader verifier;
        if (!verifier.Verify(readableSource, error))
            return false;
    }

    size_t mapSize = 0;
    if (!ChooseMapSize(sourceSize, options.mapSizeMiB, mapSize, error))
        return false;

    RemoveStaleStaging(paths.target);
    const fs::path staging = MakeStagingPath(paths.target);
    std::error_code removeEc;
    fs::remove_all(staging, removeEc);

    BdbReader reader;
    if (!reader.Open(readableSource, error))
        return false;
    if (!reader.OpenCursor(error))
        return false;

    LmdbWriter writer;
    if (!writer.Open(staging, mapSize, error))
        return false;
    if (!writer.Begin(error))
        return false;

    std::printf("%s: copying records into %s (map size %zu bytes)\n",
                scope.c_str(), staging.string().c_str(), mapSize);

    bool done = false;
    while (!done)
    {
        if (IsInterrupted())
        {
            error = "interrupted";
            writer.Abort();
            reader.Close();
            fs::remove_all(staging, removeEc);
            return false;
        }
        if (!reader.Next(done, error))
        {
            writer.Abort();
            reader.Close();
            fs::remove_all(staging, removeEc);
            return false;
        }
        if (done)
            break;
        if (!ValidateRecordKey(paths.wallet, reader.Key(), stats, error))
        {
            writer.Abort();
            reader.Close();
            fs::remove_all(staging, removeEc);
            return false;
        }
        if (!writer.PutAndVerify(reader.Key(), reader.Value(), error))
        {
            writer.Abort();
            reader.Close();
            fs::remove_all(staging, removeEc);
            return false;
        }
        ++stats.records;
        MaybeKillAfterRecords(stats.records);
        if (options.verbose && stats.records % PROGRESS_INTERVAL == 0)
        {
            std::printf("%s: copied %zu records...\n", scope.c_str(),
                        stats.records);
            std::fflush(stdout);
        }
    }
    reader.Close();

    if (stats.records == 0)
    {
        writer.Abort();
        fs::remove_all(staging, removeEc);
        error = scope + " source contains no records";
        return false;
    }
    if (paths.wallet && stats.prefixes.count("version") == 0)
    {
        writer.Abort();
        fs::remove_all(staging, removeEc);
        error = "wallet source does not contain a version record";
        return false;
    }
    if (!paths.wallet)
    {
        if (stats.prefixes.count("version") == 0)
        {
            writer.Abort();
            fs::remove_all(staging, removeEc);
            error = "chain source does not contain a version record";
            return false;
        }
        if (stats.prefixes.count("blockindex") != 0 &&
            stats.prefixes.count("hashBestChain") == 0)
        {
            writer.Abort();
            fs::remove_all(staging, removeEc);
            error = "chain source contains blockindex records but no "
                    "hashBestChain record";
            return false;
        }
    }

    size_t lmdbCount = 0;
    if (!writer.CountInTransaction(lmdbCount, error))
    {
        writer.Abort();
        fs::remove_all(staging, removeEc);
        return false;
    }
    if (lmdbCount != stats.records)
    {
        writer.Abort();
        fs::remove_all(staging, removeEc);
        error = "record count mismatch before commit: source " +
                std::to_string(stats.records) + ", LMDB " +
                std::to_string(lmdbCount);
        return false;
    }

    if (!writer.Commit(error))
    {
        fs::remove_all(staging, removeEc);
        return false;
    }
    writer.Close();
    MaybeKillAt("PHOENIX_DB_MIGRATE_TEST_KILL_AFTER_COMMIT");

    size_t committedCount = 0;
    if (!CountLmdbRecords(staging, committedCount, error))
    {
        fs::remove_all(staging, removeEc);
        return false;
    }
    if (committedCount != stats.records)
    {
        fs::remove_all(staging, removeEc);
        error = "record count mismatch after commit: source " +
                std::to_string(stats.records) + ", LMDB " +
                std::to_string(committedCount);
        return false;
    }

    if (!WriteCompletionSidecar(staging, scope, committedCount, error))
    {
        fs::remove_all(staging, removeEc);
        return false;
    }

    if (targetExists && targetIsEmpty)
    {
        fs::remove(paths.target, removeEc);
        if (removeEc)
        {
            fs::remove_all(staging, removeEc);
            error = "cannot remove the empty target directory " +
                    paths.target.string();
            return false;
        }
    }

    fs::rename(staging, paths.target, ec);
    if (ec)
    {
        error = "cannot install the verified LMDB environment at " +
                paths.target.string() + ": " + ec.message() +
                " (the complete staging environment remains at " +
                staging.string() + ")";
        return false;
    }
    MaybeKillAt("PHOENIX_DB_MIGRATE_TEST_KILL_AFTER_RENAME");

    if (!WriteMarkerAtomic(paths.marker, "lmdb", error))
        return false;

    std::error_code removeSidecarEc;
    fs::remove(paths.target / COMPLETION_SIDECAR, removeSidecarEc);

    std::printf("%s: migration complete\n", scope.c_str());
    PrintStats(scope, stats);
    std::printf("%s: LMDB environment: %s\n", scope.c_str(),
                paths.target.string().c_str());
    std::printf("%s: marker: %s (lmdb)\n", scope.c_str(),
                paths.marker.string().c_str());
    std::printf("%s: Berkeley DB source left untouched: %s\n", scope.c_str(),
                paths.source.string().c_str());
    return true;
}

} // namespace

int main(int argc, char** argv)
{
    Options options;
    std::string error;
    if (!ParseArgs(argc, argv, options, error))
    {
        PrintError(error);
        std::fprintf(stderr, "Try --help for usage.\n");
        return 2;
    }

    std::signal(SIGINT, SignalHandler);
    std::signal(SIGTERM, SignalHandler);

    if (!options.datadir.empty())
    {
        std::error_code ec;
        fs::create_directories(options.datadir, ec);
        if (ec)
        {
            PrintError("cannot create data directory " +
                       options.datadir.string() + ": " + ec.message());
            return 1;
        }
    }

    const fs::path lockPath = options.datadir.empty()
        ? fs::temp_directory_path() / LOCK_FILE
        : options.datadir / LOCK_FILE;
    MigrationLock lock;
    if (!lock.Acquire(lockPath, error))
    {
        PrintError(error);
        return 1;
    }

    fs::path walletSource = options.walletSource;
    fs::path chainSource = options.chainSource;
    fs::path walletTarget = options.walletTarget;
    fs::path chainTarget = options.chainTarget;

    if (walletSource.empty() && !options.datadir.empty())
        walletSource = options.datadir / "wallet.dat";
    if (chainSource.empty() && !options.datadir.empty())
        chainSource = options.datadir / "blkindex.dat";
    if (walletTarget.empty() && !options.datadir.empty())
        walletTarget = options.datadir / "wallet";
    if (chainTarget.empty() && !options.datadir.empty())
        chainTarget = options.datadir / "blkindex";

    if (options.migrateWallet)
    {
        if (walletSource.empty() || walletTarget.empty())
        {
            PrintError("wallet migration needs a data directory or explicit "
                       "wallet source and target paths");
            return 2;
        }
        ScopePaths paths;
        paths.name = "wallet";
        paths.wallet = true;
        paths.source = walletSource;
        paths.target = walletTarget;
        paths.marker = options.datadir.empty()
            ? ParentOrCurrent(walletTarget) / "wallet.backend"
            : options.datadir / "wallet.backend";
        if (!MigrateScope(paths, options, error))
        {
            PrintError(error);
            return 1;
        }
    }

    if (options.migrateChain)
    {
        if (chainSource.empty() || chainTarget.empty())
        {
            PrintError("chain migration needs a data directory or explicit "
                       "chain source and target paths");
            return 2;
        }
        ScopePaths paths;
        paths.name = "chain index";
        paths.wallet = false;
        paths.source = chainSource;
        paths.target = chainTarget;
        paths.marker = options.datadir.empty()
            ? ParentOrCurrent(chainTarget) / "blkindex.backend"
            : options.datadir / "blkindex.backend";
        if (!MigrateScope(paths, options, error))
        {
            PrintError(error);
            return 1;
        }
    }

    return 0;
}
