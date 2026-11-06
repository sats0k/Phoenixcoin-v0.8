#include <boost/test/unit_test.hpp>

#include <filesystem>
#include <stdexcept>
#include <string>

#include "db.h"
#include "main.h"
#include "util.h"
#include "wallet.h"
#include "checkpoints.h"

CWallet* pwalletMain;
CClientUIInterface uiInterface;

enum Checkpoints::CPMode CheckpointsMode;
uint nMsgSleep;

extern bool fPrintToConsole;
extern void noui_connect();

namespace {

std::filesystem::path g_testDataDir;

} // namespace

struct TestingSetup {
    TestingSetup() {
        fPrintToDebugger = true; // don't want to write to debug.log file
        noui_connect();

        // The unit tests exercise the real LMDB backend in a throw-away data
        // directory.  There is no mocked Berkeley DB environment any more.
        g_testDataDir = std::filesystem::temp_directory_path() /
            ("phoenixcoin_unit_" + std::to_string(GetTimeMillis()));
        std::error_code ec;
        std::filesystem::remove_all(g_testDataDir, ec);
        std::filesystem::create_directories(g_testDataDir, ec);
        // BOOST_REQUIRE cannot be used from a global fixture: Boost flags every
        // assertion outside a test case as a setup failure, even a passing one.
        // Throw instead so a real failure is still reported with its message.
        if (ec)
            throw std::runtime_error("could not create test data directory " +
                                     g_testDataDir.string() + ": " +
                                     ec.message());
        mapArgs["-datadir"] = g_testDataDir.string();

        if (!InitLMDBChainDB())
            throw std::runtime_error("could not open the LMDB chain index");
        LoadBlockIndex(true);
        if (!InitLMDBWalletDBForTest(GetDataDir()))
            throw std::runtime_error("could not open the LMDB wallet");

        bool fFirstRun;
        pwalletMain = new CWallet("wallet.dat");
        pwalletMain->LoadWallet(fFirstRun);
        RegisterWallet(pwalletMain);
    }
    ~TestingSetup()
    {
        delete pwalletMain;
        pwalletMain = nullptr;
        CloseLMDBWalletDB();
        CloseLMDBChainDB();
        std::error_code ec;
        std::filesystem::remove_all(g_testDataDir, ec);
    }
};

BOOST_GLOBAL_FIXTURE(TestingSetup);

void Shutdown(void* /*parg*/)
{
  exit(0);
}

void StartShutdown()
{
  exit(0);
}

