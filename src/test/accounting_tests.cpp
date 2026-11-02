#include <boost/test/unit_test.hpp>


#include "init.h"
#include "wallet.h"
#include "walletdb.h"

BOOST_AUTO_TEST_SUITE(accounting_tests)

static void
GetResults(CWallet& wallet, CWalletDB& walletdb,
           std::map<int64, CAccountingEntry>& results)
{
    std::list<CAccountingEntry> aes;

    results.clear();
    BOOST_CHECK(walletdb.ReorderTransactions(&wallet) == DB_LOAD_OK);
    walletdb.ListAccountCreditDebit("", aes);
    for (CAccountingEntry& ae : aes)
    {
        results[ae.nOrderPos] = ae;
    }
}

BOOST_AUTO_TEST_CASE(acc_orderupgrade)
{
    // Use a private wallet file.  This test writes empty transactions, which
    // are deliberately rejected when a wallet is loaded, and accounting
    // entries.  Leaving them in the shared mock wallet.dat would make later
    // suites fail to load the wallet.
    CWallet wallet("accounting.dat");
    CWalletDB walletdb(wallet.strWalletFile);
    std::vector<CWalletTx*> vpwtx;
    CWalletTx wtx;
    CAccountingEntry ae;
    std::map<int64, CAccountingEntry> results;

    ae.strAccount = "";
    ae.nCreditDebit = 1;
    ae.nTime = 1333333333;
    ae.strOtherAccount = "b";
    ae.strComment = "";
    walletdb.WriteAccountingEntry(ae);

    wtx.mapValue["comment"] = "z";
    wallet.AddToWallet(wtx);
    vpwtx.push_back(&wallet.mapWallet[wtx.GetHash()]);
    vpwtx[0]->nTimeReceived = (unsigned int)1333333335;
    vpwtx[0]->nOrderPos = -1;

    ae.nTime = 1333333336;
    ae.strOtherAccount = "c";
    walletdb.WriteAccountingEntry(ae);

    GetResults(wallet, walletdb, results);

    BOOST_CHECK(wallet.nOrderPosNext == 3);
    BOOST_CHECK(2 == results.size());
    BOOST_CHECK(results[0].nTime == 1333333333);
    BOOST_CHECK(results[0].strComment.empty());
    BOOST_CHECK(1 == vpwtx[0]->nOrderPos);
    BOOST_CHECK(results[2].nTime == 1333333336);
    BOOST_CHECK(results[2].strOtherAccount == "c");


    ae.nTime = 1333333330;
    ae.strOtherAccount = "d";
    ae.nOrderPos = wallet.IncOrderPosNext();
    walletdb.WriteAccountingEntry(ae);

    GetResults(wallet, walletdb, results);

    BOOST_CHECK(results.size() == 3);
    BOOST_CHECK(wallet.nOrderPosNext == 4);
    BOOST_CHECK(results[0].nTime == 1333333333);
    BOOST_CHECK(1 == vpwtx[0]->nOrderPos);
    BOOST_CHECK(results[2].nTime == 1333333336);
    BOOST_CHECK(results[3].nTime == 1333333330);
    BOOST_CHECK(results[3].strComment.empty());


    wtx.mapValue["comment"] = "y";
    --wtx.nLockTime;  // Just to change the hash :)
    wallet.AddToWallet(wtx);
    vpwtx.push_back(&wallet.mapWallet[wtx.GetHash()]);
    vpwtx[1]->nTimeReceived = (unsigned int)1333333336;

    wtx.mapValue["comment"] = "x";
    --wtx.nLockTime;  // Just to change the hash :)
    wallet.AddToWallet(wtx);
    vpwtx.push_back(&wallet.mapWallet[wtx.GetHash()]);
    vpwtx[2]->nTimeReceived = (unsigned int)1333333329;
    vpwtx[2]->nOrderPos = -1;

    GetResults(wallet, walletdb, results);

    BOOST_CHECK(results.size() == 3);
    BOOST_CHECK(wallet.nOrderPosNext == 6);
    BOOST_CHECK(0 == vpwtx[2]->nOrderPos);
    BOOST_CHECK(results[1].nTime == 1333333333);
    BOOST_CHECK(2 == vpwtx[0]->nOrderPos);
    BOOST_CHECK(results[3].nTime == 1333333336);
    BOOST_CHECK(results[4].nTime == 1333333330);
    BOOST_CHECK(results[4].strComment.empty());
    BOOST_CHECK(5 == vpwtx[1]->nOrderPos);


    ae.nTime = 1333333334;
    ae.strOtherAccount = "e";
    ae.nOrderPos = -1;
    walletdb.WriteAccountingEntry(ae);

    GetResults(wallet, walletdb, results);

    BOOST_CHECK(results.size() == 4);
    BOOST_CHECK(wallet.nOrderPosNext == 7);
    BOOST_CHECK(0 == vpwtx[2]->nOrderPos);
    BOOST_CHECK(results[1].nTime == 1333333333);
    BOOST_CHECK(2 == vpwtx[0]->nOrderPos);
    BOOST_CHECK(results[3].nTime == 1333333336);
    BOOST_CHECK(results[3].strComment.empty());
    BOOST_CHECK(results[4].nTime == 1333333330);
    BOOST_CHECK(results[4].strComment.empty());
    BOOST_CHECK(results[5].nTime == 1333333334);
    BOOST_CHECK(6 == vpwtx[1]->nOrderPos);

    // The mocked Berkeley environment backs every logical database with the
    // same in-memory store.  Remove the empty transactions this test wrote:
    // they have no inputs or outputs, so a later suite that loads the wallet
    // would fail with DB_NONCRITICAL_ERROR.
    for (const std::pair<const uint256, CWalletTx>& item : wallet.mapWallet)
        walletdb.EraseTx(item.first);
}

BOOST_AUTO_TEST_SUITE_END()
