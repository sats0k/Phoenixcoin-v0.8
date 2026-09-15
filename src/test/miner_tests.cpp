#include <boost/test/unit_test.hpp>

#include "bignum.h"
#include "main.h"
#include "util.h"

BOOST_AUTO_TEST_SUITE(miner_tests)

BOOST_AUTO_TEST_CASE(GetProofOfWorkReward_mainnet)
{
    // The original Bitcoin-era miner test used SHA256 PoW nonces and
    // Bitcoin halving heights. Phoenixcoin replaces the PoW with NeoScrypt
    // and rewards by a fork-based schedule that halves every 1M blocks, so
    // this test verifies the subsidy math directly against those rules.

    // 50 PXC per block before fork three and from fork four onwards ...
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0), 50LL * COIN);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(nForkThree - 1, 0), 50LL * COIN);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(nForkFour, 0), 50LL * COIN);

    // ... but only 25 PXC between the 3rd and 4th hard fork.
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(nForkThree, 0), 25LL * COIN);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(nForkFour - 1, 0), 25LL * COIN);

    // Halving every 1,000,000 blocks: the subsidy amount (50 * COIN) is
    // right-shifted one bit per halving, so rewards become fractional.
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(999999, 0), 50LL * COIN);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(1000000, 0), (50LL * COIN) >> 1);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(2000000, 0), (50LL * COIN) >> 2);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(3000000, 0), (50LL * COIN) >> 3);
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(4000000, 0), (50LL * COIN) >> 4);

    // Fees are added on top of the subsidy.
    BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 12345), 50LL * COIN + 12345);
}

BOOST_AUTO_TEST_CASE(GetProofOfWorkReward_testnet)
{
    bool fSavedTestNet = fTestNet;
    fTestNet = true;
    do
    {
        // Before the 1st testnet hard fork the reward is 25 PXC ...
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(0, 0), 25LL * COIN);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(nTestnetForkOne - 1, 0), 25LL * COIN);

        // ... and 50 PXC from then on (halving still applies).
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(nTestnetForkOne, 0), 50LL * COIN);
        BOOST_CHECK_EQUAL(GetProofOfWorkReward(1000000, 0), 25LL * COIN);
    }
    while (0);
    fTestNet = fSavedTestNet;
}

BOOST_AUTO_TEST_CASE(GetMoneySupply_mainnet)
{
    // Genesis blocks are unspendable but still counted (nHeight + 1).
    int64 nHeight = 0;
    BOOST_CHECK_EQUAL(GetMoneySupply(nHeight), (nHeight + 1) * 50LL * COIN);
    nHeight = nForkThree - 1;
    BOOST_CHECK_EQUAL(GetMoneySupply(nHeight), (nHeight + 1) * 50LL * COIN);

    // 50 PXC up to fork three, then 25 PXC to fork four (interior heights).
    nHeight = nForkThree;
    BOOST_CHECK_EQUAL(GetMoneySupply(nHeight),
                      nForkThree * 50LL * COIN + (nHeight - nForkThree + 1) * 25LL * COIN);
    nHeight = nForkFour - 1;
    BOOST_CHECK_EQUAL(GetMoneySupply(nHeight),
                      nForkThree * 50LL * COIN + (nHeight - nForkThree + 1) * 25LL * COIN);

    // 50 PXC from fork four to the first halving (block 1000000).
    nHeight = 999999;
    BOOST_CHECK_EQUAL(GetMoneySupply(nHeight),
                      nForkThree * 50LL * COIN +
                      (nForkFour - nForkThree) * 25LL * COIN +
                      (nHeight - nForkFour + 1) * 50LL * COIN);

    // At the first halving the accumulated 50 PXC era stops at 999999 and
    // block 1000000 is counted at the halved 25 PXC reward.
    nHeight = 1000000;
    BOOST_CHECK_EQUAL(GetMoneySupply(nHeight),
                      nForkThree * 50LL * COIN +
                      (nForkFour - nForkThree) * 25LL * COIN +
                      (1000000 - nForkFour) * 50LL * COIN +
                      (nHeight - 1000000 + 1) * 25LL * COIN);
}

BOOST_AUTO_TEST_CASE(GetMoneySupply_testnet)
{
    bool fSavedTestNet = fTestNet;
    fTestNet = true;
    do
    {
        // Testnet supply starts from zero at genesis.
        int64 nHeight = 0;
        BOOST_CHECK_EQUAL(GetMoneySupply(nHeight), nHeight * 25LL * COIN);
        nHeight = nTestnetForkOne - 1;
        BOOST_CHECK_EQUAL(GetMoneySupply(nHeight), nHeight * 25LL * COIN);

        nHeight = nTestnetForkOne;
        BOOST_CHECK_EQUAL(GetMoneySupply(nHeight),
                          nTestnetForkOne * 25LL * COIN +
                          (nHeight - nTestnetForkOne + 1) * 50LL * COIN);
    }
    while (0);
    fTestNet = fSavedTestNet;
}

BOOST_AUTO_TEST_CASE(IncrementExtraNonce_increments_and_resets)
{
    // Exercise the miner's extra-nonce scramble without a live chain: the
    // cache keyed on hashPrevBlock resets nExtraNonce when the parent
    // changes, fills in the coinbase scriptSig and rebuilds the merkle tree.
    CBlock block;
    CBlockIndex indexPrev;
    indexPrev.nHeight = 5000;

    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    block.vtx.push_back(txNew);

    unsigned int nExtraNonce = 0;
    block.hashPrevBlock = 0;
    IncrementExtraNonce(&block, &indexPrev, nExtraNonce);
    BOOST_CHECK_EQUAL(nExtraNonce, 1);
    BOOST_CHECK(block.hashMerkleRoot != 0);

    // Same parent block: extra nonce keeps climbing.
    IncrementExtraNonce(&block, &indexPrev, nExtraNonce);
    BOOST_CHECK_EQUAL(nExtraNonce, 2);

    // New parent block: extra nonce resets and the coinbase scriptSig now
    // carries the height and the reset nonce.
    block.hashPrevBlock = 1;
    IncrementExtraNonce(&block, &indexPrev, nExtraNonce);
    BOOST_CHECK_EQUAL(nExtraNonce, 1);
    BOOST_CHECK(block.vtx[0].vin[0].scriptSig.size() > 0);
    BOOST_CHECK(block.hashMerkleRoot != 0);
}

BOOST_AUTO_TEST_SUITE_END()