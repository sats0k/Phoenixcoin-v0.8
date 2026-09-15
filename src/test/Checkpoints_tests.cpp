//
// Unit tests for block-chain checkpoints
//
#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "../checkpoints.h"
#include "../util.h"

using namespace std;

BOOST_AUTO_TEST_SUITE(Checkpoints_tests)

BOOST_AUTO_TEST_CASE(sanity)
{
    uint256 p1 = uint256("0x006e800301bbd850d7ba67ad9295c3a940f5fc8f5581e3484967bd33c4c8b965");
    uint256 p4100000 = uint256("0x5721a9bf40f694be9fe2394577798a2466c94e427b9f141fb8b6c53c8660ad5c");
    BOOST_CHECK(Checkpoints::CheckHardened(1, p1));
    BOOST_CHECK(Checkpoints::CheckHardened(4100000, p4100000));

    // Wrong hashes at checkpoints should fail:
    BOOST_CHECK(!Checkpoints::CheckHardened(1, p4100000));
    BOOST_CHECK(!Checkpoints::CheckHardened(4100000, p1));

    // ... but any hash not at a checkpoint should succeed:
    BOOST_CHECK(Checkpoints::CheckHardened(2, p4100000));
    BOOST_CHECK(Checkpoints::CheckHardened(4100001, p1));

    BOOST_CHECK(Checkpoints::GetTotalBlocksEstimate() >= 4100000);
}

BOOST_AUTO_TEST_SUITE_END()
