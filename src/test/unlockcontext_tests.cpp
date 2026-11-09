#include <boost/test/unit_test.hpp>

#include "qt/unlockcontext.h"

BOOST_AUTO_TEST_SUITE(unlockcontext_tests)

BOOST_AUTO_TEST_CASE(unlock_context_self_assignment_keeps_relock)
{
    int relocks = 0;
    {
        UnlockContext ctx([&relocks] { ++relocks; }, true, true);
        const UnlockContext& same = ctx;
        ctx = same;

        BOOST_CHECK(ctx.isValid());
        BOOST_CHECK_EQUAL(relocks, 0);
    }
    // Self-assignment must leave the context responsible for re-locking.
    BOOST_CHECK_EQUAL(relocks, 1);
}

BOOST_AUTO_TEST_CASE(unlock_context_copy_constructor_transfers_relock_once)
{
    int relocks = 0;
    {
        UnlockContext original([&relocks] { ++relocks; }, true, true);
        UnlockContext copy(original);

        BOOST_CHECK(copy.isValid());
        BOOST_CHECK_EQUAL(relocks, 0);
    }
    // Only the destination owns the responsibility after the copy.
    BOOST_CHECK_EQUAL(relocks, 1);
}

BOOST_AUTO_TEST_CASE(unlock_context_copy_assignment_transfers_relock_once)
{
    int relocks = 0;
    {
        UnlockContext destination([] {}, true, true);
        UnlockContext source([&relocks] { ++relocks; }, true, true);
        destination = source;

        BOOST_CHECK_EQUAL(relocks, 0);
    }
    // Only the destination owns the responsibility after the assignment.
    BOOST_CHECK_EQUAL(relocks, 1);
}

BOOST_AUTO_TEST_CASE(unlock_context_invalid_does_not_relock)
{
    int relocks = 0;
    {
        UnlockContext ctx([&relocks] { ++relocks; }, false, true);
    }
    BOOST_CHECK_EQUAL(relocks, 0);
}

BOOST_AUTO_TEST_SUITE_END()
