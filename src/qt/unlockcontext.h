#ifndef UNLOCKCONTEXT_H
#define UNLOCKCONTEXT_H

#include <functional>
#include <utility>

/* RAII context for a wallet unlock.  The destructor re-locks the wallet when
 * the context is valid and still owns the relock responsibility.  Copying
 * transfers that responsibility to the destination, so the source must not
 * re-lock as well.  Self-assignment is a no-op: it must not silently cancel
 * the responsibility to re-lock. */
class UnlockContext
{
public:
    typedef std::function<void()> RelockFunction;

    UnlockContext(RelockFunction relockFunction, bool valid, bool relock):
        relockFunction(std::move(relockFunction)),
        valid(valid),
        relock(relock)
    {
    }

    ~UnlockContext()
    {
        if (valid && relock && relockFunction)
            relockFunction();
    }

    bool isValid() const { return valid; }

    // Copy operator and constructor transfer the context
    UnlockContext(const UnlockContext& obj) { CopyFrom(obj); }
    UnlockContext& operator=(const UnlockContext& rhs) { CopyFrom(rhs); return *this; }

private:
    void CopyFrom(const UnlockContext& rhs)
    {
        // Self-assignment keeps the current object's relock responsibility.
        if (this == &rhs)
            return;

        relockFunction = rhs.relockFunction;
        valid = rhs.valid;
        relock = rhs.relock;
        rhs.relock = false;
    }

    RelockFunction relockFunction;
    bool valid;
    mutable bool relock; // mutable, as it can be set to false by copying
};

#endif
