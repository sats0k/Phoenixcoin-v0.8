#include "hs/hybrid_message.h"
#include "hs/hybrid_script.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

// Fuzzes the pure HYBS container parser with arbitrary bytes.
//
// Sanitizers (ASan/UBSan/LSan) detect crashes, out-of-bounds reads, huge or
// repeated allocations, and undefined behavior. The structural assertion
// below pins the "no partially accepted data" contract: a successful parse
// must yield exactly the fixed ML-DSA-65 component sizes, and a rejected
// input must leave every output empty.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    std::vector<unsigned char> input(data, data + size);

    std::vector<unsigned char> compact;
    std::vector<unsigned char> ecdsaPub;
    std::vector<unsigned char> mldsaPub;
    std::vector<unsigned char> mldsaSig;

    const bool ok = ParseHybridMessage(input, compact, ecdsaPub, mldsaPub,
                                       mldsaSig);

    if (ok) {
        assert(compact.size() == 65);
        assert(ecdsaPub.size() == ECDSA_PUBKEY_SIZE);
        assert(mldsaPub.size() == ML_DSA_65_PUBKEY_SIZE);
        assert(mldsaSig.size() == ML_DSA_65_SIG_SIZE - 1);
    } else {
        assert(compact.empty());
        assert(ecdsaPub.empty());
        assert(mldsaPub.empty());
        assert(mldsaSig.empty());
    }

    return 0;
}