cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(HybridSigner LANGUAGES CXX C)

# ---------------------------------------------------------------------------
# C++ standard
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# OpenSSL (ML-DSA requires OpenSSL 3.5+)
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)

if (OPENSSL_VERSION_NUMBER LESS 0x30500000L)
    message(FATAL_ERROR
        "OpenSSL >= 3.5.0 required for ML-DSA support")
endif()

message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")

# ---------------------------------------------------------------------------
# secp256k1 (vendored, production)
# ---------------------------------------------------------------------------
add_library(secp256k1 STATIC
    src/secp256k1/src/secp256k1.c
    src/secp256k1/src/precomputed_ecmult.c
    src/secp256k1/src/precomputed_ecmult_gen.c
)

set_target_properties(secp256k1 PROPERTIES
    LINKER_LANGUAGE C
)

target_include_directories(secp256k1
    PUBLIC
        src/secp256k1/include
        src/secp256k1/src
)

target_compile_definitions(secp256k1
    PRIVATE
        ENABLE_MODULE_ECDSA
        ENABLE_MODULE_RECOVERY
)

target_compile_options(secp256k1
    PRIVATE
        -fno-strict-aliasing
)

# ---------------------------------------------------------------------------
# Phoenixcoin crypto (REAL, minimal)
# ---------------------------------------------------------------------------
add_library(phoenixcoin_crypto STATIC
    src/key.cpp
)

target_include_directories(phoenixcoin_crypto
    PUBLIC
        src
)

target_link_libraries(phoenixcoin_crypto
    PUBLIC
        secp256k1
        OpenSSL::Crypto
)

# ---------------------------------------------------------------------------
# Hybrid signer (production)
# ---------------------------------------------------------------------------
add_library(hybrid_signer STATIC
    src/hs/hybrid_signer.cpp
    src/hs/hybrid_signer.h
)

target_include_directories(hybrid_signer
    PUBLIC
        src
)

target_link_libraries(hybrid_signer
    PUBLIC
        phoenixcoin_crypto
        OpenSSL::Crypto
)

# ---------------------------------------------------------------------------
# Fuzzers
# ---------------------------------------------------------------------------
option(ENABLE_FUZZ "Build libFuzzer targets" OFF)

add_library(phoenixcoin_fuzz_support STATIC
    src/test/fuzz/fuzz_support.cpp
)

target_include_directories(phoenixcoin_fuzz_support
    PUBLIC
        src
)

function(add_fuzzer name source)
    add_executable(${name} ${source})

    target_link_libraries(${name}
        PRIVATE
            hybrid_signer
            phoenixcoin_fuzz_support
            OpenSSL::Crypto
    )

    if (ENABLE_FUZZ)
        if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            message(FATAL_ERROR
                "ENABLE_FUZZ requires Clang/libFuzzer. "
                "Detected compiler: ${CMAKE_CXX_COMPILER_ID}")
        endif()

        target_compile_options(${name} PRIVATE
            -fsanitize=fuzzer,address,undefined
            -fno-omit-frame-pointer
        )

        target_link_options(${name} PRIVATE
            -fsanitize=fuzzer,address,undefined
        )
    endif()
endfunction()

add_fuzzer(fuzz_MLDSASigner_deserialize
    src/test/fuzz/fuzz_MLDSASigner_deserialize.cpp)

add_fuzzer(fuzz_encrypted_keys
    src/test/fuzz/fuzz_encrypted_keys.cpp)

add_fuzzer(fuzz_hybrid_verify
    src/test/fuzz/fuzz_hybrid_verify.cpp)

# ---------------------------------------------------------------------------
# Encrypted ML-DSA serialization round-trip test
# ---------------------------------------------------------------------------
add_executable(test_encrypted_keys
    src/test/test_encrypted_keys.cpp
)

target_link_libraries(test_encrypted_keys
    PRIVATE
        hybrid_signer
        phoenixcoin_fuzz_support
        OpenSSL::Crypto
)
