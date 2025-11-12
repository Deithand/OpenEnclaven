cmake_minimum_required(VERSION 3.14)

# Fetch GoogleTest
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Include GoogleTest module
include(GoogleTest)

# Unit tests
add_executable(unit_tests
    unit/test_crypto.cpp
    unit/test_enclave.cpp
    unit/test_protocol.cpp
)

target_link_libraries(unit_tests
    PRIVATE
        openenclave_core
        GTest::gtest_main
        GTest::gmock_main
)

target_include_directories(unit_tests
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

# Discover tests
gtest_discover_tests(unit_tests)

# Fuzzing (only with Clang)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    option(ENABLE_FUZZING "Enable fuzzing targets" OFF)

    if(ENABLE_FUZZING)
        add_executable(fuzz_protocol
            fuzz/fuzz_protocol.cpp
        )

        target_link_libraries(fuzz_protocol
            PRIVATE
                openenclave_core
        )

        target_compile_options(fuzz_protocol
            PRIVATE
                -fsanitize=fuzzer,address
        )

        target_link_options(fuzz_protocol
            PRIVATE
                -fsanitize=fuzzer,address
        )

        add_executable(fuzz_crypto
            fuzz/fuzz_crypto.cpp
        )

        target_link_libraries(fuzz_crypto
            PRIVATE
                openenclave_core
        )

        target_compile_options(fuzz_crypto
            PRIVATE
                -fsanitize=fuzzer,address
        )

        target_link_options(fuzz_crypto
            PRIVATE
                -fsanitize=fuzzer,address
        )
    endif()
endif()
