cmake_minimum_required(VERSION 3.14)
project(OpenEnclaven VERSION 0.1.0 LANGUAGES CXX)

# C++17 standard required
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for clang-tidy
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        -Wformat=2
    )
endif()

# Security hardening flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Stack protector
    add_compile_options(-fstack-protector-strong)

    # Position independent code
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)

    # Fortify source
    add_compile_definitions(_FORTIFY_SOURCE=2)

    # No execute (NX) bit for stack
    if(NOT APPLE)
        add_link_options(-Wl,-z,noexecstack)
        add_link_options(-Wl,-z,relro)
        add_link_options(-Wl,-z,now)
    endif()
endif()

# Sanitizers (optional, enabled via cmake options)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if(ENABLE_ASAN)
    message(STATUS "AddressSanitizer enabled")
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

if(ENABLE_UBSAN)
    message(STATUS "UndefinedBehaviorSanitizer enabled")
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined)
endif()

if(ENABLE_TSAN)
    message(STATUS "ThreadSanitizer enabled")
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread)
endif()

# Find dependencies
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)

# Core library
add_library(openenclave_core STATIC
    src/core/enclave.cpp
    src/core/protocol.cpp
    src/crypto/crypto.cpp
)

target_link_libraries(openenclave_core
    PUBLIC
        OpenSSL::Crypto
)

target_include_directories(openenclave_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

# Server executable
add_executable(openenclave_server
    src/server/server.cpp
)

target_link_libraries(openenclave_server
    PRIVATE
        openenclave_core
)

# Client example
add_executable(client_example
    examples/client_example.cpp
)

target_link_libraries(client_example
    PRIVATE
        openenclave_core
)

# Testing
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install targets
install(TARGETS openenclave_server client_example
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include
)

install(TARGETS openenclave_core
    ARCHIVE DESTINATION lib
)
