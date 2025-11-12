# OpenEnclaven - Secure Enclave Prototype

[![CI](https://github.com/yourusername/OpenEnclaven/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/OpenEnclaven/actions/workflows/ci.yml)

⚠️ **SECURITY WARNING**: This is a research prototype and educational implementation. **No software provides absolute security guarantees.** This implementation has NOT been formally verified, professionally audited, or tested in production environments. Use at your own risk.

## Overview

OpenEnclaven is a C++17 prototype of a virtual "Secure Enclave" - a self-contained process/library that simulates a Trusted Execution Environment (TEE). It demonstrates secure coding practices, cryptographic isolation, and defensive programming techniques.

### Key Features

- **Isolated Execution Context**: Enclave operates as a separate process with minimal API surface
- **Encrypted Memory**: All sensitive data is encrypted at rest using AES-256-GCM
- **Modern C++ Design**: RAII, smart pointers, explicit error handling
- **Security Hardening**: Stack protection, ASLR, NX bit, FORTIFY_SOURCE
- **Comprehensive Testing**: Unit tests, fuzzing, sanitizers (ASan, UBSan, TSan)
- **Static Analysis**: clang-tidy, cppcheck integration
- **CI/CD Pipeline**: Automated security testing on every commit

## Architecture

```
┌─────────────────────────────────────────┐
│         Client Application              │
└────────────────┬────────────────────────┘
                 │ Unix Domain Socket
                 │ (Serialized Protocol)
┌────────────────▼────────────────────────┐
│      Enclave Server (Isolated)          │
│  ┌──────────────────────────────────┐  │
│  │   Encrypted Memory Region        │  │
│  │  - Modules (encrypted bytecode)  │  │
│  │  - Secure Storage (AES-256-GCM)  │  │
│  │  - Master Key (never exported)   │  │
│  └──────────────────────────────────┘  │
│                                          │
│  API:                                    │
│  - CreateContext                         │
│  - LoadModule                            │
│  - InvokeFunction                        │
│  - StoreData / RetrieveData              │
│  - GetAttestation (simulated)            │
│  - DestroyContext                        │
└──────────────────────────────────────────┘
```

## Threat Model

### Security Goals

1. **Confidentiality**: Sensitive data is encrypted and cannot be read by unauthorized parties
2. **Integrity**: Data tampering is detected through authentication tags (GCM)
3. **Isolation**: Enclave operates in a separate process with limited IPC
4. **Memory Safety**: Prevent buffer overflows, use-after-free, and other memory bugs

### Assumptions

- **Trusted OS Kernel**: We assume the operating system kernel is not compromised
- **Trusted Hardware**: No hardware attacks (side-channels, fault injection)
- **No Physical Access**: Attacker cannot access physical memory or devices
- **Secure Cryptographic Primitives**: OpenSSL implementation is correct
- **Local Attacker Only**: Network attacks are out of scope

### Known Limitations

⚠️ **This prototype does NOT protect against**:

1. **Side-Channel Attacks**:
   - Cache timing attacks (Spectre, Meltdown variants)
   - Power analysis
   - EM radiation analysis
   - Branch prediction side-channels

2. **Privileged Attackers**:
   - Root/administrator access
   - Kernel exploits
   - Debugger attachment (ptrace)
   - Memory dumps

3. **Hardware Attacks**:
   - Cold boot attacks
   - DMA attacks
   - Physical tampering
   - Rowhammer

4. **Denial of Service**:
   - Resource exhaustion
   - Socket flooding
   - Fuzzing-based crashes (mitigated but not eliminated)

5. **Implementation Gaps**:
   - Module execution is simulated (no real bytecode interpreter)
   - Attestation is mocked (no cryptographic proof)
   - No secure boot or code signing
   - Limited rate limiting

### Attack Surface

**Minimal API** (5 operations):
- `LoadModule`: Validated size limits, encrypted storage
- `InvokeFunction`: Bounds checking, function table lookup
- `StoreData` / `RetrieveData`: Key validation, size limits
- `GetAttestation`: Read-only, simulated

**Network Interface**: Unix domain socket (local only)

**Dependencies**: OpenSSL (libcrypto) for cryptographic primitives

## Building

### Prerequisites

- CMake 3.14+
- C++17 compatible compiler (GCC 11+, Clang 14+)
- OpenSSL 1.1.1+ development headers
- (Optional) clang-tidy, cppcheck for static analysis
- (Optional) Clang for fuzzing with libFuzzer

### Ubuntu/Debian

```bash
sudo apt-get install cmake ninja-build g++ libssl-dev
```

### Build Commands

```bash
# Standard build
mkdir build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ..
cmake --build .

# Run tests
ctest --output-on-failure

# Build with sanitizers
cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON ..
cmake --build .
ctest --output-on-failure

# Build with fuzzing (Clang only)
cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DENABLE_FUZZING=ON ..
cmake --build .
./tests/fuzz_protocol -max_total_time=60
./tests/fuzz_crypto -max_total_time=60
```

## Usage

### Starting the Server

```bash
./build/openenclave_server
```

The server listens on `/tmp/openenclave.sock` (Unix domain socket).

### Client Example

```bash
./build/client_example
```

This runs a series of test operations:
1. Load a module
2. Invoke a function
3. Store encrypted data
4. Retrieve and decrypt data
5. Get attestation

### Programmatic API

```cpp
#include "openenclave/enclave.hpp"

// Create enclave
auto result = openenclave::Enclave::Create();
if (result.IsError()) {
    // Handle error
    std::cerr << openenclave::StatusToString(result.GetStatus()) << std::endl;
    return 1;
}
auto enclave = std::move(result.GetValue());

// Load module
std::vector<uint8_t> module_data = { /* bytecode */ };
auto load_result = enclave->LoadModule(module_data);
if (load_result.IsOk()) {
    auto handle = load_result.GetValue();

    // Invoke function
    std::vector<uint8_t> params = { /* parameters */ };
    auto invoke_result = enclave->InvokeFunction(
        handle, "my_function", params
    );

    if (invoke_result.IsOk()) {
        auto result_data = invoke_result.GetValue();
        // Process result
    }
}

// Store sensitive data
std::vector<uint8_t> secret = { /* sensitive data */ };
enclave->StoreData("my_secret_key", secret);

// Retrieve data
auto retrieve_result = enclave->RetrieveData("my_secret_key");
if (retrieve_result.IsOk()) {
    auto decrypted = retrieve_result.GetValue();
    // Use decrypted data
}
```

## Testing Strategy

### 1. Unit Testing (GoogleTest)

**Coverage**: Cryptographic operations, enclave API, protocol serialization

```bash
cd build
ctest --verbose
```

**Test Categories**:
- Crypto: Encryption/decryption, key management, hash functions
- Enclave: Module loading, function invocation, secure storage
- Protocol: Serialization, validation, error handling

### 2. Fuzzing (libFuzzer)

**Target**: Protocol parser, crypto operations, deserialization

```bash
# Build with fuzzing
cmake -DENABLE_FUZZING=ON -DCMAKE_CXX_COMPILER=clang++ ..
cmake --build .

# Run protocol fuzzer (1 hour)
./tests/fuzz_protocol -max_total_time=3600 -timeout=10

# Run crypto fuzzer (1 hour)
./tests/fuzz_crypto -max_total_time=3600 -timeout=10
```

**Coverage**:
- Malformed protocol messages
- Invalid CRC checksums
- Oversized payloads
- Edge cases in encryption/decryption

### 3. Memory Safety (Sanitizers)

**AddressSanitizer (ASan)**: Detects memory errors

```bash
cmake -DENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
ctest
```

**Detects**:
- Heap/stack buffer overflows
- Use-after-free
- Memory leaks
- Double free

**UndefinedBehaviorSanitizer (UBSan)**: Detects undefined behavior

```bash
cmake -DENABLE_UBSAN=ON -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
ctest
```

**Detects**:
- Integer overflows
- Null pointer dereference
- Misaligned access
- Invalid casts

**ThreadSanitizer (TSan)**: Detects data races

```bash
cmake -DENABLE_TSAN=ON -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
ctest
```

**Detects**:
- Data races
- Deadlocks
- Thread safety violations

### 4. Static Analysis

**clang-tidy**: Modern C++ best practices

```bash
clang-tidy -p build src/**/*.cpp --warnings-as-errors='*'
```

**Checks**:
- CERT C++ secure coding guidelines
- CppCoreGuidelines
- Google C++ style guide
- Modernization suggestions

**cppcheck**: Additional static checks

```bash
cppcheck --enable=all --inconclusive \
  --suppress=missingIncludeSystem \
  -I include src/
```

### 5. Memory Leak Detection (Valgrind)

```bash
valgrind --leak-check=full --show-leak-kinds=all \
  ./build/unit_tests
```

### 6. Code Coverage

```bash
cmake -DCMAKE_CXX_FLAGS="--coverage" -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
ctest
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_html
```

Target: >80% line coverage for critical paths

## Security Best Practices Implemented

### 1. Memory Safety

- ✅ **RAII**: All resources use smart pointers and automatic cleanup
- ✅ **No Raw Pointers**: Prefer `std::unique_ptr`, `std::shared_ptr`
- ✅ **Bounds Checking**: All array accesses validated
- ✅ **Secure Wiping**: Sensitive data zeroed with `SecureWipe()`
- ✅ **Move Semantics**: Keys and secrets moved, not copied

### 2. Cryptography

- ✅ **AES-256-GCM**: Authenticated encryption for confidentiality + integrity
- ✅ **Random IVs**: New IV generated per encryption
- ✅ **Constant-Time Compare**: Prevents timing attacks on tag verification
- ✅ **Key Isolation**: Master key never leaves enclave, never exported
- ✅ **OpenSSL Integration**: Industry-standard cryptographic library

### 3. Input Validation

- ✅ **Size Limits**: All inputs checked against max sizes
- ✅ **String Validation**: Empty/oversized strings rejected
- ✅ **Serialization Safety**: Bounds checked during deserialization
- ✅ **CRC Verification**: Message integrity checked
- ✅ **Magic Numbers**: Protocol version validation

### 4. Error Handling

- ✅ **Explicit Errors**: `Result<T>` type for all fallible operations
- ✅ **No Exceptions**: Explicit error codes, no exception overhead
- ✅ **Error Propagation**: Errors checked at every level
- ✅ **Graceful Degradation**: Failed crypto operations don't crash

### 5. Compiler Hardening

- ✅ **Stack Protector**: `-fstack-protector-strong`
- ✅ **PIE**: Position Independent Executable
- ✅ **FORTIFY_SOURCE**: Buffer overflow detection
- ✅ **NX Bit**: Non-executable stack
- ✅ **RELRO**: Relocation Read-Only

### 6. Code Quality

- ✅ **Static Analysis**: clang-tidy, cppcheck
- ✅ **Dynamic Analysis**: ASan, UBSan, TSan
- ✅ **Fuzzing**: Protocol and crypto fuzzers
- ✅ **CI/CD**: Automated testing on every commit

## Future Security Enhancements

### Recommended Next Steps

1. **Formal Verification**:
   - Model enclave security properties in TLA+ or Coq
   - Prove absence of information leaks
   - Verify cryptographic protocol correctness

2. **Professional Security Audit**:
   - Hire third-party security firm
   - Penetration testing
   - Code review by cryptography experts
   - Side-channel analysis

3. **Hardware TEE Integration**:
   - Port to Intel SGX for real hardware isolation
   - Use ARM TrustZone on embedded devices
   - Leverage AMD SEV for VM isolation

4. **Advanced Protections**:
   - Implement constant-time programming throughout
   - Add side-channel resistant algorithms
   - Deploy against Spectre/Meltdown variants
   - Secure boot and remote attestation

5. **Extended Testing**:
   - 24+ hour fuzzing campaigns
   - Differential testing against reference implementations
   - Concolic execution (e.g., KLEE)
   - Property-based testing (e.g., QuickCheck-style)

6. **Runtime Protections**:
   - Seccomp sandboxing
   - Capability-based security
   - AppArmor/SELinux profiles
   - Resource limits and rate limiting

## Project Structure

```
OpenEnclaven/
├── include/openenclave/      # Public API headers
│   ├── enclave.hpp            # Main enclave interface
│   ├── crypto.hpp             # Cryptographic primitives
│   └── protocol.hpp           # Wire protocol definitions
├── src/
│   ├── core/                  # Core enclave implementation
│   │   ├── enclave.cpp
│   │   └── protocol.cpp
│   ├── crypto/                # Cryptography implementation
│   │   └── crypto.cpp
│   └── server/                # Server daemon
│       └── server.cpp
├── tests/
│   ├── unit/                  # Unit tests (GoogleTest)
│   │   ├── test_crypto.cpp
│   │   ├── test_enclave.cpp
│   │   └── test_protocol.cpp
│   ├── fuzz/                  # Fuzzing harnesses (libFuzzer)
│   │   ├── fuzz_protocol.cpp
│   │   └── fuzz_crypto.cpp
│   └── integration/           # Integration tests
├── examples/                  # Example clients
│   └── client_example.cpp
├── .github/workflows/         # CI/CD configuration
│   └── ci.yml
├── CMakeLists.txt             # Build configuration
├── .clang-tidy                # Static analysis config
└── README.md                  # This file
```

## Contributing

Security contributions are welcome! Please:

1. Run all tests before submitting
2. Add tests for new features
3. Follow the existing code style
4. Run static analysis tools
5. Report security issues privately (see SECURITY.md)

## License

MIT License - See LICENSE file for details

## Disclaimer

⚠️ **IMPORTANT SECURITY NOTICE**

This software is provided "AS IS" without warranty of any kind. The authors make no claims about the security properties of this implementation. **No software provides absolute security guarantees.**

This is a **prototype for research and educational purposes**. It has NOT been:
- Formally verified
- Professionally audited
- Tested in production
- Certified for any compliance standard

DO NOT use this software to protect:
- Financial data
- Personal identifiable information (PII)
- Healthcare records
- Cryptographic keys in production
- Any data where a breach would cause harm

For production use cases requiring strong security guarantees:
1. Conduct a professional security audit
2. Perform formal verification where possible
3. Use hardware-backed TEEs (Intel SGX, ARM TrustZone)
4. Implement comprehensive monitoring and incident response
5. Follow industry best practices and compliance requirements

**The authors assume no liability for security breaches, data loss, or any damages resulting from the use of this software.**

## References

- [Intel SGX Documentation](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html)
- [ARM TrustZone](https://www.arm.com/technologies/trustzone-for-cortex-a)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CppCoreGuidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines)
- [CERT C++ Secure Coding Standard](https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88046682)
- [Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html)

## Contact

For security issues, please contact: [your-security-email]

For general questions: [your-email]
