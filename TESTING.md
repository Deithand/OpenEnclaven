# Testing Strategy & Plan

This document outlines the comprehensive testing strategy for OpenEnclaven.

## Testing Pyramid

```
        ┌──────────────┐
        │   Manual     │  <- Security audits, penetration testing
        │  Security    │
        │   Testing    │
        ├──────────────┤
        │ Integration  │  <- End-to-end workflows
        │    Tests     │
        ├──────────────┤
        │  Unit Tests  │  <- Component testing
        │  (GoogleTest)│
        ├──────────────┤
        │   Fuzzing    │  <- Input mutation testing
        │ (libFuzzer)  │
        ├──────────────┤
        │  Sanitizers  │  <- Memory/UB detection
        │ (ASan/UBSan) │
        ├──────────────┤
        │   Static     │  <- Code analysis
        │  Analysis    │
        └──────────────┘
```

## 1. Unit Testing

**Tool**: GoogleTest (gtest/gmock)

**Coverage Target**: >80% line coverage for critical paths

### Test Suites

#### Cryptography Tests (`test_crypto.cpp`)

- ✅ Key generation and management
- ✅ Encryption/decryption round-trips
- ✅ Authentication tag verification
- ✅ AAD (Additional Authenticated Data) handling
- ✅ Tamper detection (ciphertext/tag modification)
- ✅ Hash computation
- ✅ Constant-time comparison
- ✅ Secure memory wiping
- ✅ Large data encryption (stress testing)
- ✅ Empty data edge cases

#### Enclave Tests (`test_enclave.cpp`)

- ✅ Enclave creation and initialization
- ✅ Module loading (valid/invalid cases)
- ✅ Function invocation
- ✅ Secure storage (store/retrieve)
- ✅ Handle management
- ✅ Error handling (invalid parameters)
- ✅ Size limit enforcement
- ✅ Attestation generation
- ✅ Multiple enclave instances

#### Protocol Tests (`test_protocol.cpp`)

- ✅ CRC32 checksum calculation
- ✅ Message header serialization/deserialization
- ✅ Request/response handling
- ✅ All request types (LoadModule, InvokeFunction, etc.)
- ✅ Message validation
- ✅ Size limit checks
- ✅ Malformed input handling

### Running Unit Tests

```bash
cd build
ctest --verbose
# or
./unit_tests --gtest_filter='*' --gtest_color=yes
```

## 2. Fuzzing

**Tool**: libFuzzer (LLVM)

**Duration**: Minimum 1 hour per fuzzer, recommended 24+ hours

### Fuzzing Targets

#### Protocol Fuzzer (`fuzz_protocol.cpp`)

**Purpose**: Find crashes in protocol parsing

**Targets**:
- Message header deserialization
- Request/response parsing
- All request type deserialization
- CRC validation
- Size overflow detection

**Command**:
```bash
./tests/fuzz_protocol \
  -max_total_time=3600 \
  -timeout=10 \
  -max_len=1048576 \
  -rss_limit_mb=2048
```

#### Crypto Fuzzer (`fuzz_crypto.cpp`)

**Purpose**: Find crashes in cryptographic operations

**Targets**:
- Encryption/decryption with random inputs
- EncryptedData deserialization
- Hash computation
- Malformed ciphertext handling
- AAD manipulation
- Constant-time operations

**Command**:
```bash
./tests/fuzz_crypto \
  -max_total_time=3600 \
  -timeout=10 \
  -max_len=1048576 \
  -rss_limit_mb=2048
```

### Fuzzing Best Practices

1. **Corpus Collection**: Save interesting inputs
   ```bash
   mkdir corpus
   ./fuzz_protocol corpus/ -max_total_time=3600
   ```

2. **Continuous Fuzzing**: Run overnight/weekend
   ```bash
   ./fuzz_protocol -max_total_time=86400  # 24 hours
   ```

3. **Parallel Fuzzing**:
   ```bash
   ./fuzz_protocol -jobs=8 -workers=8
   ```

4. **Crash Analysis**:
   ```bash
   # Reproduce crash
   ./fuzz_protocol crash-file
   ```

## 3. Memory Safety Testing

### AddressSanitizer (ASan)

**Purpose**: Detect memory errors

**Detects**:
- Heap buffer overflow
- Stack buffer overflow
- Use-after-free
- Use-after-return
- Memory leaks
- Double free

**Build & Run**:
```bash
cmake -DENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
ASAN_OPTIONS=check_initialization_order=1:strict_init_order=1 \
  ctest --output-on-failure
```

**Environment Variables**:
```bash
ASAN_OPTIONS=\
detect_leaks=1:\
check_initialization_order=1:\
strict_init_order=1:\
detect_stack_use_after_return=1:\
detect_invalid_pointer_pairs=2:\
halt_on_error=0
```

### UndefinedBehaviorSanitizer (UBSan)

**Purpose**: Detect undefined behavior

**Detects**:
- Integer overflow/underflow
- Division by zero
- Null pointer dereference
- Misaligned memory access
- Invalid casts
- Invalid shifts

**Build & Run**:
```bash
cmake -DENABLE_UBSAN=ON -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
ctest --output-on-failure
```

**Environment Variables**:
```bash
UBSAN_OPTIONS=\
print_stacktrace=1:\
halt_on_error=0
```

### ThreadSanitizer (TSan)

**Purpose**: Detect race conditions

**Detects**:
- Data races
- Deadlocks
- Thread leaks
- Signal-unsafe calls

**Build & Run**:
```bash
cmake -DENABLE_TSAN=ON -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
TSAN_OPTIONS=second_deadlock_stack=1 ctest --output-on-failure
```

**Note**: TSan cannot be combined with ASan.

### MemorySanitizer (MSan)

**Purpose**: Detect uninitialized memory reads

**Requires**: Clang, instrumented libc++

**Build & Run**:
```bash
cmake -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_CXX_FLAGS="-fsanitize=memory -fno-omit-frame-pointer" ..
cmake --build .
ctest --output-on-failure
```

## 4. Static Analysis

### clang-tidy

**Purpose**: Enforce C++ best practices and detect bugs

**Configuration**: `.clang-tidy`

**Checks**:
- CERT C++ secure coding guidelines
- CppCoreGuidelines
- Google C++ style guide
- Modernization suggestions
- Performance issues
- Readability improvements

**Run**:
```bash
# On all source files
find src -name "*.cpp" | xargs clang-tidy -p build

# With auto-fix (use carefully)
clang-tidy -fix -p build src/core/enclave.cpp
```

### cppcheck

**Purpose**: Additional static analysis

**Run**:
```bash
cppcheck --enable=all \
  --inconclusive \
  --suppress=missingIncludeSystem \
  --inline-suppr \
  --error-exitcode=1 \
  -I include \
  src/
```

**Checks**:
- Memory leaks
- Null pointer dereference
- Buffer overflows
- Uninitialized variables
- Unused code

### Compiler Warnings

**Flags Enabled**:
```
-Wall -Wextra -Wpedantic -Werror
-Wshadow -Wconversion -Wsign-conversion
-Wnull-dereference -Wold-style-cast
-Wcast-align -Wunused -Woverloaded-virtual
-Wformat=2
```

## 5. Dynamic Analysis

### Valgrind (Memcheck)

**Purpose**: Memory leak detection

**Run**:
```bash
valgrind --leak-check=full \
  --show-leak-kinds=all \
  --track-origins=yes \
  --verbose \
  ./build/unit_tests
```

**Interpret Results**:
- "definitely lost": Real leaks (must fix)
- "indirectly lost": Cascading from real leaks
- "possibly lost": Investigate
- "still reachable": Program-lifetime allocations (acceptable)

### Valgrind (Helgrind)

**Purpose**: Thread error detection (alternative to TSan)

**Run**:
```bash
valgrind --tool=helgrind ./build/unit_tests
```

## 6. Code Coverage

**Tool**: LCOV (GCC) or llvm-cov (Clang)

### GCC Coverage

```bash
cmake -DCMAKE_CXX_FLAGS="--coverage" \
  -DCMAKE_C_FLAGS="--coverage" \
  -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
ctest

# Generate report
lcov --directory . --capture --output-file coverage.info
lcov --remove coverage.info '/usr/*' '*/tests/*' --output-file coverage.info
lcov --list coverage.info

# HTML report
genhtml coverage.info --output-directory coverage_html
```

### Clang Coverage

```bash
cmake -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping" ..
cmake --build .

LLVM_PROFILE_FILE="coverage-%p.profraw" ctest

llvm-profdata merge -sparse coverage-*.profraw -o coverage.profdata
llvm-cov show ./unit_tests -instr-profile=coverage.profdata
```

## 7. Integration Testing

**Status**: TODO

**Planned Tests**:
1. Client-server communication
2. Multiple concurrent clients
3. Long-running stability tests
4. Error recovery scenarios
5. Resource exhaustion handling

## 8. Performance Testing

**Status**: TODO

**Planned Benchmarks**:
1. Encryption/decryption throughput
2. Module loading latency
3. Function invocation overhead
4. Storage operations (IOPS)
5. Memory footprint

**Tools**: Google Benchmark, perf, flamegraphs

## 9. Security Auditing

### Automated Tools

- [x] Static analysis (clang-tidy, cppcheck)
- [x] Dynamic analysis (ASan, UBSan, TSan)
- [x] Fuzzing (libFuzzer)
- [ ] Symbolic execution (KLEE, angr)
- [ ] Formal verification (TLA+, Coq)

### Manual Review Checklist

- [ ] Cryptographic primitives audit
- [ ] Input validation review
- [ ] Memory safety audit
- [ ] Error handling completeness
- [ ] Side-channel analysis
- [ ] Protocol security review
- [ ] Threat model validation

### Professional Audit Recommendations

For production use, consider:

1. **Penetration Testing**: Hire security firm
2. **Code Review**: External C++ security experts
3. **Cryptography Review**: Cryptographer audit
4. **Side-Channel Analysis**: Timing attack testing
5. **Formal Verification**: Prove security properties

## 10. Continuous Integration

**Platform**: GitHub Actions

**Workflow**: `.github/workflows/ci.yml`

### CI Pipeline

```
┌─────────────────┐
│  Code Push      │
└────────┬────────┘
         │
    ┌────▼────┐
    │ Checkout│
    └────┬────┘
         │
    ┌────▼────────────────────────┐
    │ Matrix Build                │
    │ - Ubuntu GCC                │
    │ - Ubuntu Clang              │
    └────┬────────────────────────┘
         │
    ┌────▼────────────────────────┐
    │ Run Unit Tests              │
    └────┬────────────────────────┘
         │
    ┌────▼────────────────────────┐
    │ Sanitizer Builds            │
    │ - ASan                      │
    │ - UBSan                     │
    └────┬────────────────────────┘
         │
    ┌────▼────────────────────────┐
    │ Static Analysis             │
    │ - clang-tidy                │
    │ - cppcheck                  │
    └────┬────────────────────────┘
         │
    ┌────▼────────────────────────┐
    │ Fuzzing (short run)         │
    │ - 60 seconds per fuzzer     │
    └────┬────────────────────────┘
         │
    ┌────▼────────────────────────┐
    │ Code Coverage               │
    │ - Generate report           │
    │ - Upload artifact           │
    └─────────────────────────────┘
```

## Testing Schedule

### Per Commit

- ✅ Unit tests
- ✅ Basic sanitizers (ASan)
- ✅ clang-tidy
- ✅ Short fuzzing (1 minute)

### Nightly

- ✅ All sanitizers (ASan, UBSan, TSan)
- ✅ Extended fuzzing (1 hour)
- ✅ Code coverage analysis
- ✅ cppcheck full scan

### Weekly

- [ ] Long fuzzing runs (24 hours)
- [ ] Valgrind full analysis
- [ ] Performance benchmarks
- [ ] Integration tests

### Before Release

- [ ] Full test suite on all platforms
- [ ] Extended fuzzing (72+ hours)
- [ ] Manual security review
- [ ] Documentation review
- [ ] Performance regression testing

## Reporting Issues

If tests fail:

1. **Capture Output**: Save full test logs
2. **Reproduce Locally**: Verify not a flake
3. **Minimal Reproducer**: Reduce to smallest case
4. **Report**: GitHub issue with details

For security issues: See SECURITY.md

## Best Practices

1. ✅ Run tests before committing
2. ✅ Fix warnings immediately
3. ✅ Add tests for new features
4. ✅ Add tests for bug fixes
5. ✅ Keep tests fast (<1s per unit test)
6. ✅ Use sanitizers in development
7. ✅ Run fuzzing regularly
8. ✅ Review coverage reports
9. ✅ Update tests when changing behavior
10. ✅ Document test rationale

---

**Remember**: Testing finds bugs, but cannot prove absence of bugs. Formal verification and professional audits are recommended for production use.
