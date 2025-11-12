#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <optional>

namespace openenclave {

// Forward declarations
class EnclaveImpl;
class CryptoModule;

/**
 * @brief Result type for enclave operations
 *
 * Provides explicit error handling without exceptions
 */
enum class EnclaveStatus {
    OK = 0,
    ERROR_INVALID_PARAMETER,
    ERROR_CONTEXT_NOT_INITIALIZED,
    ERROR_CRYPTO_FAILURE,
    ERROR_MODULE_LOAD_FAILED,
    ERROR_FUNCTION_NOT_FOUND,
    ERROR_EXECUTION_FAILED,
    ERROR_OUT_OF_MEMORY,
    ERROR_SERIALIZATION_FAILED,
    ERROR_AUTHENTICATION_FAILED
};

/**
 * @brief Convert status to human-readable string
 */
const char* StatusToString(EnclaveStatus status) noexcept;

/**
 * @brief Result wrapper with explicit error handling
 */
template<typename T>
class Result {
public:
    static Result<T> Ok(T value) {
        return Result<T>(std::move(value), EnclaveStatus::OK);
    }

    static Result<T> Error(EnclaveStatus status) {
        return Result<T>(status);
    }

    bool IsOk() const noexcept { return status_ == EnclaveStatus::OK; }
    bool IsError() const noexcept { return !IsOk(); }

    EnclaveStatus GetStatus() const noexcept { return status_; }

    T& GetValue() { return value_.value(); }
    const T& GetValue() const { return value_.value(); }

    T ValueOr(T default_value) const {
        return IsOk() ? value_.value() : std::move(default_value);
    }

private:
    explicit Result(T value, EnclaveStatus status)
        : value_(std::move(value)), status_(status) {}

    explicit Result(EnclaveStatus status)
        : value_(std::nullopt), status_(status) {}

    std::optional<T> value_;
    EnclaveStatus status_;
};

/**
 * @brief Specialization for void operations
 */
template<>
class Result<void> {
public:
    static Result<void> Ok() {
        return Result<void>(EnclaveStatus::OK);
    }

    static Result<void> Error(EnclaveStatus status) {
        return Result<void>(status);
    }

    bool IsOk() const noexcept { return status_ == EnclaveStatus::OK; }
    bool IsError() const noexcept { return !IsOk(); }

    EnclaveStatus GetStatus() const noexcept { return status_; }

private:
    explicit Result(EnclaveStatus status) : status_(status) {}

    EnclaveStatus status_;
};

/**
 * @brief Opaque handle to user-loaded module
 */
class ModuleHandle {
public:
    explicit ModuleHandle(uint64_t id) : id_(id) {}
    uint64_t GetId() const noexcept { return id_; }

private:
    uint64_t id_;
};

/**
 * @brief Secure Enclave Context
 *
 * Main interface for the secure enclave. Provides isolation and
 * encrypted memory for sensitive operations.
 *
 * Thread-safety: Not thread-safe. Caller must synchronize access.
 */
class Enclave {
public:
    /**
     * @brief Create a new enclave context
     *
     * Initializes crypto subsystem and allocates secure memory region.
     * Keys are generated internally and never exposed.
     *
     * @return Result containing unique_ptr to Enclave or error status
     */
    static Result<std::unique_ptr<Enclave>> Create();

    /**
     * @brief Destructor - securely wipes all sensitive data
     */
    ~Enclave();

    // Non-copyable, non-movable (secure memory should not be copied)
    Enclave(const Enclave&) = delete;
    Enclave& operator=(const Enclave&) = delete;
    Enclave(Enclave&&) = delete;
    Enclave& operator=(Enclave&&) = delete;

    /**
     * @brief Load a user module into the enclave
     *
     * Module data is validated and loaded into encrypted memory.
     *
     * @param module_data Serialized module bytecode/data
     * @return Result containing ModuleHandle or error status
     */
    Result<ModuleHandle> LoadModule(const std::vector<uint8_t>& module_data);

    /**
     * @brief Invoke a function within a loaded module
     *
     * All parameters and results are encrypted in transit.
     *
     * @param handle Module handle from LoadModule
     * @param function_name Name of function to invoke
     * @param params Serialized parameters (encrypted)
     * @return Result containing encrypted response or error status
     */
    Result<std::vector<uint8_t>> InvokeFunction(
        const ModuleHandle& handle,
        const std::string& function_name,
        const std::vector<uint8_t>& params
    );

    /**
     * @brief Store encrypted data in the enclave
     *
     * Data is encrypted with the enclave's master key.
     *
     * @param key Storage key
     * @param data Plain data to encrypt and store
     * @return Result indicating success or error
     */
    Result<void> StoreData(const std::string& key, const std::vector<uint8_t>& data);

    /**
     * @brief Retrieve and decrypt data from the enclave
     *
     * @param key Storage key
     * @return Result containing decrypted data or error status
     */
    Result<std::vector<uint8_t>> RetrieveData(const std::string& key);

    /**
     * @brief Get enclave attestation data (simulated)
     *
     * In a real TEE, this would provide cryptographic proof of the enclave state.
     * This is a simplified simulation.
     *
     * @return Attestation data
     */
    Result<std::vector<uint8_t>> GetAttestation() const;

private:
    Enclave(); // Private constructor, use Create()

    std::unique_ptr<EnclaveImpl> impl_;
};

} // namespace openenclave
