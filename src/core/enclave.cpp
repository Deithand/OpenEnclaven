#include "openenclave/enclave.hpp"
#include "openenclave/crypto.hpp"
#include <map>
#include <mutex>
#include <atomic>
#include <cstring>

namespace openenclave {

// ============================================================================
// Status to String Conversion
// ============================================================================

const char* StatusToString(EnclaveStatus status) noexcept {
    switch (status) {
        case EnclaveStatus::OK:
            return "OK";
        case EnclaveStatus::ERROR_INVALID_PARAMETER:
            return "Invalid parameter";
        case EnclaveStatus::ERROR_CONTEXT_NOT_INITIALIZED:
            return "Context not initialized";
        case EnclaveStatus::ERROR_CRYPTO_FAILURE:
            return "Cryptographic operation failed";
        case EnclaveStatus::ERROR_MODULE_LOAD_FAILED:
            return "Module load failed";
        case EnclaveStatus::ERROR_FUNCTION_NOT_FOUND:
            return "Function not found";
        case EnclaveStatus::ERROR_EXECUTION_FAILED:
            return "Execution failed";
        case EnclaveStatus::ERROR_OUT_OF_MEMORY:
            return "Out of memory";
        case EnclaveStatus::ERROR_SERIALIZATION_FAILED:
            return "Serialization failed";
        case EnclaveStatus::ERROR_AUTHENTICATION_FAILED:
            return "Authentication failed";
        default:
            return "Unknown error";
    }
}

// ============================================================================
// Module Storage (simplified for prototype)
// ============================================================================

struct LoadedModule {
    uint64_t id;
    std::vector<uint8_t> encrypted_code;
    std::map<std::string, uint32_t> function_table; // function_name -> offset

    LoadedModule(uint64_t module_id) : id(module_id) {}
};

// ============================================================================
// EnclaveImpl - Internal Implementation
// ============================================================================

class EnclaveImpl {
public:
    EnclaveImpl()
        : crypto_module_(std::make_unique<crypto::CryptoModule>())
        , next_module_id_(1)
        , initialized_(false) {}

    ~EnclaveImpl() {
        // Secure wipe of all sensitive data
        for (auto& [key, data] : secure_storage_) {
            crypto::SecureWipe(data.data(), data.size());
        }
        secure_storage_.clear();
        modules_.clear();
    }

    bool Initialize() {
        if (initialized_) return true;

        // Initialize crypto subsystem
        if (!crypto_module_->Initialize()) {
            return false;
        }

        // Generate master encryption key
        master_key_ = crypto::SecureKey::Generate();
        if (!master_key_) {
            return false;
        }

        initialized_ = true;
        return true;
    }

    Result<uint64_t> LoadModule(const std::vector<uint8_t>& module_data) {
        if (!initialized_) {
            return Result<uint64_t>::Error(EnclaveStatus::ERROR_CONTEXT_NOT_INITIALIZED);
        }

        if (module_data.empty() || module_data.size() > 10 * 1024 * 1024) {
            return Result<uint64_t>::Error(EnclaveStatus::ERROR_INVALID_PARAMETER);
        }

        std::lock_guard<std::mutex> lock(mutex_);

        // Encrypt module data
        auto encrypted = crypto_module_->Encrypt(*master_key_, module_data);
        if (!encrypted) {
            return Result<uint64_t>::Error(EnclaveStatus::ERROR_CRYPTO_FAILURE);
        }

        // Create module entry
        uint64_t module_id = next_module_id_++;
        auto module = std::make_unique<LoadedModule>(module_id);
        module->encrypted_code = encrypted->Serialize();

        // Simplified: Parse module and build function table
        // In a real implementation, this would parse bytecode/ELF/etc.
        // For this prototype, we just store a dummy function entry
        module->function_table["test_function"] = 0;

        modules_[module_id] = std::move(module);

        return Result<uint64_t>::Ok(module_id);
    }

    Result<std::vector<uint8_t>> InvokeFunction(
        uint64_t module_handle,
        const std::string& function_name,
        const std::vector<uint8_t>& params
    ) {
        if (!initialized_) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_CONTEXT_NOT_INITIALIZED);
        }

        if (function_name.empty() || function_name.size() > 256) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_INVALID_PARAMETER);
        }

        std::lock_guard<std::mutex> lock(mutex_);

        // Find module
        auto it = modules_.find(module_handle);
        if (it == modules_.end()) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_MODULE_LOAD_FAILED);
        }

        auto& module = it->second;

        // Find function
        auto func_it = module->function_table.find(function_name);
        if (func_it == module->function_table.end()) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_FUNCTION_NOT_FOUND);
        }

        // Decrypt module code
        crypto::EncryptedData encrypted;
        if (!crypto::EncryptedData::Deserialize(module->encrypted_code, encrypted)) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_CRYPTO_FAILURE);
        }

        std::vector<uint8_t> module_code;
        if (!crypto_module_->Decrypt(*master_key_, encrypted, {}, module_code)) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_CRYPTO_FAILURE);
        }

        // Execute function (simplified - just echo params back for prototype)
        // In a real implementation, this would execute bytecode/native code
        std::vector<uint8_t> result = params;

        // Add a marker to show it was processed
        result.push_back(0x42); // 'B' for "processed by enclave"

        // Securely wipe decrypted code
        crypto::SecureWipe(module_code.data(), module_code.size());

        return Result<std::vector<uint8_t>>::Ok(std::move(result));
    }

    Result<void> StoreData(const std::string& key, const std::vector<uint8_t>& data) {
        if (!initialized_) {
            return Result<void>::Error(EnclaveStatus::ERROR_CONTEXT_NOT_INITIALIZED);
        }

        if (key.empty() || key.size() > 256) {
            return Result<void>::Error(EnclaveStatus::ERROR_INVALID_PARAMETER);
        }

        if (data.empty() || data.size() > 10 * 1024 * 1024) {
            return Result<void>::Error(EnclaveStatus::ERROR_INVALID_PARAMETER);
        }

        std::lock_guard<std::mutex> lock(mutex_);

        // Encrypt data
        auto encrypted = crypto_module_->Encrypt(*master_key_, data);
        if (!encrypted) {
            return Result<void>::Error(EnclaveStatus::ERROR_CRYPTO_FAILURE);
        }

        // Store encrypted data
        secure_storage_[key] = encrypted->Serialize();

        return Result<void>::Ok();
    }

    Result<std::vector<uint8_t>> RetrieveData(const std::string& key) {
        if (!initialized_) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_CONTEXT_NOT_INITIALIZED);
        }

        if (key.empty() || key.size() > 256) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_INVALID_PARAMETER);
        }

        std::lock_guard<std::mutex> lock(mutex_);

        // Find encrypted data
        auto it = secure_storage_.find(key);
        if (it == secure_storage_.end()) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_FUNCTION_NOT_FOUND); // Reuse error code
        }

        // Deserialize encrypted data
        crypto::EncryptedData encrypted;
        if (!crypto::EncryptedData::Deserialize(it->second, encrypted)) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_CRYPTO_FAILURE);
        }

        // Decrypt data
        std::vector<uint8_t> plaintext;
        if (!crypto_module_->Decrypt(*master_key_, encrypted, {}, plaintext)) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_CRYPTO_FAILURE);
        }

        return Result<std::vector<uint8_t>>::Ok(std::move(plaintext));
    }

    Result<std::vector<uint8_t>> GetAttestation() const {
        if (!initialized_) {
            return Result<std::vector<uint8_t>>::Error(
                EnclaveStatus::ERROR_CONTEXT_NOT_INITIALIZED);
        }

        // Simplified attestation - in a real TEE, this would provide
        // cryptographic proof of the enclave's identity and state
        std::vector<uint8_t> attestation;

        // Format: [VERSION:4][TIMESTAMP:8][HASH:32]
        uint32_t version = 1;
        attestation.insert(attestation.end(),
                          reinterpret_cast<const uint8_t*>(&version),
                          reinterpret_cast<const uint8_t*>(&version) + 4);

        // Simulated timestamp
        uint64_t timestamp = 0x0123456789ABCDEF;
        attestation.insert(attestation.end(),
                          reinterpret_cast<const uint8_t*>(&timestamp),
                          reinterpret_cast<const uint8_t*>(&timestamp) + 8);

        // Simulated measurement hash
        std::vector<uint8_t> measurement_data = {0x01, 0x02, 0x03, 0x04};
        auto hash = crypto_module_->ComputeHash(measurement_data);
        attestation.insert(attestation.end(), hash.begin(), hash.end());

        return Result<std::vector<uint8_t>>::Ok(std::move(attestation));
    }

private:
    std::unique_ptr<crypto::CryptoModule> crypto_module_;
    std::unique_ptr<crypto::SecureKey> master_key_;

    std::map<uint64_t, std::unique_ptr<LoadedModule>> modules_;
    std::map<std::string, std::vector<uint8_t>> secure_storage_;

    std::atomic<uint64_t> next_module_id_;
    std::mutex mutex_;
    bool initialized_;
};

// ============================================================================
// Enclave Public API Implementation
// ============================================================================

Enclave::Enclave() : impl_(std::make_unique<EnclaveImpl>()) {}

Enclave::~Enclave() = default;

Result<std::unique_ptr<Enclave>> Enclave::Create() {
    auto enclave = std::unique_ptr<Enclave>(new Enclave());

    if (!enclave->impl_->Initialize()) {
        return Result<std::unique_ptr<Enclave>>::Error(
            EnclaveStatus::ERROR_CONTEXT_NOT_INITIALIZED);
    }

    return Result<std::unique_ptr<Enclave>>::Ok(std::move(enclave));
}

Result<ModuleHandle> Enclave::LoadModule(const std::vector<uint8_t>& module_data) {
    auto result = impl_->LoadModule(module_data);

    if (result.IsError()) {
        return Result<ModuleHandle>::Error(result.GetStatus());
    }

    return Result<ModuleHandle>::Ok(ModuleHandle(result.GetValue()));
}

Result<std::vector<uint8_t>> Enclave::InvokeFunction(
    const ModuleHandle& handle,
    const std::string& function_name,
    const std::vector<uint8_t>& params
) {
    return impl_->InvokeFunction(handle.GetId(), function_name, params);
}

Result<void> Enclave::StoreData(const std::string& key, const std::vector<uint8_t>& data) {
    return impl_->StoreData(key, data);
}

Result<std::vector<uint8_t>> Enclave::RetrieveData(const std::string& key) {
    return impl_->RetrieveData(key);
}

Result<std::vector<uint8_t>> Enclave::GetAttestation() const {
    return impl_->GetAttestation();
}

} // namespace openenclave
