#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace openenclave {
namespace crypto {

// AES-256-GCM parameters
constexpr size_t AES_KEY_SIZE = 32;  // 256 bits
constexpr size_t AES_IV_SIZE = 12;   // 96 bits for GCM
constexpr size_t AES_TAG_SIZE = 16;  // 128 bits authentication tag

/**
 * @brief Secure key storage (never exported)
 *
 * Uses RAII to ensure keys are wiped from memory on destruction.
 */
class SecureKey {
public:
    /**
     * @brief Generate a new random key
     */
    static std::unique_ptr<SecureKey> Generate();

    /**
     * @brief Destructor - securely wipes key material
     */
    ~SecureKey();

    // Non-copyable
    SecureKey(const SecureKey&) = delete;
    SecureKey& operator=(const SecureKey&) = delete;

    // Movable
    SecureKey(SecureKey&& other) noexcept;
    SecureKey& operator=(SecureKey&& other) noexcept;

    /**
     * @brief Get const pointer to key data (internal use only)
     *
     * WARNING: Never export this data outside the enclave!
     */
    const uint8_t* GetKeyData() const noexcept;

    size_t GetKeySize() const noexcept { return AES_KEY_SIZE; }

private:
    SecureKey();

    // Secure memory storage for key
    std::array<uint8_t, AES_KEY_SIZE> key_data_;
    bool is_valid_;
};

/**
 * @brief Encrypted data container
 *
 * Contains ciphertext, IV, and authentication tag.
 */
struct EncryptedData {
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, AES_IV_SIZE> iv;
    std::array<uint8_t, AES_TAG_SIZE> tag;

    // Serialization helpers
    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(const std::vector<uint8_t>& data, EncryptedData& out);
};

/**
 * @brief High-level crypto operations wrapper
 *
 * Provides constant-time operations where applicable to prevent
 * timing side-channel attacks.
 */
class CryptoModule {
public:
    CryptoModule();
    ~CryptoModule();

    // Non-copyable, non-movable
    CryptoModule(const CryptoModule&) = delete;
    CryptoModule& operator=(const CryptoModule&) = delete;
    CryptoModule(CryptoModule&&) = delete;
    CryptoModule& operator=(CryptoModule&&) = delete;

    /**
     * @brief Initialize crypto subsystem
     *
     * Must be called before any crypto operations.
     */
    bool Initialize();

    /**
     * @brief Generate cryptographically secure random bytes
     *
     * @param buffer Output buffer
     * @param size Number of bytes to generate
     * @return true on success
     */
    bool GenerateRandomBytes(uint8_t* buffer, size_t size);

    /**
     * @brief Encrypt data using AES-256-GCM
     *
     * @param key Encryption key
     * @param plaintext Data to encrypt
     * @param aad Additional authenticated data (optional)
     * @return Encrypted data container or empty on error
     */
    std::unique_ptr<EncryptedData> Encrypt(
        const SecureKey& key,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad = {}
    );

    /**
     * @brief Decrypt data using AES-256-GCM
     *
     * Performs constant-time authentication check to prevent timing attacks.
     *
     * @param key Decryption key
     * @param encrypted Encrypted data container
     * @param aad Additional authenticated data (must match encryption)
     * @param plaintext Output buffer for decrypted data
     * @return true on success and authentication, false otherwise
     */
    bool Decrypt(
        const SecureKey& key,
        const EncryptedData& encrypted,
        const std::vector<uint8_t>& aad,
        std::vector<uint8_t>& plaintext
    );

    /**
     * @brief Compute SHA-256 hash
     *
     * @param data Input data
     * @return 32-byte hash
     */
    std::array<uint8_t, 32> ComputeHash(const std::vector<uint8_t>& data);

    /**
     * @brief Constant-time memory comparison
     *
     * Prevents timing side-channels when comparing secrets.
     *
     * @param a First buffer
     * @param b Second buffer
     * @param size Size to compare
     * @return true if equal
     */
    static bool ConstantTimeCompare(const void* a, const void* b, size_t size) noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Secure memory wiper
 *
 * Ensures memory is zeroed even with compiler optimizations.
 */
void SecureWipe(void* ptr, size_t size) noexcept;

/**
 * @brief RAII wrapper for secure memory allocation
 */
template<typename T>
class SecureBuffer {
public:
    explicit SecureBuffer(size_t size)
        : buffer_(new T[size]), size_(size) {}

    ~SecureBuffer() {
        if (buffer_) {
            SecureWipe(buffer_.get(), size_ * sizeof(T));
        }
    }

    // Non-copyable
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Movable
    SecureBuffer(SecureBuffer&& other) noexcept
        : buffer_(std::move(other.buffer_)), size_(other.size_) {
        other.size_ = 0;
    }

    T* Get() noexcept { return buffer_.get(); }
    const T* Get() const noexcept { return buffer_.get(); }
    size_t Size() const noexcept { return size_; }

private:
    std::unique_ptr<T[]> buffer_;
    size_t size_;
};

} // namespace crypto
} // namespace openenclave
