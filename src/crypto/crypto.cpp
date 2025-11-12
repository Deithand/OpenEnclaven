#include "openenclave/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <cstring>
#include <algorithm>

namespace openenclave {
namespace crypto {

// Secure memory wipe implementation
// Uses volatile to prevent compiler optimization
void SecureWipe(void* ptr, size_t size) noexcept {
    if (!ptr || size == 0) return;

    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }

    // Additional barrier - use OpenSSL's secure clear if available
#ifdef OPENSSL_cleanse
    OPENSSL_cleanse(ptr, size);
#endif
}

// ============================================================================
// SecureKey Implementation
// ============================================================================

SecureKey::SecureKey() : is_valid_(false) {
    SecureWipe(key_data_.data(), key_data_.size());
}

SecureKey::~SecureKey() {
    SecureWipe(key_data_.data(), key_data_.size());
    is_valid_ = false;
}

SecureKey::SecureKey(SecureKey&& other) noexcept
    : key_data_(other.key_data_), is_valid_(other.is_valid_) {
    other.is_valid_ = false;
    SecureWipe(other.key_data_.data(), other.key_data_.size());
}

SecureKey& SecureKey::operator=(SecureKey&& other) noexcept {
    if (this != &other) {
        SecureWipe(key_data_.data(), key_data_.size());
        key_data_ = other.key_data_;
        is_valid_ = other.is_valid_;
        other.is_valid_ = false;
        SecureWipe(other.key_data_.data(), other.key_data_.size());
    }
    return *this;
}

std::unique_ptr<SecureKey> SecureKey::Generate() {
    auto key = std::unique_ptr<SecureKey>(new SecureKey());

    if (RAND_bytes(key->key_data_.data(), AES_KEY_SIZE) != 1) {
        return nullptr;
    }

    key->is_valid_ = true;
    return key;
}

const uint8_t* SecureKey::GetKeyData() const noexcept {
    return is_valid_ ? key_data_.data() : nullptr;
}

// ============================================================================
// EncryptedData Implementation
// ============================================================================

std::vector<uint8_t> EncryptedData::Serialize() const {
    std::vector<uint8_t> result;

    // Format: [IV_SIZE:4][TAG_SIZE:4][CIPHERTEXT_SIZE:4][IV][TAG][CIPHERTEXT]
    const uint32_t iv_size = static_cast<uint32_t>(iv.size());
    const uint32_t tag_size = static_cast<uint32_t>(tag.size());
    const uint32_t ct_size = static_cast<uint32_t>(ciphertext.size());

    result.reserve(12 + iv.size() + tag.size() + ciphertext.size());

    // Write sizes
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&iv_size),
                  reinterpret_cast<const uint8_t*>(&iv_size) + 4);
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&tag_size),
                  reinterpret_cast<const uint8_t*>(&tag_size) + 4);
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&ct_size),
                  reinterpret_cast<const uint8_t*>(&ct_size) + 4);

    // Write data
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), tag.begin(), tag.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());

    return result;
}

bool EncryptedData::Deserialize(const std::vector<uint8_t>& data, EncryptedData& out) {
    if (data.size() < 12) return false;

    // Read sizes
    uint32_t iv_size, tag_size, ct_size;
    std::memcpy(&iv_size, data.data(), 4);
    std::memcpy(&tag_size, data.data() + 4, 4);
    std::memcpy(&ct_size, data.data() + 8, 4);

    // Validate sizes
    if (iv_size != AES_IV_SIZE || tag_size != AES_TAG_SIZE) return false;
    if (data.size() != 12 + iv_size + tag_size + ct_size) return false;

    // Read data
    size_t offset = 12;
    std::copy_n(data.begin() + offset, AES_IV_SIZE, out.iv.begin());
    offset += AES_IV_SIZE;

    std::copy_n(data.begin() + offset, AES_TAG_SIZE, out.tag.begin());
    offset += AES_TAG_SIZE;

    out.ciphertext.assign(data.begin() + offset, data.end());

    return true;
}

// ============================================================================
// CryptoModule Implementation
// ============================================================================

class CryptoModule::Impl {
public:
    Impl() : initialized_(false) {}

    bool Initialize() {
        if (initialized_) return true;

        // OpenSSL initialization (automatic in OpenSSL 1.1.0+)
        initialized_ = true;
        return true;
    }

private:
    bool initialized_;
};

CryptoModule::CryptoModule() : impl_(std::make_unique<Impl>()) {}

CryptoModule::~CryptoModule() = default;

bool CryptoModule::Initialize() {
    return impl_->Initialize();
}

bool CryptoModule::GenerateRandomBytes(uint8_t* buffer, size_t size) {
    if (!buffer || size == 0) return false;
    return RAND_bytes(buffer, static_cast<int>(size)) == 1;
}

std::unique_ptr<EncryptedData> CryptoModule::Encrypt(
    const SecureKey& key,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad
) {
    auto encrypted = std::make_unique<EncryptedData>();

    // Generate random IV
    if (!GenerateRandomBytes(encrypted->iv.data(), AES_IV_SIZE)) {
        return nullptr;
    }

    // Create and initialize context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return nullptr;

    // Cleanup helper
    auto cleanup = [ctx]() { EVP_CIPHER_CTX_free(ctx); };

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                          key.GetKeyData(), encrypted->iv.data()) != 1) {
        cleanup();
        return nullptr;
    }

    // Add AAD if present
    if (!aad.empty()) {
        int len;
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(),
                             static_cast<int>(aad.size())) != 1) {
            cleanup();
            return nullptr;
        }
    }

    // Encrypt plaintext
    encrypted->ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int len = 0;

    if (EVP_EncryptUpdate(ctx, encrypted->ciphertext.data(), &len,
                         plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        cleanup();
        return nullptr;
    }

    int ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, encrypted->ciphertext.data() + len, &len) != 1) {
        cleanup();
        return nullptr;
    }

    ciphertext_len += len;
    encrypted->ciphertext.resize(ciphertext_len);

    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE,
                           encrypted->tag.data()) != 1) {
        cleanup();
        return nullptr;
    }

    cleanup();
    return encrypted;
}

bool CryptoModule::Decrypt(
    const SecureKey& key,
    const EncryptedData& encrypted,
    const std::vector<uint8_t>& aad,
    std::vector<uint8_t>& plaintext
) {
    // Create and initialize context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    // Cleanup helper
    auto cleanup = [ctx]() { EVP_CIPHER_CTX_free(ctx); };

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                          key.GetKeyData(), encrypted.iv.data()) != 1) {
        cleanup();
        return false;
    }

    // Add AAD if present
    if (!aad.empty()) {
        int len;
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(),
                             static_cast<int>(aad.size())) != 1) {
            cleanup();
            return false;
        }
    }

    // Decrypt ciphertext
    plaintext.resize(encrypted.ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    int len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                         encrypted.ciphertext.data(),
                         static_cast<int>(encrypted.ciphertext.size())) != 1) {
        cleanup();
        return false;
    }

    int plaintext_len = len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE,
                           const_cast<uint8_t*>(encrypted.tag.data())) != 1) {
        cleanup();
        return false;
    }

    // Finalize decryption (this verifies the tag in constant time)
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);

    cleanup();

    if (ret > 0) {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return true;
    }

    // Authentication failed - wipe plaintext
    SecureWipe(plaintext.data(), plaintext.size());
    plaintext.clear();
    return false;
}

std::array<uint8_t, 32> CryptoModule::ComputeHash(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 32> hash;
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

bool CryptoModule::ConstantTimeCompare(const void* a, const void* b, size_t size) noexcept {
    if (!a || !b) return false;

    const volatile uint8_t* va = static_cast<const volatile uint8_t*>(a);
    const volatile uint8_t* vb = static_cast<const volatile uint8_t*>(b);

    volatile uint8_t result = 0;
    for (size_t i = 0; i < size; ++i) {
        result |= va[i] ^ vb[i];
    }

    return result == 0;
}

} // namespace crypto
} // namespace openenclave
