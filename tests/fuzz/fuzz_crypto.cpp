#include "openenclave/crypto.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>

using namespace openenclave::crypto;

// Global crypto module (initialized once)
static std::unique_ptr<CryptoModule> g_crypto_module;

// Initialize on first use
static CryptoModule* GetCryptoModule() {
    if (!g_crypto_module) {
        g_crypto_module = std::make_unique<CryptoModule>();
        g_crypto_module->Initialize();
    }
    return g_crypto_module.get();
}

// LibFuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    auto crypto = GetCryptoModule();

    // Skip too small inputs
    if (size < 12) {
        return 0;
    }

    // Create input vector
    std::vector<uint8_t> input(data, data + size);

    // Test 1: Hash computation (should never crash)
    {
        crypto->ComputeHash(input);
    }

    // Test 2: EncryptedData deserialization
    {
        EncryptedData encrypted;
        EncryptedData::Deserialize(input, encrypted);
    }

    // Test 3: Encrypt/Decrypt with random data
    {
        auto key = SecureKey::Generate();
        if (key) {
            // Limit plaintext size to avoid timeout
            size_t plaintext_size = std::min(size, size_t(1024));
            std::vector<uint8_t> plaintext(data, data + plaintext_size);

            auto encrypted = crypto->Encrypt(*key, plaintext);
            if (encrypted) {
                std::vector<uint8_t> decrypted;
                crypto->Decrypt(*key, *encrypted, {}, decrypted);
            }
        }
    }

    // Test 4: Decrypt with fuzzed encrypted data
    if (size >= 12 + AES_IV_SIZE + AES_TAG_SIZE) {
        auto key = SecureKey::Generate();
        if (key) {
            EncryptedData encrypted;

            // Try to parse fuzzed input as encrypted data
            if (EncryptedData::Deserialize(input, encrypted)) {
                std::vector<uint8_t> decrypted;
                // This should handle malformed data gracefully
                crypto->Decrypt(*key, encrypted, {}, decrypted);
            }
        }
    }

    // Test 5: Constant-time compare
    if (size >= 32) {
        CryptoModule::ConstantTimeCompare(data, data + 16, 16);
    }

    // Test 6: SecureWipe (should never crash)
    {
        std::vector<uint8_t> buffer = input;
        SecureWipe(buffer.data(), buffer.size());
    }

    // Test 7: Encrypt with AAD
    if (size >= 16) {
        auto key = SecureKey::Generate();
        if (key) {
            size_t split = size / 2;
            std::vector<uint8_t> plaintext(data, data + split);
            std::vector<uint8_t> aad(data + split, data + size);

            // Limit sizes
            if (plaintext.size() > 1024) plaintext.resize(1024);
            if (aad.size() > 256) aad.resize(256);

            auto encrypted = crypto->Encrypt(*key, plaintext, aad);
            if (encrypted) {
                std::vector<uint8_t> decrypted;
                crypto->Decrypt(*key, *encrypted, aad, decrypted);

                // Try decrypting with wrong AAD (should fail gracefully)
                std::vector<uint8_t> wrong_aad = aad;
                if (!wrong_aad.empty()) {
                    wrong_aad[0] ^= 0xFF;
                }
                std::vector<uint8_t> decrypted_fail;
                crypto->Decrypt(*key, *encrypted, wrong_aad, decrypted_fail);
            }
        }
    }

    // Test 8: EncryptedData round-trip with fuzzed data
    {
        EncryptedData encrypted;
        if (size >= AES_IV_SIZE + AES_TAG_SIZE) {
            // Try to construct EncryptedData from fuzzed input
            std::copy_n(data, std::min(size, size_t(AES_IV_SIZE)), encrypted.iv.begin());

            size_t offset = AES_IV_SIZE;
            if (size > offset + AES_TAG_SIZE) {
                std::copy_n(data + offset, AES_TAG_SIZE, encrypted.tag.begin());
                offset += AES_TAG_SIZE;

                if (size > offset) {
                    size_t ct_size = std::min(size - offset, size_t(1024));
                    encrypted.ciphertext.assign(data + offset, data + offset + ct_size);
                }
            }

            // Serialize and deserialize
            auto serialized = encrypted.Serialize();
            EncryptedData deserialized;
            EncryptedData::Deserialize(serialized, deserialized);
        }
    }

    return 0;
}
