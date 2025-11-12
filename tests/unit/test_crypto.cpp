#include "openenclave/crypto.hpp"
#include <gtest/gtest.h>
#include <vector>
#include <array>

using namespace openenclave::crypto;

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
        crypto_module_ = std::make_unique<CryptoModule>();
        ASSERT_TRUE(crypto_module_->Initialize());
    }

    std::unique_ptr<CryptoModule> crypto_module_;
};

TEST_F(CryptoTest, SecureKeyGeneration) {
    auto key = SecureKey::Generate();
    ASSERT_NE(key, nullptr);
    EXPECT_NE(key->GetKeyData(), nullptr);
    EXPECT_EQ(key->GetKeySize(), AES_KEY_SIZE);
}

TEST_F(CryptoTest, SecureKeyMove) {
    auto key1 = SecureKey::Generate();
    ASSERT_NE(key1, nullptr);

    auto key2 = std::move(key1);
    EXPECT_NE(key2->GetKeyData(), nullptr);
}

TEST_F(CryptoTest, RandomBytesGeneration) {
    std::array<uint8_t, 32> buffer1{};
    std::array<uint8_t, 32> buffer2{};

    ASSERT_TRUE(crypto_module_->GenerateRandomBytes(buffer1.data(), buffer1.size()));
    ASSERT_TRUE(crypto_module_->GenerateRandomBytes(buffer2.data(), buffer2.size()));

    // Random bytes should be different
    EXPECT_NE(buffer1, buffer2);
}

TEST_F(CryptoTest, EncryptDecrypt) {
    auto key = SecureKey::Generate();
    ASSERT_NE(key, nullptr);

    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};

    // Encrypt
    auto encrypted = crypto_module_->Encrypt(*key, plaintext);
    ASSERT_NE(encrypted, nullptr);
    EXPECT_GT(encrypted->ciphertext.size(), 0);

    // Decrypt
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(crypto_module_->Decrypt(*key, *encrypted, {}, decrypted));

    // Verify
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(CryptoTest, EncryptDecryptWithAAD) {
    auto key = SecureKey::Generate();
    ASSERT_NE(key, nullptr);

    std::vector<uint8_t> plaintext = {'s', 'e', 'c', 'r', 'e', 't'};
    std::vector<uint8_t> aad = {'m', 'e', 't', 'a', 'd', 'a', 't', 'a'};

    // Encrypt with AAD
    auto encrypted = crypto_module_->Encrypt(*key, plaintext, aad);
    ASSERT_NE(encrypted, nullptr);

    // Decrypt with correct AAD
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(crypto_module_->Decrypt(*key, *encrypted, aad, decrypted));
    EXPECT_EQ(plaintext, decrypted);

    // Decrypt with wrong AAD should fail
    std::vector<uint8_t> wrong_aad = {'w', 'r', 'o', 'n', 'g'};
    std::vector<uint8_t> decrypted_fail;
    EXPECT_FALSE(crypto_module_->Decrypt(*key, *encrypted, wrong_aad, decrypted_fail));
}

TEST_F(CryptoTest, DecryptionFailsWithTamperedCiphertext) {
    auto key = SecureKey::Generate();
    ASSERT_NE(key, nullptr);

    std::vector<uint8_t> plaintext = {'d', 'a', 't', 'a'};

    auto encrypted = crypto_module_->Encrypt(*key, plaintext);
    ASSERT_NE(encrypted, nullptr);

    // Tamper with ciphertext
    if (!encrypted->ciphertext.empty()) {
        encrypted->ciphertext[0] ^= 0xFF;
    }

    // Decryption should fail
    std::vector<uint8_t> decrypted;
    EXPECT_FALSE(crypto_module_->Decrypt(*key, *encrypted, {}, decrypted));
}

TEST_F(CryptoTest, DecryptionFailsWithTamperedTag) {
    auto key = SecureKey::Generate();
    ASSERT_NE(key, nullptr);

    std::vector<uint8_t> plaintext = {'d', 'a', 't', 'a'};

    auto encrypted = crypto_module_->Encrypt(*key, plaintext);
    ASSERT_NE(encrypted, nullptr);

    // Tamper with tag
    encrypted->tag[0] ^= 0xFF;

    // Decryption should fail
    std::vector<uint8_t> decrypted;
    EXPECT_FALSE(crypto_module_->Decrypt(*key, *encrypted, {}, decrypted));
}

TEST_F(CryptoTest, EncryptedDataSerialization) {
    auto key = SecureKey::Generate();
    ASSERT_NE(key, nullptr);

    std::vector<uint8_t> plaintext = {'t', 'e', 's', 't'};

    auto encrypted = crypto_module_->Encrypt(*key, plaintext);
    ASSERT_NE(encrypted, nullptr);

    // Serialize
    auto serialized = encrypted->Serialize();
    EXPECT_GT(serialized.size(), 0);

    // Deserialize
    EncryptedData deserialized;
    ASSERT_TRUE(EncryptedData::Deserialize(serialized, deserialized));

    // Verify deserialized data can be decrypted
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(crypto_module_->Decrypt(*key, deserialized, {}, decrypted));
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(CryptoTest, ComputeHash) {
    std::vector<uint8_t> data = {'t', 'e', 's', 't'};

    auto hash1 = crypto_module_->ComputeHash(data);
    auto hash2 = crypto_module_->ComputeHash(data);

    // Same input should produce same hash
    EXPECT_EQ(hash1, hash2);

    // Different input should produce different hash
    std::vector<uint8_t> different_data = {'t', 'e', 's', 't', '2'};
    auto hash3 = crypto_module_->ComputeHash(different_data);
    EXPECT_NE(hash1, hash3);
}

TEST_F(CryptoTest, ConstantTimeCompare) {
    std::array<uint8_t, 16> data1;
    std::array<uint8_t, 16> data2;
    std::array<uint8_t, 16> data3;

    crypto_module_->GenerateRandomBytes(data1.data(), data1.size());
    data2 = data1;
    crypto_module_->GenerateRandomBytes(data3.data(), data3.size());

    // Same data should compare equal
    EXPECT_TRUE(CryptoModule::ConstantTimeCompare(data1.data(), data2.data(), data1.size()));

    // Different data should not compare equal
    EXPECT_FALSE(CryptoModule::ConstantTimeCompare(data1.data(), data3.data(), data1.size()));
}

TEST_F(CryptoTest, SecureWipe) {
    std::array<uint8_t, 32> buffer;
    buffer.fill(0xFF);

    SecureWipe(buffer.data(), buffer.size());

    // Verify all bytes are zero
    for (auto byte : buffer) {
        EXPECT_EQ(byte, 0);
    }
}

TEST_F(CryptoTest, SecureBuffer) {
    {
        SecureBuffer<uint8_t> buffer(32);
        EXPECT_NE(buffer.Get(), nullptr);
        EXPECT_EQ(buffer.Size(), 32);

        // Fill with data
        std::fill_n(buffer.Get(), 32, 0xAA);
    }
    // Buffer should be wiped on destruction
}

TEST_F(CryptoTest, LargeDataEncryption) {
    auto key = SecureKey::Generate();
    ASSERT_NE(key, nullptr);

    // Create large plaintext (1 MB)
    std::vector<uint8_t> plaintext(1024 * 1024);
    crypto_module_->GenerateRandomBytes(plaintext.data(), plaintext.size());

    // Encrypt
    auto encrypted = crypto_module_->Encrypt(*key, plaintext);
    ASSERT_NE(encrypted, nullptr);

    // Decrypt
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(crypto_module_->Decrypt(*key, *encrypted, {}, decrypted));

    // Verify
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(CryptoTest, EmptyDataEncryption) {
    auto key = SecureKey::Generate();
    ASSERT_NE(key, nullptr);

    std::vector<uint8_t> plaintext;

    // Encrypt empty data
    auto encrypted = crypto_module_->Encrypt(*key, plaintext);
    ASSERT_NE(encrypted, nullptr);

    // Decrypt
    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(crypto_module_->Decrypt(*key, *encrypted, {}, decrypted));

    // Verify
    EXPECT_EQ(plaintext, decrypted);
    EXPECT_TRUE(decrypted.empty());
}
