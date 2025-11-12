#include "openenclave/enclave.hpp"
#include <gtest/gtest.h>
#include <vector>

using namespace openenclave;

class EnclaveTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto result = Enclave::Create();
        ASSERT_TRUE(result.IsOk());
        enclave_ = std::move(result.GetValue());
    }

    std::unique_ptr<Enclave> enclave_;
};

TEST_F(EnclaveTest, EnclaveCreation) {
    ASSERT_NE(enclave_, nullptr);
}

TEST_F(EnclaveTest, LoadModule) {
    std::vector<uint8_t> module_data = {0x01, 0x02, 0x03, 0x04};

    auto result = enclave_->LoadModule(module_data);
    ASSERT_TRUE(result.IsOk());

    auto handle = result.GetValue();
    EXPECT_GT(handle.GetId(), 0);
}

TEST_F(EnclaveTest, LoadEmptyModuleFails) {
    std::vector<uint8_t> empty_module;

    auto result = enclave_->LoadModule(empty_module);
    EXPECT_TRUE(result.IsError());
    EXPECT_EQ(result.GetStatus(), EnclaveStatus::ERROR_INVALID_PARAMETER);
}

TEST_F(EnclaveTest, LoadTooLargeModuleFails) {
    // Create module larger than 10MB
    std::vector<uint8_t> large_module(11 * 1024 * 1024, 0xFF);

    auto result = enclave_->LoadModule(large_module);
    EXPECT_TRUE(result.IsError());
    EXPECT_EQ(result.GetStatus(), EnclaveStatus::ERROR_INVALID_PARAMETER);
}

TEST_F(EnclaveTest, InvokeFunction) {
    // Load module first
    std::vector<uint8_t> module_data = {0x01, 0x02, 0x03, 0x04};
    auto load_result = enclave_->LoadModule(module_data);
    ASSERT_TRUE(load_result.IsOk());
    auto handle = load_result.GetValue();

    // Invoke function
    std::vector<uint8_t> params = {0x10, 0x20, 0x30};
    auto invoke_result = enclave_->InvokeFunction(handle, "test_function", params);

    ASSERT_TRUE(invoke_result.IsOk());
    auto result = invoke_result.GetValue();

    // Verify result contains at least the input params
    EXPECT_GE(result.size(), params.size());
}

TEST_F(EnclaveTest, InvokeFunctionInvalidHandle) {
    ModuleHandle invalid_handle(999999);

    std::vector<uint8_t> params = {0x10, 0x20};
    auto result = enclave_->InvokeFunction(invalid_handle, "test_function", params);

    EXPECT_TRUE(result.IsError());
    EXPECT_EQ(result.GetStatus(), EnclaveStatus::ERROR_MODULE_LOAD_FAILED);
}

TEST_F(EnclaveTest, InvokeFunctionNotFound) {
    // Load module first
    std::vector<uint8_t> module_data = {0x01, 0x02, 0x03, 0x04};
    auto load_result = enclave_->LoadModule(module_data);
    ASSERT_TRUE(load_result.IsOk());
    auto handle = load_result.GetValue();

    // Invoke non-existent function
    std::vector<uint8_t> params = {0x10, 0x20};
    auto invoke_result = enclave_->InvokeFunction(handle, "nonexistent_function", params);

    EXPECT_TRUE(invoke_result.IsError());
    EXPECT_EQ(invoke_result.GetStatus(), EnclaveStatus::ERROR_FUNCTION_NOT_FOUND);
}

TEST_F(EnclaveTest, InvokeFunctionEmptyName) {
    // Load module first
    std::vector<uint8_t> module_data = {0x01, 0x02, 0x03, 0x04};
    auto load_result = enclave_->LoadModule(module_data);
    ASSERT_TRUE(load_result.IsOk());
    auto handle = load_result.GetValue();

    // Invoke with empty function name
    std::vector<uint8_t> params = {0x10, 0x20};
    auto invoke_result = enclave_->InvokeFunction(handle, "", params);

    EXPECT_TRUE(invoke_result.IsError());
    EXPECT_EQ(invoke_result.GetStatus(), EnclaveStatus::ERROR_INVALID_PARAMETER);
}

TEST_F(EnclaveTest, StoreAndRetrieveData) {
    std::string key = "test_key";
    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};

    // Store data
    auto store_result = enclave_->StoreData(key, data);
    ASSERT_TRUE(store_result.IsOk());

    // Retrieve data
    auto retrieve_result = enclave_->RetrieveData(key);
    ASSERT_TRUE(retrieve_result.IsOk());

    auto retrieved_data = retrieve_result.GetValue();
    EXPECT_EQ(data, retrieved_data);
}

TEST_F(EnclaveTest, RetrieveNonExistentKey) {
    auto result = enclave_->RetrieveData("nonexistent_key");

    EXPECT_TRUE(result.IsError());
    EXPECT_EQ(result.GetStatus(), EnclaveStatus::ERROR_FUNCTION_NOT_FOUND);
}

TEST_F(EnclaveTest, StoreEmptyKeyFails) {
    std::vector<uint8_t> data = {'t', 'e', 's', 't'};

    auto result = enclave_->StoreData("", data);

    EXPECT_TRUE(result.IsError());
    EXPECT_EQ(result.GetStatus(), EnclaveStatus::ERROR_INVALID_PARAMETER);
}

TEST_F(EnclaveTest, StoreEmptyDataFails) {
    std::vector<uint8_t> empty_data;

    auto result = enclave_->StoreData("key", empty_data);

    EXPECT_TRUE(result.IsError());
    EXPECT_EQ(result.GetStatus(), EnclaveStatus::ERROR_INVALID_PARAMETER);
}

TEST_F(EnclaveTest, StoreOverwritesExistingKey) {
    std::string key = "test_key";
    std::vector<uint8_t> data1 = {'d', 'a', 't', 'a', '1'};
    std::vector<uint8_t> data2 = {'d', 'a', 't', 'a', '2'};

    // Store first data
    auto store1 = enclave_->StoreData(key, data1);
    ASSERT_TRUE(store1.IsOk());

    // Overwrite with second data
    auto store2 = enclave_->StoreData(key, data2);
    ASSERT_TRUE(store2.IsOk());

    // Retrieve should return second data
    auto retrieve_result = enclave_->RetrieveData(key);
    ASSERT_TRUE(retrieve_result.IsOk());

    auto retrieved_data = retrieve_result.GetValue();
    EXPECT_EQ(data2, retrieved_data);
    EXPECT_NE(data1, retrieved_data);
}

TEST_F(EnclaveTest, GetAttestation) {
    auto result = enclave_->GetAttestation();

    ASSERT_TRUE(result.IsOk());
    auto attestation = result.GetValue();

    // Attestation should have expected size (4 + 8 + 32 = 44 bytes)
    EXPECT_EQ(attestation.size(), 44);
}

TEST_F(EnclaveTest, LoadMultipleModules) {
    std::vector<uint8_t> module1 = {0x01, 0x02};
    std::vector<uint8_t> module2 = {0x03, 0x04};

    auto result1 = enclave_->LoadModule(module1);
    ASSERT_TRUE(result1.IsOk());

    auto result2 = enclave_->LoadModule(module2);
    ASSERT_TRUE(result2.IsOk());

    // Handles should be different
    EXPECT_NE(result1.GetValue().GetId(), result2.GetValue().GetId());
}

TEST_F(EnclaveTest, StoreLargeData) {
    std::string key = "large_data";
    std::vector<uint8_t> large_data(1024 * 1024, 0xAB); // 1MB

    auto store_result = enclave_->StoreData(key, large_data);
    ASSERT_TRUE(store_result.IsOk());

    auto retrieve_result = enclave_->RetrieveData(key);
    ASSERT_TRUE(retrieve_result.IsOk());

    auto retrieved_data = retrieve_result.GetValue();
    EXPECT_EQ(large_data, retrieved_data);
}

TEST_F(EnclaveTest, StoreTooLargeDataFails) {
    std::string key = "too_large";
    std::vector<uint8_t> too_large_data(11 * 1024 * 1024, 0xFF); // > 10MB

    auto result = enclave_->StoreData(key, too_large_data);

    EXPECT_TRUE(result.IsError());
    EXPECT_EQ(result.GetStatus(), EnclaveStatus::ERROR_INVALID_PARAMETER);
}

TEST_F(EnclaveTest, StatusToStringCoverage) {
    EXPECT_STREQ(StatusToString(EnclaveStatus::OK), "OK");
    EXPECT_STREQ(StatusToString(EnclaveStatus::ERROR_INVALID_PARAMETER), "Invalid parameter");
    EXPECT_STREQ(StatusToString(EnclaveStatus::ERROR_CRYPTO_FAILURE), "Cryptographic operation failed");
}

TEST(EnclaveCreationTest, MultipleEnclaves) {
    auto result1 = Enclave::Create();
    ASSERT_TRUE(result1.IsOk());

    auto result2 = Enclave::Create();
    ASSERT_TRUE(result2.IsOk());

    // Both should be independent
    EXPECT_NE(result1.GetValue().get(), result2.GetValue().get());
}
