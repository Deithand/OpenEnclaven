#include "openenclave/protocol.hpp"
#include <gtest/gtest.h>
#include <vector>

using namespace openenclave::protocol;

TEST(ProtocolTest, CRC32Calculation) {
    std::vector<uint8_t> data1 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> data2 = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> data3 = {0x05, 0x06, 0x07, 0x08};

    uint32_t crc1 = CalculateCRC32(data1.data(), data1.size());
    uint32_t crc2 = CalculateCRC32(data2.data(), data2.size());
    uint32_t crc3 = CalculateCRC32(data3.data(), data3.size());

    // Same data should produce same CRC
    EXPECT_EQ(crc1, crc2);

    // Different data should produce different CRC (highly likely)
    EXPECT_NE(crc1, crc3);
}

TEST(ProtocolTest, MessageHeaderSerialization) {
    MessageHeader header;
    header.magic = MessageHeader::MAGIC;
    header.version = MessageHeader::VERSION;
    header.command_type = static_cast<uint8_t>(CommandType::LOAD_MODULE);
    header.flags = 0;
    header.payload_size = 100;
    header.checksum = 0x12345678;

    // Serialize
    auto serialized = header.Serialize();
    EXPECT_EQ(serialized.size(), 16);

    // Deserialize
    MessageHeader deserialized;
    ASSERT_TRUE(MessageHeader::Deserialize(serialized, deserialized));

    // Verify
    EXPECT_EQ(deserialized.magic, header.magic);
    EXPECT_EQ(deserialized.version, header.version);
    EXPECT_EQ(deserialized.command_type, header.command_type);
    EXPECT_EQ(deserialized.flags, header.flags);
    EXPECT_EQ(deserialized.payload_size, header.payload_size);
    EXPECT_EQ(deserialized.checksum, header.checksum);
}

TEST(ProtocolTest, MessageHeaderDeserializationTooSmall) {
    std::vector<uint8_t> invalid_data = {0x01, 0x02, 0x03};

    MessageHeader header;
    EXPECT_FALSE(MessageHeader::Deserialize(invalid_data, header));
}

TEST(ProtocolTest, RequestSerialization) {
    Request request;
    request.header.magic = MessageHeader::MAGIC;
    request.header.version = MessageHeader::VERSION;
    request.header.command_type = static_cast<uint8_t>(CommandType::LOAD_MODULE);
    request.header.flags = 0;
    request.payload = {0x01, 0x02, 0x03, 0x04};
    request.header.payload_size = static_cast<uint32_t>(request.payload.size());
    request.header.checksum = CalculateCRC32(request.payload.data(), request.payload.size());

    // Serialize
    auto serialized = request.Serialize();
    EXPECT_EQ(serialized.size(), 16 + request.payload.size());

    // Deserialize
    Request deserialized;
    ASSERT_TRUE(Request::Deserialize(serialized, deserialized));

    // Verify
    EXPECT_EQ(deserialized.header.magic, request.header.magic);
    EXPECT_EQ(deserialized.payload, request.payload);
}

TEST(ProtocolTest, ResponseSerialization) {
    Response response;
    response.header.magic = MessageHeader::MAGIC;
    response.header.version = MessageHeader::VERSION;
    response.header.command_type = 0;
    response.header.flags = 0;
    response.status = ResponseStatus::SUCCESS;
    response.payload = {0x10, 0x20, 0x30};
    response.header.payload_size = static_cast<uint32_t>(response.payload.size());
    response.header.checksum = CalculateCRC32(response.payload.data(), response.payload.size());

    // Serialize
    auto serialized = response.Serialize();
    EXPECT_EQ(serialized.size(), 17 + response.payload.size());

    // Deserialize
    Response deserialized;
    ASSERT_TRUE(Response::Deserialize(serialized, deserialized));

    // Verify
    EXPECT_EQ(deserialized.status, response.status);
    EXPECT_EQ(deserialized.payload, response.payload);
}

TEST(ProtocolTest, LoadModuleRequestSerialization) {
    LoadModuleRequest request;
    request.module_data = {0x01, 0x02, 0x03, 0x04, 0x05};

    // Serialize
    auto serialized = request.Serialize();
    EXPECT_GT(serialized.size(), 0);

    // Deserialize
    LoadModuleRequest deserialized;
    ASSERT_TRUE(LoadModuleRequest::Deserialize(serialized, deserialized));

    // Verify
    EXPECT_EQ(deserialized.module_data, request.module_data);
}

TEST(ProtocolTest, LoadModuleResponseSerialization) {
    LoadModuleResponse response;
    response.module_handle = 0x123456789ABCDEF0;

    // Serialize
    auto serialized = response.Serialize();
    EXPECT_EQ(serialized.size(), 8);

    // Deserialize
    LoadModuleResponse deserialized;
    ASSERT_TRUE(LoadModuleResponse::Deserialize(serialized, deserialized));

    // Verify
    EXPECT_EQ(deserialized.module_handle, response.module_handle);
}

TEST(ProtocolTest, InvokeFunctionRequestSerialization) {
    InvokeFunctionRequest request;
    request.module_handle = 0x1234567890ABCDEF;
    request.function_name = "test_function";
    request.params = {0x01, 0x02, 0x03};

    // Serialize
    auto serialized = request.Serialize();
    EXPECT_GT(serialized.size(), 0);

    // Deserialize
    InvokeFunctionRequest deserialized;
    ASSERT_TRUE(InvokeFunctionRequest::Deserialize(serialized, deserialized));

    // Verify
    EXPECT_EQ(deserialized.module_handle, request.module_handle);
    EXPECT_EQ(deserialized.function_name, request.function_name);
    EXPECT_EQ(deserialized.params, request.params);
}

TEST(ProtocolTest, StoreDataRequestSerialization) {
    StoreDataRequest request;
    request.key = "my_key";
    request.data = {0x10, 0x20, 0x30, 0x40};

    // Serialize
    auto serialized = request.Serialize();
    EXPECT_GT(serialized.size(), 0);

    // Deserialize
    StoreDataRequest deserialized;
    ASSERT_TRUE(StoreDataRequest::Deserialize(serialized, deserialized));

    // Verify
    EXPECT_EQ(deserialized.key, request.key);
    EXPECT_EQ(deserialized.data, request.data);
}

TEST(ProtocolTest, RetrieveDataRequestSerialization) {
    RetrieveDataRequest request;
    request.key = "my_secret_key";

    // Serialize
    auto serialized = request.Serialize();
    EXPECT_GT(serialized.size(), 0);

    // Deserialize
    RetrieveDataRequest deserialized;
    ASSERT_TRUE(RetrieveDataRequest::Deserialize(serialized, deserialized));

    // Verify
    EXPECT_EQ(deserialized.key, request.key);
}

TEST(ProtocolTest, ValidateRequestWithCorrectChecksum) {
    Request request;
    request.header.magic = MessageHeader::MAGIC;
    request.header.version = MessageHeader::VERSION;
    request.header.command_type = static_cast<uint8_t>(CommandType::LOAD_MODULE);
    request.header.flags = 0;
    request.payload = {0x01, 0x02, 0x03, 0x04};
    request.header.payload_size = static_cast<uint32_t>(request.payload.size());
    request.header.checksum = CalculateCRC32(request.payload.data(), request.payload.size());

    EXPECT_TRUE(ValidateMessage(request));
}

TEST(ProtocolTest, ValidateRequestWithWrongMagic) {
    Request request;
    request.header.magic = 0xDEADBEEF;
    request.header.version = MessageHeader::VERSION;
    request.header.command_type = static_cast<uint8_t>(CommandType::LOAD_MODULE);
    request.header.flags = 0;
    request.payload = {0x01, 0x02};
    request.header.payload_size = static_cast<uint32_t>(request.payload.size());
    request.header.checksum = CalculateCRC32(request.payload.data(), request.payload.size());

    EXPECT_FALSE(ValidateMessage(request));
}

TEST(ProtocolTest, ValidateRequestWithWrongChecksum) {
    Request request;
    request.header.magic = MessageHeader::MAGIC;
    request.header.version = MessageHeader::VERSION;
    request.header.command_type = static_cast<uint8_t>(CommandType::LOAD_MODULE);
    request.header.flags = 0;
    request.payload = {0x01, 0x02, 0x03};
    request.header.payload_size = static_cast<uint32_t>(request.payload.size());
    request.header.checksum = 0xDEADBEEF; // Wrong checksum

    EXPECT_FALSE(ValidateMessage(request));
}

TEST(ProtocolTest, ValidateResponseWithCorrectChecksum) {
    Response response;
    response.header.magic = MessageHeader::MAGIC;
    response.header.version = MessageHeader::VERSION;
    response.header.command_type = 0;
    response.header.flags = 0;
    response.status = ResponseStatus::SUCCESS;
    response.payload = {0x10, 0x20};
    response.header.payload_size = static_cast<uint32_t>(response.payload.size());
    response.header.checksum = CalculateCRC32(response.payload.data(), response.payload.size());

    EXPECT_TRUE(ValidateMessage(response));
}

TEST(ProtocolTest, EmptyPayloadSerialization) {
    Request request;
    request.header.magic = MessageHeader::MAGIC;
    request.header.version = MessageHeader::VERSION;
    request.header.command_type = static_cast<uint8_t>(CommandType::GET_ATTESTATION);
    request.header.flags = 0;
    request.payload.clear();
    request.header.payload_size = 0;
    request.header.checksum = 0;

    // Serialize
    auto serialized = request.Serialize();
    EXPECT_EQ(serialized.size(), 16);

    // Deserialize
    Request deserialized;
    ASSERT_TRUE(Request::Deserialize(serialized, deserialized));

    // Verify
    EXPECT_TRUE(deserialized.payload.empty());
}

TEST(ProtocolTest, LargePayloadSerialization) {
    LoadModuleRequest request;
    request.module_data.resize(1024 * 1024, 0xAB); // 1MB

    // Serialize
    auto serialized = request.Serialize();
    EXPECT_GT(serialized.size(), 1024 * 1024);

    // Deserialize
    LoadModuleRequest deserialized;
    ASSERT_TRUE(LoadModuleRequest::Deserialize(serialized, deserialized));

    // Verify
    EXPECT_EQ(deserialized.module_data, request.module_data);
}

TEST(ProtocolTest, DeserializeTooLargeStringFails) {
    // Create a payload with a string size that exceeds the sanity check limit
    std::vector<uint8_t> payload;
    uint32_t huge_size = 2 * 1024 * 1024; // 2MB (exceeds 1MB limit)
    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&huge_size),
                  reinterpret_cast<uint8_t*>(&huge_size) + 4);

    RetrieveDataRequest request;
    EXPECT_FALSE(RetrieveDataRequest::Deserialize(payload, request));
}

TEST(ProtocolTest, DeserializeTooLargeBytesFails) {
    // Create a payload with a bytes size that exceeds the sanity check limit
    std::vector<uint8_t> payload;
    uint32_t huge_size = 11 * 1024 * 1024; // 11MB (exceeds 10MB limit)
    payload.insert(payload.end(), reinterpret_cast<uint8_t*>(&huge_size),
                  reinterpret_cast<uint8_t*>(&huge_size) + 4);

    LoadModuleRequest request;
    EXPECT_FALSE(LoadModuleRequest::Deserialize(payload, request));
}
