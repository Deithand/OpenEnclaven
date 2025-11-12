#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace openenclave {
namespace protocol {

/**
 * @brief Command types for enclave communication
 */
enum class CommandType : uint8_t {
    LOAD_MODULE = 1,
    INVOKE_FUNCTION = 2,
    STORE_DATA = 3,
    RETRIEVE_DATA = 4,
    GET_ATTESTATION = 5,
    SHUTDOWN = 255
};

/**
 * @brief Response status codes
 */
enum class ResponseStatus : uint8_t {
    SUCCESS = 0,
    ERROR_INVALID_COMMAND = 1,
    ERROR_INVALID_PARAMS = 2,
    ERROR_EXECUTION_FAILED = 3,
    ERROR_NOT_FOUND = 4,
    ERROR_CRYPTO_FAILED = 5,
    ERROR_INTERNAL = 255
};

/**
 * @brief Message header for wire protocol
 */
struct MessageHeader {
    uint32_t magic;          // Protocol magic number
    uint16_t version;        // Protocol version
    uint8_t command_type;    // CommandType
    uint8_t flags;           // Reserved flags
    uint32_t payload_size;   // Size of payload in bytes
    uint32_t checksum;       // CRC32 checksum of payload

    static constexpr uint32_t MAGIC = 0x4F45534B; // "OESK"
    static constexpr uint16_t VERSION = 1;

    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(const std::vector<uint8_t>& data, MessageHeader& out);
};

/**
 * @brief Request message
 */
struct Request {
    MessageHeader header;
    std::vector<uint8_t> payload;

    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(const std::vector<uint8_t>& data, Request& out);
};

/**
 * @brief Response message
 */
struct Response {
    MessageHeader header;
    ResponseStatus status;
    std::vector<uint8_t> payload;

    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(const std::vector<uint8_t>& data, Response& out);
};

/**
 * @brief LoadModule request payload
 */
struct LoadModuleRequest {
    std::vector<uint8_t> module_data;

    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(const std::vector<uint8_t>& data, LoadModuleRequest& out);
};

/**
 * @brief LoadModule response payload
 */
struct LoadModuleResponse {
    uint64_t module_handle;

    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(const std::vector<uint8_t>& data, LoadModuleResponse& out);
};

/**
 * @brief InvokeFunction request payload
 */
struct InvokeFunctionRequest {
    uint64_t module_handle;
    std::string function_name;
    std::vector<uint8_t> params;

    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(const std::vector<uint8_t>& data, InvokeFunctionRequest& out);
};

/**
 * @brief StoreData request payload
 */
struct StoreDataRequest {
    std::string key;
    std::vector<uint8_t> data;

    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(const std::vector<uint8_t>& data, StoreDataRequest& out);
};

/**
 * @brief RetrieveData request payload
 */
struct RetrieveDataRequest {
    std::string key;

    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(const std::vector<uint8_t>& data, RetrieveDataRequest& out);
};

/**
 * @brief Calculate CRC32 checksum
 */
uint32_t CalculateCRC32(const uint8_t* data, size_t size);

/**
 * @brief Validate message integrity
 */
bool ValidateMessage(const Request& request);
bool ValidateMessage(const Response& response);

} // namespace protocol
} // namespace openenclave
