#include "openenclave/protocol.hpp"
#include <cstring>
#include <algorithm>

namespace openenclave {
namespace protocol {

// CRC32 implementation (standard polynomial 0xEDB88320)
uint32_t CalculateCRC32(const uint8_t* data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }

    return ~crc;
}

// Helper: Write uint32_t to vector
static void WriteUInt32(std::vector<uint8_t>& vec, uint32_t value) {
    vec.insert(vec.end(), reinterpret_cast<const uint8_t*>(&value),
               reinterpret_cast<const uint8_t*>(&value) + 4);
}

// Helper: Write uint16_t to vector
static void WriteUInt16(std::vector<uint8_t>& vec, uint16_t value) {
    vec.insert(vec.end(), reinterpret_cast<const uint8_t*>(&value),
               reinterpret_cast<const uint8_t*>(&value) + 2);
}

// Helper: Write uint8_t to vector
static void WriteUInt8(std::vector<uint8_t>& vec, uint8_t value) {
    vec.push_back(value);
}

// Helper: Write string to vector (length-prefixed)
static void WriteString(std::vector<uint8_t>& vec, const std::string& str) {
    uint32_t len = static_cast<uint32_t>(str.size());
    WriteUInt32(vec, len);
    vec.insert(vec.end(), str.begin(), str.end());
}

// Helper: Write bytes to vector (length-prefixed)
static void WriteBytes(std::vector<uint8_t>& vec, const std::vector<uint8_t>& bytes) {
    uint32_t len = static_cast<uint32_t>(bytes.size());
    WriteUInt32(vec, len);
    vec.insert(vec.end(), bytes.begin(), bytes.end());
}

// Helper: Read uint32_t from vector
static bool ReadUInt32(const std::vector<uint8_t>& vec, size_t& offset, uint32_t& value) {
    if (offset + 4 > vec.size()) return false;
    std::memcpy(&value, vec.data() + offset, 4);
    offset += 4;
    return true;
}

// Helper: Read uint16_t from vector
static bool ReadUInt16(const std::vector<uint8_t>& vec, size_t& offset, uint16_t& value) {
    if (offset + 2 > vec.size()) return false;
    std::memcpy(&value, vec.data() + offset, 2);
    offset += 2;
    return true;
}

// Helper: Read uint8_t from vector
static bool ReadUInt8(const std::vector<uint8_t>& vec, size_t& offset, uint8_t& value) {
    if (offset >= vec.size()) return false;
    value = vec[offset++];
    return true;
}

// Helper: Read string from vector
static bool ReadString(const std::vector<uint8_t>& vec, size_t& offset, std::string& str) {
    uint32_t len;
    if (!ReadUInt32(vec, offset, len)) return false;
    if (len > 1024 * 1024) return false; // Sanity check: max 1MB
    if (offset + len > vec.size()) return false;

    str.assign(vec.begin() + static_cast<std::vector<uint8_t>::difference_type>(offset),
               vec.begin() + static_cast<std::vector<uint8_t>::difference_type>(offset + len));
    offset += len;
    return true;
}

// Helper: Read bytes from vector
static bool ReadBytes(const std::vector<uint8_t>& vec, size_t& offset, std::vector<uint8_t>& bytes) {
    uint32_t len;
    if (!ReadUInt32(vec, offset, len)) return false;
    if (len > 10 * 1024 * 1024) return false; // Sanity check: max 10MB
    if (offset + len > vec.size()) return false;

    bytes.assign(vec.begin() + static_cast<std::vector<uint8_t>::difference_type>(offset),
                 vec.begin() + static_cast<std::vector<uint8_t>::difference_type>(offset + len));
    offset += len;
    return true;
}

// ============================================================================
// MessageHeader Implementation
// ============================================================================

std::vector<uint8_t> MessageHeader::Serialize() const {
    std::vector<uint8_t> result;
    result.reserve(16);

    WriteUInt32(result, magic);
    WriteUInt16(result, version);
    WriteUInt8(result, command_type);
    WriteUInt8(result, flags);
    WriteUInt32(result, payload_size);
    WriteUInt32(result, checksum);

    return result;
}

bool MessageHeader::Deserialize(const std::vector<uint8_t>& data, MessageHeader& out) {
    if (data.size() < 16) return false;

    size_t offset = 0;
    if (!ReadUInt32(data, offset, out.magic)) return false;
    if (!ReadUInt16(data, offset, out.version)) return false;
    if (!ReadUInt8(data, offset, out.command_type)) return false;
    if (!ReadUInt8(data, offset, out.flags)) return false;
    if (!ReadUInt32(data, offset, out.payload_size)) return false;
    if (!ReadUInt32(data, offset, out.checksum)) return false;

    return true;
}

// ============================================================================
// Request Implementation
// ============================================================================

std::vector<uint8_t> Request::Serialize() const {
    auto header_bytes = header.Serialize();
    std::vector<uint8_t> result;
    result.reserve(header_bytes.size() + payload.size());
    result.insert(result.end(), header_bytes.begin(), header_bytes.end());
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

bool Request::Deserialize(const std::vector<uint8_t>& data, Request& out) {
    if (data.size() < 16) return false;

    std::vector<uint8_t> header_bytes(data.begin(), data.begin() + 16);
    if (!MessageHeader::Deserialize(header_bytes, out.header)) return false;

    if (data.size() != 16 + out.header.payload_size) return false;

    out.payload.assign(data.begin() + 16, data.end());
    return true;
}

// ============================================================================
// Response Implementation
// ============================================================================

std::vector<uint8_t> Response::Serialize() const {
    auto header_bytes = header.Serialize();
    std::vector<uint8_t> result;
    result.reserve(header_bytes.size() + 1 + payload.size());
    result.insert(result.end(), header_bytes.begin(), header_bytes.end());
    result.push_back(static_cast<uint8_t>(status));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

bool Response::Deserialize(const std::vector<uint8_t>& data, Response& out) {
    if (data.size() < 17) return false;

    std::vector<uint8_t> header_bytes(data.begin(), data.begin() + 16);
    if (!MessageHeader::Deserialize(header_bytes, out.header)) return false;

    out.status = static_cast<ResponseStatus>(data[16]);

    if (data.size() != 17 + out.header.payload_size) return false;

    out.payload.assign(data.begin() + 17, data.end());
    return true;
}

// ============================================================================
// LoadModuleRequest Implementation
// ============================================================================

std::vector<uint8_t> LoadModuleRequest::Serialize() const {
    std::vector<uint8_t> result;
    WriteBytes(result, module_data);
    return result;
}

bool LoadModuleRequest::Deserialize(const std::vector<uint8_t>& data, LoadModuleRequest& out) {
    size_t offset = 0;
    return ReadBytes(data, offset, out.module_data);
}

// ============================================================================
// LoadModuleResponse Implementation
// ============================================================================

std::vector<uint8_t> LoadModuleResponse::Serialize() const {
    std::vector<uint8_t> result;
    result.reserve(8);
    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&module_handle),
                  reinterpret_cast<const uint8_t*>(&module_handle) + 8);
    return result;
}

bool LoadModuleResponse::Deserialize(const std::vector<uint8_t>& data, LoadModuleResponse& out) {
    if (data.size() < 8) return false;
    std::memcpy(&out.module_handle, data.data(), 8);
    return true;
}

// ============================================================================
// InvokeFunctionRequest Implementation
// ============================================================================

std::vector<uint8_t> InvokeFunctionRequest::Serialize() const {
    std::vector<uint8_t> result;
    result.reserve(8 + 4 + function_name.size() + 4 + params.size());

    result.insert(result.end(), reinterpret_cast<const uint8_t*>(&module_handle),
                  reinterpret_cast<const uint8_t*>(&module_handle) + 8);
    WriteString(result, function_name);
    WriteBytes(result, params);

    return result;
}

bool InvokeFunctionRequest::Deserialize(const std::vector<uint8_t>& data, InvokeFunctionRequest& out) {
    if (data.size() < 8) return false;

    size_t offset = 0;
    std::memcpy(&out.module_handle, data.data(), 8);
    offset += 8;

    if (!ReadString(data, offset, out.function_name)) return false;
    if (!ReadBytes(data, offset, out.params)) return false;

    return true;
}

// ============================================================================
// StoreDataRequest Implementation
// ============================================================================

std::vector<uint8_t> StoreDataRequest::Serialize() const {
    std::vector<uint8_t> result;
    WriteString(result, key);
    WriteBytes(result, data);
    return result;
}

bool StoreDataRequest::Deserialize(const std::vector<uint8_t>& data, StoreDataRequest& out) {
    size_t offset = 0;
    if (!ReadString(data, offset, out.key)) return false;
    if (!ReadBytes(data, offset, out.data)) return false;
    return true;
}

// ============================================================================
// RetrieveDataRequest Implementation
// ============================================================================

std::vector<uint8_t> RetrieveDataRequest::Serialize() const {
    std::vector<uint8_t> result;
    WriteString(result, key);
    return result;
}

bool RetrieveDataRequest::Deserialize(const std::vector<uint8_t>& data, RetrieveDataRequest& out) {
    size_t offset = 0;
    return ReadString(data, offset, out.key);
}

// ============================================================================
// Message Validation
// ============================================================================

bool ValidateMessage(const Request& request) {
    // Check magic number
    if (request.header.magic != MessageHeader::MAGIC) return false;

    // Check version
    if (request.header.version != MessageHeader::VERSION) return false;

    // Check payload size matches
    if (request.payload.size() != request.header.payload_size) return false;

    // Verify checksum
    uint32_t computed_crc = CalculateCRC32(request.payload.data(), request.payload.size());
    if (computed_crc != request.header.checksum) return false;

    return true;
}

bool ValidateMessage(const Response& response) {
    // Check magic number
    if (response.header.magic != MessageHeader::MAGIC) return false;

    // Check version
    if (response.header.version != MessageHeader::VERSION) return false;

    // Check payload size matches
    if (response.payload.size() != response.header.payload_size) return false;

    // Verify checksum
    uint32_t computed_crc = CalculateCRC32(response.payload.data(), response.payload.size());
    if (computed_crc != response.header.checksum) return false;

    return true;
}

} // namespace protocol
} // namespace openenclave
