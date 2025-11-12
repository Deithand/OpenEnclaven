#include "openenclave/protocol.hpp"
#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

using namespace openenclave;

class EnclaveClient {
public:
    EnclaveClient() : socket_fd_(-1) {}

    ~EnclaveClient() {
        Disconnect();
    }

    bool Connect(const char* socket_path) {
        socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd_ < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }

        struct sockaddr_un addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

        if (connect(socket_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            std::cerr << "Failed to connect to " << socket_path << std::endl;
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        return true;
    }

    void Disconnect() {
        if (socket_fd_ >= 0) {
            close(socket_fd_);
            socket_fd_ = -1;
        }
    }

    bool LoadModule(const std::vector<uint8_t>& module_data, uint64_t& handle_out) {
        protocol::LoadModuleRequest req;
        req.module_data = module_data;

        auto payload = req.Serialize();

        protocol::Request request;
        request.header.magic = protocol::MessageHeader::MAGIC;
        request.header.version = protocol::MessageHeader::VERSION;
        request.header.command_type = static_cast<uint8_t>(protocol::CommandType::LOAD_MODULE);
        request.header.flags = 0;
        request.header.payload_size = static_cast<uint32_t>(payload.size());
        request.header.checksum = protocol::CalculateCRC32(payload.data(), payload.size());
        request.payload = payload;

        auto response = SendRequest(request);
        if (!response || response->status != protocol::ResponseStatus::SUCCESS) {
            return false;
        }

        protocol::LoadModuleResponse resp;
        if (!protocol::LoadModuleResponse::Deserialize(response->payload, resp)) {
            return false;
        }

        handle_out = resp.module_handle;
        return true;
    }

    bool InvokeFunction(uint64_t module_handle, const std::string& function_name,
                       const std::vector<uint8_t>& params, std::vector<uint8_t>& result_out) {
        protocol::InvokeFunctionRequest req;
        req.module_handle = module_handle;
        req.function_name = function_name;
        req.params = params;

        auto payload = req.Serialize();

        protocol::Request request;
        request.header.magic = protocol::MessageHeader::MAGIC;
        request.header.version = protocol::MessageHeader::VERSION;
        request.header.command_type = static_cast<uint8_t>(protocol::CommandType::INVOKE_FUNCTION);
        request.header.flags = 0;
        request.header.payload_size = static_cast<uint32_t>(payload.size());
        request.header.checksum = protocol::CalculateCRC32(payload.data(), payload.size());
        request.payload = payload;

        auto response = SendRequest(request);
        if (!response || response->status != protocol::ResponseStatus::SUCCESS) {
            return false;
        }

        result_out = response->payload;
        return true;
    }

    bool StoreData(const std::string& key, const std::vector<uint8_t>& data) {
        protocol::StoreDataRequest req;
        req.key = key;
        req.data = data;

        auto payload = req.Serialize();

        protocol::Request request;
        request.header.magic = protocol::MessageHeader::MAGIC;
        request.header.version = protocol::MessageHeader::VERSION;
        request.header.command_type = static_cast<uint8_t>(protocol::CommandType::STORE_DATA);
        request.header.flags = 0;
        request.header.payload_size = static_cast<uint32_t>(payload.size());
        request.header.checksum = protocol::CalculateCRC32(payload.data(), payload.size());
        request.payload = payload;

        auto response = SendRequest(request);
        return response && response->status == protocol::ResponseStatus::SUCCESS;
    }

    bool RetrieveData(const std::string& key, std::vector<uint8_t>& data_out) {
        protocol::RetrieveDataRequest req;
        req.key = key;

        auto payload = req.Serialize();

        protocol::Request request;
        request.header.magic = protocol::MessageHeader::MAGIC;
        request.header.version = protocol::MessageHeader::VERSION;
        request.header.command_type = static_cast<uint8_t>(protocol::CommandType::RETRIEVE_DATA);
        request.header.flags = 0;
        request.header.payload_size = static_cast<uint32_t>(payload.size());
        request.header.checksum = protocol::CalculateCRC32(payload.data(), payload.size());
        request.payload = payload;

        auto response = SendRequest(request);
        if (!response || response->status != protocol::ResponseStatus::SUCCESS) {
            return false;
        }

        data_out = response->payload;
        return true;
    }

    bool GetAttestation(std::vector<uint8_t>& attestation_out) {
        protocol::Request request;
        request.header.magic = protocol::MessageHeader::MAGIC;
        request.header.version = protocol::MessageHeader::VERSION;
        request.header.command_type = static_cast<uint8_t>(protocol::CommandType::GET_ATTESTATION);
        request.header.flags = 0;
        request.header.payload_size = 0;
        request.header.checksum = 0;

        auto response = SendRequest(request);
        if (!response || response->status != protocol::ResponseStatus::SUCCESS) {
            return false;
        }

        attestation_out = response->payload;
        return true;
    }

private:
    std::unique_ptr<protocol::Response> SendRequest(const protocol::Request& request) {
        if (socket_fd_ < 0) return nullptr;

        auto data = request.Serialize();

        // Send request
        if (send(socket_fd_, data.data(), data.size(), 0) < 0) {
            return nullptr;
        }

        // Receive response header
        std::vector<uint8_t> header_buf(16);
        ssize_t n = recv(socket_fd_, header_buf.data(), header_buf.size(), MSG_WAITALL);
        if (n != 16) {
            return nullptr;
        }

        auto response = std::make_unique<protocol::Response>();
        if (!protocol::MessageHeader::Deserialize(header_buf, response->header)) {
            return nullptr;
        }

        // Receive status byte
        uint8_t status_byte;
        n = recv(socket_fd_, &status_byte, 1, MSG_WAITALL);
        if (n != 1) {
            return nullptr;
        }
        response->status = static_cast<protocol::ResponseStatus>(status_byte);

        // Receive payload if present
        if (response->header.payload_size > 0) {
            response->payload.resize(response->header.payload_size);
            n = recv(socket_fd_, response->payload.data(), response->header.payload_size, MSG_WAITALL);
            if (static_cast<size_t>(n) != response->header.payload_size) {
                return nullptr;
            }
        }

        return response;
    }

    int socket_fd_;
};

int main() {
    EnclaveClient client;

    std::cout << "Connecting to enclave server..." << std::endl;
    if (!client.Connect("/tmp/openenclave.sock")) {
        std::cerr << "Failed to connect. Make sure the server is running." << std::endl;
        return 1;
    }

    std::cout << "Connected successfully!" << std::endl;

    // Test 1: Load module
    std::cout << "\nTest 1: Loading module..." << std::endl;
    std::vector<uint8_t> module_data = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint64_t module_handle;

    if (client.LoadModule(module_data, module_handle)) {
        std::cout << "Module loaded successfully! Handle: " << module_handle << std::endl;
    } else {
        std::cerr << "Failed to load module" << std::endl;
        return 1;
    }

    // Test 2: Invoke function
    std::cout << "\nTest 2: Invoking function..." << std::endl;
    std::vector<uint8_t> params = {0x10, 0x20, 0x30};
    std::vector<uint8_t> result;

    if (client.InvokeFunction(module_handle, "test_function", params, result)) {
        std::cout << "Function invoked successfully! Result size: " << result.size() << " bytes" << std::endl;
    } else {
        std::cerr << "Failed to invoke function" << std::endl;
        return 1;
    }

    // Test 3: Store data
    std::cout << "\nTest 3: Storing data..." << std::endl;
    std::vector<uint8_t> secret_data = {'H', 'e', 'l', 'l', 'o', ' ', 'E', 'n', 'c', 'l', 'a', 'v', 'e'};

    if (client.StoreData("my_secret", secret_data)) {
        std::cout << "Data stored successfully!" << std::endl;
    } else {
        std::cerr << "Failed to store data" << std::endl;
        return 1;
    }

    // Test 4: Retrieve data
    std::cout << "\nTest 4: Retrieving data..." << std::endl;
    std::vector<uint8_t> retrieved_data;

    if (client.RetrieveData("my_secret", retrieved_data)) {
        std::cout << "Data retrieved successfully! Data: ";
        for (uint8_t byte : retrieved_data) {
            std::cout << static_cast<char>(byte);
        }
        std::cout << std::endl;
    } else {
        std::cerr << "Failed to retrieve data" << std::endl;
        return 1;
    }

    // Test 5: Get attestation
    std::cout << "\nTest 5: Getting attestation..." << std::endl;
    std::vector<uint8_t> attestation;

    if (client.GetAttestation(attestation)) {
        std::cout << "Attestation retrieved successfully! Size: " << attestation.size() << " bytes" << std::endl;
    } else {
        std::cerr << "Failed to get attestation" << std::endl;
        return 1;
    }

    std::cout << "\nAll tests passed!" << std::endl;

    return 0;
}
