#include "openenclave/enclave.hpp"
#include "openenclave/protocol.hpp"
#include <iostream>
#include <memory>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>

namespace openenclave {
namespace server {

constexpr const char* SOCKET_PATH = "/tmp/openenclave.sock";
constexpr size_t MAX_MESSAGE_SIZE = 16 * 1024 * 1024; // 16MB

class EnclaveServer {
public:
    EnclaveServer() : socket_fd_(-1), running_(false) {}

    ~EnclaveServer() {
        Shutdown();
    }

    bool Initialize() {
        // Create enclave instance
        auto result = Enclave::Create();
        if (result.IsError()) {
            std::cerr << "Failed to create enclave: "
                      << StatusToString(result.GetStatus()) << std::endl;
            return false;
        }

        enclave_ = std::move(result.GetValue());

        // Create Unix domain socket
        socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd_ < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }

        // Remove existing socket file if present
        unlink(SOCKET_PATH);

        // Bind socket
        struct sockaddr_un addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

        if (bind(socket_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            std::cerr << "Failed to bind socket" << std::endl;
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        // Listen for connections
        if (listen(socket_fd_, 5) < 0) {
            std::cerr << "Failed to listen on socket" << std::endl;
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        std::cout << "Enclave server initialized on " << SOCKET_PATH << std::endl;
        return true;
    }

    void Run() {
        if (socket_fd_ < 0 || !enclave_) {
            std::cerr << "Server not initialized" << std::endl;
            return;
        }

        running_ = true;
        std::cout << "Server running. Press Ctrl+C to stop." << std::endl;

        while (running_) {
            // Accept connection
            int client_fd = accept(socket_fd_, nullptr, nullptr);
            if (client_fd < 0) {
                if (running_) {
                    std::cerr << "Failed to accept connection" << std::endl;
                }
                continue;
            }

            // Handle client request
            HandleClient(client_fd);

            close(client_fd);
        }
    }

    void Shutdown() {
        running_ = false;

        if (socket_fd_ >= 0) {
            close(socket_fd_);
            socket_fd_ = -1;
        }

        unlink(SOCKET_PATH);

        enclave_.reset();

        std::cout << "Server shut down" << std::endl;
    }

private:
    void HandleClient(int client_fd) {
        // Read request header
        std::vector<uint8_t> header_buf(16);
        ssize_t n = recv(client_fd, header_buf.data(), header_buf.size(), 0);

        if (n != 16) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INVALID_COMMAND);
            return;
        }

        // Parse header
        protocol::Request request;
        if (!protocol::MessageHeader::Deserialize(header_buf, request.header)) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INVALID_COMMAND);
            return;
        }

        // Validate header
        if (request.header.magic != protocol::MessageHeader::MAGIC ||
            request.header.version != protocol::MessageHeader::VERSION) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INVALID_COMMAND);
            return;
        }

        // Check payload size
        if (request.header.payload_size > MAX_MESSAGE_SIZE) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INVALID_PARAMS);
            return;
        }

        // Read payload
        request.payload.resize(request.header.payload_size);
        if (request.header.payload_size > 0) {
            n = recv(client_fd, request.payload.data(), request.header.payload_size, MSG_WAITALL);
            if (static_cast<size_t>(n) != request.header.payload_size) {
                SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INVALID_PARAMS);
                return;
            }
        }

        // Validate message
        if (!protocol::ValidateMessage(request)) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INVALID_PARAMS);
            return;
        }

        // Dispatch command
        DispatchCommand(client_fd, request);
    }

    void DispatchCommand(int client_fd, const protocol::Request& request) {
        auto cmd_type = static_cast<protocol::CommandType>(request.header.command_type);

        switch (cmd_type) {
            case protocol::CommandType::LOAD_MODULE:
                HandleLoadModule(client_fd, request);
                break;

            case protocol::CommandType::INVOKE_FUNCTION:
                HandleInvokeFunction(client_fd, request);
                break;

            case protocol::CommandType::STORE_DATA:
                HandleStoreData(client_fd, request);
                break;

            case protocol::CommandType::RETRIEVE_DATA:
                HandleRetrieveData(client_fd, request);
                break;

            case protocol::CommandType::GET_ATTESTATION:
                HandleGetAttestation(client_fd, request);
                break;

            case protocol::CommandType::SHUTDOWN:
                HandleShutdown(client_fd, request);
                break;

            default:
                SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INVALID_COMMAND);
                break;
        }
    }

    void HandleLoadModule(int client_fd, const protocol::Request& request) {
        protocol::LoadModuleRequest req;
        if (!protocol::LoadModuleRequest::Deserialize(request.payload, req)) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INVALID_PARAMS);
            return;
        }

        auto result = enclave_->LoadModule(req.module_data);
        if (result.IsError()) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_EXECUTION_FAILED);
            return;
        }

        protocol::LoadModuleResponse resp;
        resp.module_handle = result.GetValue().GetId();

        SendSuccessResponse(client_fd, resp.Serialize());
    }

    void HandleInvokeFunction(int client_fd, const protocol::Request& request) {
        protocol::InvokeFunctionRequest req;
        if (!protocol::InvokeFunctionRequest::Deserialize(request.payload, req)) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INVALID_PARAMS);
            return;
        }

        ModuleHandle handle(req.module_handle);
        auto result = enclave_->InvokeFunction(handle, req.function_name, req.params);

        if (result.IsError()) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_EXECUTION_FAILED);
            return;
        }

        SendSuccessResponse(client_fd, result.GetValue());
    }

    void HandleStoreData(int client_fd, const protocol::Request& request) {
        protocol::StoreDataRequest req;
        if (!protocol::StoreDataRequest::Deserialize(request.payload, req)) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INVALID_PARAMS);
            return;
        }

        auto result = enclave_->StoreData(req.key, req.data);
        if (result.IsError()) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_EXECUTION_FAILED);
            return;
        }

        SendSuccessResponse(client_fd, {});
    }

    void HandleRetrieveData(int client_fd, const protocol::Request& request) {
        protocol::RetrieveDataRequest req;
        if (!protocol::RetrieveDataRequest::Deserialize(request.payload, req)) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INVALID_PARAMS);
            return;
        }

        auto result = enclave_->RetrieveData(req.key);
        if (result.IsError()) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_NOT_FOUND);
            return;
        }

        SendSuccessResponse(client_fd, result.GetValue());
    }

    void HandleGetAttestation(int client_fd, const protocol::Request& request) {
        (void)request; // Unused

        auto result = enclave_->GetAttestation();
        if (result.IsError()) {
            SendErrorResponse(client_fd, protocol::ResponseStatus::ERROR_INTERNAL);
            return;
        }

        SendSuccessResponse(client_fd, result.GetValue());
    }

    void HandleShutdown(int client_fd, const protocol::Request& request) {
        (void)request; // Unused

        SendSuccessResponse(client_fd, {});

        std::cout << "Shutdown command received" << std::endl;
        running_ = false;
    }

    void SendSuccessResponse(int client_fd, const std::vector<uint8_t>& payload) {
        protocol::Response response;
        response.header.magic = protocol::MessageHeader::MAGIC;
        response.header.version = protocol::MessageHeader::VERSION;
        response.header.command_type = 0;
        response.header.flags = 0;
        response.header.payload_size = static_cast<uint32_t>(payload.size());
        response.header.checksum = protocol::CalculateCRC32(payload.data(), payload.size());
        response.status = protocol::ResponseStatus::SUCCESS;
        response.payload = payload;

        auto data = response.Serialize();
        send(client_fd, data.data(), data.size(), 0);
    }

    void SendErrorResponse(int client_fd, protocol::ResponseStatus status) {
        protocol::Response response;
        response.header.magic = protocol::MessageHeader::MAGIC;
        response.header.version = protocol::MessageHeader::VERSION;
        response.header.command_type = 0;
        response.header.flags = 0;
        response.header.payload_size = 0;
        response.header.checksum = 0;
        response.status = status;

        auto data = response.Serialize();
        send(client_fd, data.data(), data.size(), 0);
    }

    std::unique_ptr<Enclave> enclave_;
    int socket_fd_;
    bool running_;
};

// Global server instance for signal handler
static EnclaveServer* g_server = nullptr;

void signal_handler(int signum) {
    (void)signum;
    if (g_server) {
        g_server->Shutdown();
    }
}

} // namespace server
} // namespace openenclave

int main() {
    using namespace openenclave::server;

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Create and initialize server
    EnclaveServer server;
    g_server = &server;

    if (!server.Initialize()) {
        std::cerr << "Failed to initialize server" << std::endl;
        return 1;
    }

    // Run server
    server.Run();

    g_server = nullptr;
    return 0;
}
