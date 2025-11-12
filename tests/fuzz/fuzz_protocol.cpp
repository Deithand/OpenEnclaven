#include "openenclave/protocol.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>

using namespace openenclave::protocol;

// LibFuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Skip inputs that are too small
    if (size < 16) {
        return 0;
    }

    // Create input vector
    std::vector<uint8_t> input(data, data + size);

    // Test 1: MessageHeader deserialization
    {
        MessageHeader header;
        MessageHeader::Deserialize(input, header);
    }

    // Test 2: Request deserialization
    {
        Request request;
        Request::Deserialize(input, request);

        // If deserialization succeeds, try validation
        if (request.header.magic == MessageHeader::MAGIC &&
            request.header.version == MessageHeader::VERSION) {
            ValidateMessage(request);
        }
    }

    // Test 3: Response deserialization
    if (size >= 17) {
        Response response;
        Response::Deserialize(input, response);

        // If deserialization succeeds, try validation
        if (response.header.magic == MessageHeader::MAGIC &&
            response.header.version == MessageHeader::VERSION) {
            ValidateMessage(response);
        }
    }

    // Test 4: LoadModuleRequest deserialization
    {
        LoadModuleRequest req;
        LoadModuleRequest::Deserialize(input, req);
    }

    // Test 5: LoadModuleResponse deserialization
    if (size >= 8) {
        LoadModuleResponse resp;
        LoadModuleResponse::Deserialize(input, resp);
    }

    // Test 6: InvokeFunctionRequest deserialization
    {
        InvokeFunctionRequest req;
        InvokeFunctionRequest::Deserialize(input, req);
    }

    // Test 7: StoreDataRequest deserialization
    {
        StoreDataRequest req;
        StoreDataRequest::Deserialize(input, req);
    }

    // Test 8: RetrieveDataRequest deserialization
    {
        RetrieveDataRequest req;
        RetrieveDataRequest::Deserialize(input, req);
    }

    // Test 9: CRC32 calculation (should never crash)
    {
        CalculateCRC32(data, size);
    }

    return 0;
}
