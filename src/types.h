#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <windows.h>
#else
// Linux/macOS alternatives
#include <sys/types.h>
#include <cstddef>
typedef size_t SIZE_T;
typedef void* HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned char BYTE;
#define FALSE 0
#define TRUE 1
#endif

using json = nlohmann::json;

namespace MemoryMCP {

constexpr size_t MAX_REGIONS = 1000;
constexpr size_t MAX_REGION_SIZE = 1024 * 1024;
constexpr size_t BUFFER_SIZE = 4096;

enum class ValueType {
    STRING,
    INT,
    INT32,
    INT64,
    FLOAT,
    FLOAT32,
    FLOAT64
};

struct MemoryAddress {
    uintptr_t address;
    std::string value;
    ValueType type;
    
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(MemoryAddress, address, value, type)
};

struct ScanRequest {
    std::string process_name;
    std::string value;
    ValueType value_type;
    
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ScanRequest, process_name, value, value_type)
};

struct ScanResponse {
    std::vector<MemoryAddress> addresses;
    size_t count;
    std::string message;
    bool success;
    
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ScanResponse, addresses, count, message, success)
};

struct AddressesRequest {
    size_t max_count;
    
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(AddressesRequest, max_count)
};

struct AddressesResponse {
    std::vector<std::string> addresses;
    size_t count;
    std::string message;
    bool success;
    
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(AddressesResponse, addresses, count, message, success)
};

struct FilterRequest {
    std::vector<std::string> addresses;
    std::string new_value;
    ValueType value_type;
    
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(FilterRequest, addresses, new_value, value_type)
};

struct FilterResponse {
    std::vector<MemoryAddress> addresses;
    size_t count;
    std::string message;
    bool success;
    
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(FilterResponse, addresses, count, message, success)
};

struct ResetResponse {
    std::string message;
    bool success;
    
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(ResetResponse, message, success)
};

struct EndpointInfo {
    std::string path;
    std::string method;
    std::string description;
    std::string request_body;
    std::string response_body;
    
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(EndpointInfo, path, method, description, request_body, response_body)
};

struct McpResponse {
    std::string name;
    std::string version;
    std::string description;
    std::vector<EndpointInfo> endpoints;
    std::vector<std::string> supported_types;
    
    NLOHMANN_DEFINE_TYPE_INTRUSIVE(McpResponse, name, version, description, endpoints, supported_types)
};

inline std::string value_type_to_string(ValueType type) {
    switch (type) {
        case ValueType::STRING: return "string";
        case ValueType::INT: return "int";
        case ValueType::INT32: return "int32";
        case ValueType::INT64: return "int64";
        case ValueType::FLOAT: return "float";
        case ValueType::FLOAT32: return "float32";
        case ValueType::FLOAT64: return "float64";
        default: return "unknown";
    }
}

inline ValueType string_to_value_type(const std::string& type_str) {
    if (type_str == "string") return ValueType::STRING;
    if (type_str == "int") return ValueType::INT;
    if (type_str == "int32") return ValueType::INT32;
    if (type_str == "int64") return ValueType::INT64;
    if (type_str == "float") return ValueType::FLOAT;
    if (type_str == "float32") return ValueType::FLOAT32;
    if (type_str == "float64") return ValueType::FLOAT64;
    return ValueType::STRING;
}

NLOHMANN_JSON_SERIALIZE_ENUM(ValueType, {
    {ValueType::STRING, "string"},
    {ValueType::INT, "int"},
    {ValueType::INT32, "int32"},
    {ValueType::INT64, "int64"},
    {ValueType::FLOAT, "float"},
    {ValueType::FLOAT32, "float32"},
    {ValueType::FLOAT64, "float64"}
})

inline std::wstring string_to_wstring(const std::string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.length(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.length(), &wstrTo[0], size_needed);
    return wstrTo;
}

inline std::string wstring_to_string(const std::wstring& wstr) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

} // namespace MemoryMCP 