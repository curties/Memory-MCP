#pragma once
#include "types.h"
#include <windows.h>
#include <vector>
#include <string>
#include <memory>
#include <mutex>

namespace MemoryMCP {

class MemoryScanner {
public:
    MemoryScanner();
    ~MemoryScanner();

    ScanResponse scan_memory(const std::string& process_name, const std::string& value, ValueType value_type);
    AddressesResponse get_addresses(size_t max_count = 100);
    FilterResponse filter_addresses(const std::vector<std::string>& addresses, const std::string& new_value, ValueType value_type);
    ResetResponse reset();

private:
    DWORD find_process_by_name(const std::string& process_name);
    HANDLE open_process(DWORD process_id);
    std::string get_process_name(DWORD process_id);
    std::vector<MemoryAddress> scan_memory_region(HANDLE process_handle, uintptr_t base_address, 
                                                 const std::string& search_value, ValueType value_type);
    std::vector<uintptr_t> get_memory_regions(HANDLE process_handle);
    bool is_readable_memory(const MEMORY_BASIC_INFORMATION& mbi);
    
    std::string value_type_to_string(ValueType type);
    ValueType string_to_value_type(const std::string& type_str);
    std::vector<uint8_t> value_to_bytes(const std::string& value, ValueType type);
    bool compare_memory(const uint8_t* buffer, const std::vector<uint8_t>& target, ValueType type);

    std::vector<MemoryAddress> found_addresses_;
    std::mutex addresses_mutex_;
    
    static constexpr size_t BUFFER_SIZE = 4096;
    static constexpr size_t MAX_REGIONS = 1000;
};

} // namespace MemoryMCP rot'ebal de pari