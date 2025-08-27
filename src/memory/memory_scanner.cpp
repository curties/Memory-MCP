#include "memory_scanner.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <fmt/base.h>

#pragma comment(lib, "psapi.lib")

using namespace MemoryMCP;

MemoryScanner::MemoryScanner() {
    fmt::print(stderr, "[INFO] Memory Scanner initialized\n");
}

MemoryScanner::~MemoryScanner() {
    fmt::print(stderr, "[INFO] Memory Scanner shutting down\n");
}

ScanResponse MemoryScanner::scan_memory(const std::string& process_name, const std::string& value, ValueType value_type) {
    fmt::print(stderr, "[INFO] Starting memory scan...\n");
    fmt::print(stderr, "[INFO] Process: {}\n", process_name);
    fmt::print(stderr, "[INFO] Searching for: {} (type: {})\n", value, value_type_to_string(value_type));

    
    ScanResponse response;
    response.success = false;
    response.count = 0;
    
    try {
        DWORD process_id = find_process_by_name(process_name);
        if (process_id == 0) {
            response.message = "Process not found: " + process_name;
            fmt::print(stderr, "[ERROR] {}\n", response.message);
            return response;
        }
        
        fmt::print(stderr, "[SUCCESS] Process found, PID: {}\n", process_id);
        
        HANDLE process_handle = open_process(process_id);
        if (process_handle == NULL) {
            response.message = "Failed to open process";
            fmt::print(stderr, "[ERROR] {}\n", response.message);
            return response;
        }
        
        fmt::print(stderr, "[SUCCESS] Process opened, handle: {}\n", process_handle);
        
        std::vector<uintptr_t> memory_regions = get_memory_regions(process_handle);
        fmt::print(stderr, "[INFO] Found {} memory regions\n", memory_regions.size());
        
        std::vector<MemoryAddress> all_found;
        size_t scanned_regions = 0;
        
        for (uintptr_t region : memory_regions) {
            if (scanned_regions >= MAX_REGIONS) {
                fmt::print(stderr, "[WARNING] Reached region limit ({})\n", MAX_REGIONS);
                break;
            }
            
            std::vector<MemoryAddress> region_results = scan_memory_region(process_handle, region, value, value_type);
            if (!region_results.empty()) {
                all_found.insert(all_found.end(), region_results.begin(), region_results.end());
                fmt::print(stderr, "[INFO] In region 0x{:x} found {} matches\n", region, region_results.size());
            }
            
            scanned_regions++;
        }
        
        {
            std::lock_guard<std::mutex> lock(addresses_mutex_);
            found_addresses_ = all_found;
        }
        
        response.addresses = all_found;
        response.count = all_found.size();
        response.success = true;
        response.message = "Scan completed. Found " + std::to_string(all_found.size()) + " matches";
        
        fmt::print(stderr, "[SUCCESS] Scan completed!\n");
        fmt::print(stderr, "[INFO] Result: {} matches\n", all_found.size());
        
        CloseHandle(process_handle);
        
    } catch (const std::exception& e) {
        response.message = "Scan error: " + std::string(e.what());
        fmt::print(stderr, "[ERROR] {}\n", response.message);
    }
    
    return response;
}

AddressesResponse MemoryScanner::get_addresses(size_t max_count) {
    AddressesResponse response;
    response.success = false;
    
    try {
        std::lock_guard<std::mutex> lock(addresses_mutex_);
        
        size_t count = (std::min)(found_addresses_.size(), max_count);
        response.count = count;
        response.success = true;
        
        for (size_t i = 0; i < count; ++i) {
            std::stringstream ss;
            ss << "0x" << std::hex << std::uppercase << found_addresses_[i].address;
            response.addresses.push_back(ss.str());
        }
        
        response.message = "Retrieved " + std::to_string(count) + " addresses";
        
    } catch (const std::exception& e) {
        response.message = "Error getting addresses: " + std::string(e.what());
    }
    
    return response;
}

FilterResponse MemoryScanner::filter_addresses(const std::vector<std::string>& addresses, const std::string& new_value, ValueType value_type) {
    fmt::print(stderr, "[INFO] Filtering {} addresses...\n", addresses.size());
    fmt::print(stderr, "[INFO] New value: {}\n", new_value);
    
    FilterResponse response;
    response.success = false;

    try {
        std::lock_guard<std::mutex> lock(addresses_mutex_);
        
        std::vector<MemoryAddress> filtered;
        
        for (const auto& addr_str : addresses) {
            uintptr_t address;
            std::stringstream ss(addr_str);
            ss >> std::hex >> address;
            
            for (const auto& found : found_addresses_) {
                if (found.address == address) {
                    MemoryAddress new_addr = found;
                    new_addr.value = new_value;
                    new_addr.type = value_type;
                    filtered.push_back(new_addr);
                    break;
                }
            }
        }
        
        response.addresses = filtered;
        response.count = filtered.size();
        response.success = true;
        response.message = "Filtering completed. Found " + std::to_string(filtered.size()) + " addresses";
        
        fmt::print(stderr, "[SUCCESS] Filtering completed: {} addresses\n", filtered.size());
        
    } catch (const std::exception& e) {
        response.message = "Filtering error: " + std::string(e.what());
        fmt::print(stderr, "[ERROR] {}\n", response.message);
    }
    
    return response;
}

ResetResponse MemoryScanner::reset() {
    ResetResponse response;
    
    try {
        std::lock_guard<std::mutex> lock(addresses_mutex_);
        found_addresses_.clear();
        
        response.success = true;
        response.message = "Scanner reset";
        
        fmt::print(stderr, "[INFO] Memory Scanner reset\n");
        
    } catch (const std::exception& e) {
        response.success = false;
        response.message = "Reset error: " + std::string(e.what());
        fmt::print(stderr, "[ERROR] {}\n", response.message);
    }
    
    return response;
}

DWORD MemoryScanner::find_process_by_name(const std::string& process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fmt::print(stderr, "[ERROR] Failed to create process snapshot\n");
        return 0;
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    if (!Process32FirstW(snapshot, &pe32)) {
        fmt::print(stderr, "[ERROR] Failed to get first process\n");
        CloseHandle(snapshot);
        return 0;
    }
    
    do {
        std::wstring wname(pe32.szExeFile);
        std::string name = wstring_to_string(wname);
        
        if (name == process_name) {
            fmt::print(stderr, "[SUCCESS] Process found: {} (PID: {})\n", name, pe32.th32ProcessID);
            CloseHandle(snapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32NextW(snapshot, &pe32));
    
    fmt::print(stderr, "[ERROR] Process not found: {}\n", process_name);
    CloseHandle(snapshot);
    return 0;
}

HANDLE MemoryScanner::open_process(DWORD process_id) {
    HANDLE handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        process_id
    );
    
    if (handle == NULL) {
        fmt::print(stderr, "[ERROR] Failed to open process PID {}\n", process_id);
        fmt::print(stderr, "[INFO] Error code: {}\n", GetLastError());
        return NULL;
    }
    
    return handle;
}

std::vector<uintptr_t> MemoryScanner::get_memory_regions(HANDLE process_handle) {
    std::vector<uintptr_t> regions;
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = 0;
    
    while (VirtualQueryEx(process_handle, (LPCVOID)address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect == PAGE_READWRITE || 
             mbi.Protect == PAGE_READONLY || 
             mbi.Protect == PAGE_EXECUTE_READ || 
             mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            regions.push_back((uintptr_t)mbi.BaseAddress);
        }
        
        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        
        if (address == 0) break;
    }
    
    return regions;
}

std::vector<MemoryAddress> MemoryScanner::scan_memory_region(HANDLE process_handle, uintptr_t region_address, const std::string& value, ValueType value_type) {
    std::vector<MemoryAddress> found;
    MEMORY_BASIC_INFORMATION mbi;
    
    if (VirtualQueryEx(process_handle, (LPCVOID)region_address, &mbi, sizeof(mbi)) == 0) {
        return found;
    }
    
    if (mbi.State != MEM_COMMIT) {
        return found;
    }
    
    size_t region_size = mbi.RegionSize;
    if (region_size > MAX_REGION_SIZE) {
        region_size = MAX_REGION_SIZE;
    }
    
    std::vector<BYTE> buffer(region_size);
    SIZE_T bytes_read;
    
    if (!ReadProcessMemory(process_handle, (LPCVOID)region_address, buffer.data(), region_size, &bytes_read)) {
        return found;
    }
    
    if (value_type == ValueType::STRING) {
        for (size_t i = 0; i <= bytes_read - value.length(); ++i) {
            if (memcmp(buffer.data() + i, value.c_str(), value.length()) == 0) {
                MemoryAddress addr;
                addr.address = region_address + i;
                addr.value = value;
                addr.type = value_type;
                found.push_back(addr);
            }
        }
        
        std::wstring wide_target;
        for (char c : value) {
            wide_target += static_cast<wchar_t>(c);
        }
        
        size_t wide_size = wide_target.length() * sizeof(wchar_t);
        if (bytes_read >= wide_size) {
            for (size_t i = 0; i <= bytes_read - wide_size; ++i) {
                if (memcmp(buffer.data() + i, wide_target.c_str(), wide_size) == 0) {
                    MemoryAddress addr;
                    addr.address = region_address + i;
                    addr.value = value;
                    addr.type = value_type;
                    found.push_back(addr);
                }
            }
        }
    } else {
        for (size_t i = 0; i <= bytes_read - value.length(); ++i) {
            bool match = true;
            for (size_t j = 0; j < value.length(); ++j) {
                if (buffer[i + j] != static_cast<BYTE>(value[j])) {
                    match = false;
                    break;
                }
            }
            
            if (match) {
                MemoryAddress addr;
                addr.address = region_address + i;
                addr.value = value;
                addr.type = value_type;
                found.push_back(addr);
            }
        }
    }
    
    return found;
}

std::string MemoryScanner::value_type_to_string(ValueType type) {
    switch (type) {
        case ValueType::INT: return "int";
        case ValueType::INT32: return "int32";
        case ValueType::INT64: return "int64";
        case ValueType::FLOAT: return "float";
        case ValueType::FLOAT32: return "float32";
        case ValueType::FLOAT64: return "float64";
        case ValueType::STRING: return "string";
        default: return "unknown";
    }
} // blyadskie types