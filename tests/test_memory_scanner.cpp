#include <gtest/gtest.h>
#include "memory/memory_scanner.h"
#include <memory>

using namespace MemoryMCP;

class MemoryScannerTest : public ::testing::Test {
protected:
    void SetUp() override {
        scanner = std::make_unique<MemoryScanner>();
    }
    
    void TearDown() override {
        scanner.reset();
    }
    
    std::unique_ptr<MemoryScanner> scanner;
};

TEST_F(MemoryScannerTest, Constructor) {
    EXPECT_NE(scanner, nullptr);
}

TEST_F(MemoryScannerTest, ResetInitialState) {
    ResetResponse resp = scanner->reset();
    EXPECT_TRUE(resp.success);
    EXPECT_FALSE(resp.message.empty());
}

TEST_F(MemoryScannerTest, GetAddressesEmpty) {
    AddressesResponse resp = scanner->get_addresses(10);
    EXPECT_EQ(resp.count, 0);
    EXPECT_TRUE(resp.addresses.empty());
    EXPECT_TRUE(resp.success);
}

TEST_F(MemoryScannerTest, FilterAddressesEmpty) {
    std::vector<std::string> addresses = {"0x1000", "0x2000"};
    FilterResponse resp = scanner->filter_addresses(addresses, "new_value", ValueType::STRING);
    EXPECT_EQ(resp.count, 0);
    EXPECT_TRUE(resp.addresses.empty());
    EXPECT_TRUE(resp.success);
}

TEST_F(MemoryScannerTest, ScanMemoryInvalidProcess) {
    // Test with non-existent process
    ScanResponse resp = scanner->scan_memory("non_existent_process.exe", "test", ValueType::STRING);
    EXPECT_FALSE(resp.success);
    EXPECT_EQ(resp.count, 0);
    EXPECT_TRUE(resp.addresses.empty());
    EXPECT_FALSE(resp.message.empty());
}

// Note: value_type_to_string and string_to_value_type are private methods
// These tests would need the methods to be made public or use friend class

TEST_F(MemoryScannerTest, MemoryScannerLifetime) {
    // Test that scanner can be destroyed and recreated
    scanner.reset();
    scanner = std::make_unique<MemoryScanner>();
    EXPECT_NE(scanner, nullptr);
    
    ResetResponse resp = scanner->reset();
    EXPECT_TRUE(resp.success);
}
