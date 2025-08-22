#include <gtest/gtest.h>
#include "types.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace MemoryMCP;

class TypesTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code if needed
    }
};

TEST_F(TypesTest, MemoryAddressSerialization) {
    MemoryAddress addr;
    addr.address = 0x12345678;
    addr.value = "test_value";
    addr.type = ValueType::STRING;
    
    json j = addr;
    
    EXPECT_EQ(j["address"], 0x12345678);
    EXPECT_EQ(j["value"], "test_value");
    EXPECT_EQ(j["type"], "string");
}

TEST_F(TypesTest, MemoryAddressDeserialization) {
    json j = {
        {"address", 0x87654321},
        {"value", "deserialized_value"},
        {"type", "int"}
    };
    
    MemoryAddress addr = j.get<MemoryAddress>();
    
    EXPECT_EQ(addr.address, 0x87654321);
    EXPECT_EQ(addr.value, "deserialized_value");
    EXPECT_EQ(addr.type, ValueType::INT);
}

TEST_F(TypesTest, ScanRequestSerialization) {
    ScanRequest req;
    req.process_name = "test_process.exe";
    req.value = "123";
    req.value_type = ValueType::INT;
    
    json j = req;
    
    EXPECT_EQ(j["process_name"], "test_process.exe");
    EXPECT_EQ(j["value"], "123");
    EXPECT_EQ(j["value_type"], "int");
}

TEST_F(TypesTest, ScanResponseSerialization) {
    ScanResponse resp;
    resp.addresses = {
        {0x1000, "value1", ValueType::STRING},
        {0x2000, "value2", ValueType::INT}
    };
    resp.count = 2;
    resp.message = "Scan completed";
    resp.success = true;
    
    json j = resp;
    
    EXPECT_EQ(j["count"], 2);
    EXPECT_EQ(j["message"], "Scan completed");
    EXPECT_EQ(j["success"], true);
    EXPECT_EQ(j["addresses"].size(), 2);
}

TEST_F(TypesTest, ValueTypeConversion) {
    EXPECT_EQ(value_type_to_string(ValueType::STRING), "string");
    EXPECT_EQ(value_type_to_string(ValueType::INT), "int");
    EXPECT_EQ(value_type_to_string(ValueType::FLOAT), "float");
    
    EXPECT_EQ(string_to_value_type("string"), ValueType::STRING);
    EXPECT_EQ(string_to_value_type("int"), ValueType::INT);
    EXPECT_EQ(string_to_value_type("float"), ValueType::FLOAT);
}

TEST_F(TypesTest, Constants) {
    EXPECT_EQ(MAX_REGIONS, 1000);
    EXPECT_EQ(MAX_REGION_SIZE, 1024 * 1024);
    EXPECT_EQ(BUFFER_SIZE, 4096);
}
