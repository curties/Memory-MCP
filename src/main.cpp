#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <csignal>
#include <memory>
#include "memory_scanner.h"
#include "http_server.h"
#include "types.h"
#include "nlohmann/json.hpp"
#include <fmt/base.h>

using json = nlohmann::json;
using namespace MemoryMCP;

std::atomic<bool> g_running{true};

void signal_handler(int /*signal*/) {
    g_running = false;
}

void run_mcp_mode() {
    auto scanner = std::make_unique<MemoryScanner>();
    std::string line;

    while (g_running && std::getline(std::cin, line)) {
        try {
            json request = json::parse(line);
            json response;
            response["jsonrpc"] = "2.0";
            
            if (request.contains("id")) {
                response["id"] = request["id"];
            }

            if (request.contains("method")) {
                std::string method = request["method"];

                if (method == "initialize") {
                    json capabilities;
                    capabilities["tools"] = {{"listChanged", false}};

                    json serverInfo;
                    serverInfo["name"] = "memory-mcp-server";
                    serverInfo["version"] = "1.0.0";

                    response["result"] = {
                        {"protocolVersion", "2024-11-05"},
                        {"capabilities", capabilities},
                        {"serverInfo", serverInfo}
                    };

                } else if (method == "tools/list") {
                    response["result"] = {
                        {"tools", json::array({
                            {
                                {"name", "scan_memory"},
                                {"description", "Scans process memory for specified value"},
                                {"inputSchema", {
                                    {"type", "object"},
                                    {"properties", {
                                        {"process_name", {{"type", "string"}, {"description", "Process name"}}},
                                        {"value", {{"type", "string"}, {"description", "Search value"}}},
                                        {"value_type", {{"type", "string"}, {"description", "Data type"}}}
                                    }},
                                    {"required", json::array({"process_name", "value", "value_type"})}
                                }}
                            },
                            {
                                {"name", "get_addresses"},
                                {"description", "Gets found memory addresses"},
                                {"inputSchema", {
                                    {"type", "object"},
                                    {"properties", {
                                        {"max_count", {{"type", "integer"}, {"description", "Maximum number of addresses"}}}
                                    }}
                                }}
                            },
                            {
                                {"name", "filter_addresses"},
                                {"description", "Filters addresses by new value"},
                                {"inputSchema", {
                                    {"type", "object"},
                                    {"properties", {
                                        {"addresses", {{"type", "array"}, {"description", "Address list"}}},
                                        {"new_value", {{"type", "string"}, {"description", "New value"}}},
                                        {"value_type", {{"type", "string"}, {"description", "Data type"}}}
                                    }},
                                    {"required", json::array({"addresses", "new_value", "value_type"})}
                                }}
                            },
                            {
                                {"name", "reset_memory_scanner"},
                                {"description", "Resets all search data"},
                                {"inputSchema", {
                                    {"type", "object"},
                                    {"properties", json::object()}
                                }}
                            }
                        })}
                    };

                } else if (method == "tools/call") {
                    json params = request["params"];
                    std::string name = params["name"];
                    json arguments = params["arguments"];

                    if (name == "scan_memory") {
                        std::string process_name = arguments["process_name"];
                        std::string value = arguments["value"];
                        std::string type_str = arguments["value_type"];

                        ValueType value_type = string_to_value_type(type_str);
                        ScanResponse scan_response = scanner->scan_memory(process_name, value, value_type);

                        response["result"] = {
                            {"content", json::array({
                                {
                                    {"type", "text"},
                                    {"text", "Scan completed. Found " + std::to_string(scan_response.count) + " addresses."}
                                }
                            })},
                            {"isError", !scan_response.success}
                        };

                    } else if (name == "get_addresses") {
                        size_t max_count = arguments.value("max_count", 100);
                        AddressesResponse addr_response = scanner->get_addresses(max_count);

                        std::string addresses_text = "Found addresses:\n";
                        for (const auto& addr : addr_response.addresses) {
                            addresses_text += addr + "\n";
                        }

                        response["result"] = {
                            {"content", json::array({
                                {
                                    {"type", "text"},
                                    {"text", addresses_text}
                                }
                            })},
                            {"isError", !addr_response.success}
                        };

                    } else if (name == "filter_addresses") {
                        std::vector<std::string> addresses = arguments["addresses"];
                        std::string new_value = arguments["new_value"];
                        std::string type_str = arguments["value_type"];

                        ValueType value_type = string_to_value_type(type_str);
                        FilterResponse filter_response = scanner->filter_addresses(addresses, new_value, value_type);

                        response["result"] = {
                            {"content", json::array({
                                {
                                    {"type", "text"},
                                    {"text", "Filtering completed. Remaining: " + std::to_string(filter_response.count) + " addresses."}
                                }
                            })},
                            {"isError", !filter_response.success}
                        };

                    } else if (name == "reset_memory_scanner") {
                        ResetResponse reset_response = scanner->reset();

                        response["result"] = {
                            {"content", json::array({
                                {
                                    {"type", "text"},
                                    {"text", reset_response.message}
                                }
                            })},
                            {"isError", !reset_response.success}
                        };
                    } else {
                        response["error"] = {
                            {"code", -32601},
                            {"message", "Unknown tool: " + name}
                        };
                    }
                } else {
                    response["error"] = {
                        {"code", -32601},
                        {"message", "Unknown method: " + method}
                    };
                }
            } else {
                response["error"] = {
                    {"code", -32600},
                    {"message", "Invalid Request"}
                };
            }

            fmt::print("{}\n", response.dump());

        } catch (const std::exception& e) {
            json error_response;
            error_response["jsonrpc"] = "2.0";
            error_response["error"] = {
                {"code", -32700},
                {"message", std::string("Parse error: ") + e.what()}
            };
            error_response["id"] = nullptr;
            fmt::print("{}\n", error_response.dump());
        }
    }
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    bool mcp_mode = false;
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--mcp") {
            mcp_mode = true;
            break;
        }
    }

    if (mcp_mode) {
        run_mcp_mode();
        return 0;
    }

    try {
        HttpServer server(3000);
        
        std::thread server_thread([&server]() {
            server.start();
        });

        fmt::print("Memory MCP Server started on port 3000\n");
        fmt::print("Press Ctrl+C to stop\n");

        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        server.stop();
        if (server_thread.joinable()) {
            server_thread.join();
        }

    } catch (const std::exception& e) {
        fmt::print("Error: {}\n", e.what());
        return 1;
    }

    return 0;
} 