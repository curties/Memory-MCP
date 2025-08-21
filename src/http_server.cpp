#include "http_server.h"
#include "memory_scanner.h"
#include <httplib.h>
#include <iostream>
#include <nlohmann/json.hpp>

using namespace httplib;
using json = nlohmann::json;

namespace MemoryMCP {

HttpServer::HttpServer(uint16_t port) : port_(port) {
    server_ = std::make_unique<Server>();
}

HttpServer::~HttpServer() {
    stop();
    std::cerr << "[INFO] HTTP server stopped" << std::endl;
}

void HttpServer::setup_routes() {
    std::cerr << "[INFO] Setting up HTTP server routes..." << std::endl;

    server_->set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"}
    });

    server_->Post("/scan", [this](const Request& req, Response& res) {
        std::cerr << "[INFO] Registering route POST /scan" << std::endl;
        handle_scan(req, res);
    });

    server_->Get("/addresses", [this](const Request& req, Response& res) {
        handle_get_addresses(req, res);
    });

    server_->Post("/filter", [this](const Request& req, Response& res) {
        handle_filter(req, res);
    });

    server_->Post("/reset", [this](const Request& req, Response& res) {
        handle_reset(req, res);
    });

    server_->Get("/mcp", [this](const Request& req, Response& res) {
        std::cerr << "[INFO] Registering route GET /mcp" << std::endl;
        handle_mcp(req, res);
    });

    server_->Post("/tools/call", [this](const Request& req, Response& res) {
        std::cerr << "[INFO] Registering route POST /tools/call" << std::endl;
        handle_mcp_tools_call(req, res);
    });

    server_->Get("/tools/list", [this](const Request& req, Response& res) {
        std::cerr << "[INFO] Registering route GET /tools/list" << std::endl;
        handle_mcp_tools_list(req, res);
    });

    server_->Options(".*", [this](const Request& req, Response& res) {
        handle_cors(req, res);
    });
}

bool HttpServer::start() {
    if (!server_) {
        return false;
    }

    setup_routes();
    scanner_ = std::make_unique<MemoryScanner>();

    return server_->listen("0.0.0.0", port_);
}

void HttpServer::stop() {
    if (server_) {
        server_->stop();
    }
}

void HttpServer::handle_scan(const Request& req, Response& res) {
    std::cerr << "[INFO] Processing scan request" << std::endl;

    try {
        json request_body = json::parse(req.body);
        
        std::string process_name = request_body["process_name"];
        std::string value = request_body["value"];
        std::string type_str = request_body["value_type"];
        
        ValueType value_type = MemoryMCP::string_to_value_type(type_str);
        
        std::cerr << "[INFO] Process: " << process_name << std::endl;
        std::cerr << "[INFO] Value: " << value << std::endl;
        std::cerr << "[INFO] Type: " << MemoryMCP::value_type_to_string(value_type) << std::endl;
        
        ScanResponse scan_response = scanner_->scan_memory(process_name, value, value_type);
        
        json response;
        response["success"] = scan_response.success;
        response["count"] = scan_response.count;
        response["message"] = scan_response.message;
        
        if (scan_response.success) {
            json addresses_array = json::array();
            for (const auto& addr : scan_response.addresses) {
                json addr_obj;
                addr_obj["address"] = "0x" + std::to_string(addr.address);
                addr_obj["value"] = addr.value;
                addr_obj["type"] = MemoryMCP::value_type_to_string(addr.type);
                addresses_array.push_back(addr_obj);
            }
            response["addresses"] = addresses_array;
        }
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        json error_response;
        error_response["success"] = false;
        error_response["message"] = "Error: " + std::string(e.what());
        res.set_content(error_response.dump(), "application/json");
    }
}

void HttpServer::handle_get_addresses(const Request& req, Response& res) {
    std::cerr << "[INFO] Processing get addresses request" << std::endl;

    try {
        size_t max_count = 100;
        if (req.has_param("max_count")) {
            max_count = std::stoul(req.get_param_value("max_count"));
        }
        
        AddressesResponse addr_response = scanner_->get_addresses(max_count);
        
        json response;
        response["success"] = addr_response.success;
        response["count"] = addr_response.count;
        response["message"] = addr_response.message;
        response["addresses"] = addr_response.addresses;
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        json error_response;
        error_response["success"] = false;
        error_response["message"] = "Error: " + std::string(e.what());
        res.set_content(error_response.dump(), "application/json");
    }
}

void HttpServer::handle_filter(const Request& req, Response& res) {
    std::cerr << "[INFO] Processing filter request" << std::endl;

    try {
        json request_body = json::parse(req.body);
        
        std::vector<std::string> addresses = request_body["addresses"];
        std::string new_value = request_body["new_value"];
        std::string type_str = request_body["value_type"];
        
        ValueType value_type = MemoryMCP::string_to_value_type(type_str);
        FilterResponse filter_response = scanner_->filter_addresses(addresses, new_value, value_type);
        
        json response;
        response["success"] = filter_response.success;
        response["count"] = filter_response.count;
        response["message"] = filter_response.message;
        
        if (filter_response.success) {
            json addresses_array = json::array();
            for (const auto& addr : filter_response.addresses) {
                json addr_obj;
                addr_obj["address"] = "0x" + std::to_string(addr.address);
                addr_obj["value"] = addr.value;
                addr_obj["type"] = MemoryMCP::value_type_to_string(addr.type);
                addresses_array.push_back(addr_obj);
            }
            response["addresses"] = addresses_array;
        }
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        json error_response;
        error_response["success"] = false;
        error_response["message"] = "Error: " + std::string(e.what());
        res.set_content(error_response.dump(), "application/json");
    }
}

void HttpServer::handle_reset(const Request&, Response& res) {
    std::cerr << "[INFO] Processing reset request" << std::endl;

    try {
        ResetResponse reset_response = scanner_->reset();
        
        json response;
        response["success"] = reset_response.success;
        response["message"] = reset_response.message;
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        json error_response;
        error_response["success"] = false;
        error_response["message"] = "Error: " + std::string(e.what());
        res.set_content(error_response.dump(), "application/json");
    }
}

void HttpServer::handle_mcp(const Request&, Response& res) {
    std::cerr << "[INFO] Processing MCP metadata request" << std::endl;

    try {
        json response;
        response["jsonrpc"] = "2.0";
        response["result"] = {
            {"protocolVersion", "2024-11-05"},
            {"capabilities", {
                {"tools", {{"listChanged", false}}}
            }},
            {"serverInfo", {
                {"name", "memory-mcp-server"},
                {"version", "1.0.0"}
            }}
        };
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        json error_response;
        error_response["jsonrpc"] = "2.0";
        error_response["error"] = {
            {"code", -32700},
            {"message", "Parse error: " + std::string(e.what())}
        };
        res.set_content(error_response.dump(), "application/json");
    }
}

void HttpServer::handle_mcp_tools_call(const Request& req, Response& res) {
    std::cerr << "[INFO] Processing MCP tools call request" << std::endl;

    try {
        json request_body = json::parse(req.body);
        json params = request_body["params"];
        std::string name = params["name"];
        json arguments = params["arguments"];

        json response;
        response["jsonrpc"] = "2.0";
        response["id"] = request_body.value("id", nullptr);

        if (name == "scan_memory") {
            std::string process_name = arguments["process_name"];
            std::string value = arguments["value"];
            std::string type_str = arguments["value_type"];

            ValueType value_type = MemoryMCP::string_to_value_type(type_str);
            ScanResponse scan_response = scanner_->scan_memory(process_name, value, value_type);

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
            AddressesResponse addr_response = scanner_->get_addresses(max_count);

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

            ValueType value_type = MemoryMCP::string_to_value_type(type_str);
            FilterResponse filter_response = scanner_->filter_addresses(addresses, new_value, value_type);

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
            ResetResponse reset_response = scanner_->reset();

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
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        json error_response;
        error_response["jsonrpc"] = "2.0";
        error_response["error"] = {
            {"code", -32700},
            {"message", "Parse error: " + std::string(e.what())}
        };
        res.set_content(error_response.dump(), "application/json");
    }
}

void HttpServer::handle_mcp_tools_list(const Request&, Response& res) {
    std::cerr << "[INFO] Processing MCP tools list request" << std::endl;

    try {
        json response;
        response["jsonrpc"] = "2.0";
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
        
        res.set_content(response.dump(), "application/json");
        
    } catch (const std::exception& e) {
        json error_response;
        error_response["jsonrpc"] = "2.0";
        error_response["error"] = {
            {"code", -32700},
            {"message", "Parse error: " + std::string(e.what())}
        };
        res.set_content(error_response.dump(), "application/json");
    }
}

void HttpServer::handle_cors(const Request&, Response& res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Content-Type");
    res.status = 200;
}

} // namespace MemoryMCP 