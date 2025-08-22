#pragma once
#include "types.h"
#include <memory>
#include <string>
#include <atomic>

namespace httplib {
    class Server;
    struct Request;
    struct Response;
}

namespace MemoryMCP {
    class MemoryScanner;

class HttpServer {
public:
    HttpServer(uint16_t port = 3000);
    ~HttpServer();

    bool start();
    void stop();

private:
    void setup_routes();
    
    void handle_scan(const httplib::Request& req, httplib::Response& res);
    void handle_get_addresses(const httplib::Request& req, httplib::Response& res);
    void handle_filter(const httplib::Request& req, httplib::Response& res);
    void handle_reset(const httplib::Request& req, httplib::Response& res);
    void handle_mcp(const httplib::Request& req, httplib::Response& res);
    void handle_mcp_tools_call(const httplib::Request& req, httplib::Response& res);
    void handle_mcp_tools_list(const httplib::Request& req, httplib::Response& res);
    void handle_cors(const httplib::Request& req, httplib::Response& res);

    uint16_t port_;
    std::unique_ptr<httplib::Server> server_;
    std::unique_ptr<MemoryScanner> scanner_;
};

} // namespace MemoryMCP 