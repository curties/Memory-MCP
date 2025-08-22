[![CMake on a single platform](https://github.com/kkkeeetttx/Memory-MCP/actions/workflows/cmake.yml/badge.svg)](https://github.com/kkkeeetttx/Memory-MCP/actions/workflows/cmake.yml)

# Memory MCP

A high-performance C++ MCP (Model Context Protocol) server for real-time memory scanning and analysis of Windows processes.

## Overview

Memory MCP provides direct access to process memory through the Model Context Protocol, enabling AI assistants to scan, filter, and analyze memory contents in real-time. Built with modern C++ and optimized for Windows, it offers low-latency memory operations with minimal resource overhead.

## Features

- **Real-time Memory Scanning**: Scan process memory for specific values (strings, integers, doubles)
- **Address Filtering**: Filter memory addresses based on value changes
- **Process Management**: Automatic process discovery and memory access
- **MCP Protocol**: Native MCP server implementation via stdin/stdout
- **HTTP API**: Alternative HTTP interface for external integrations
- **Windows Optimized**: Built specifically for Windows with native API calls


## Prerequisites

- **A PC and basic technical knowledge** (recommended)
- **CMake 3.16+**
- **Administrator privileges**

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/kkkeeetttx/Memory-MCP
cd Memory-MCP
```

### 2. Build Project
```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

### 3. Verify Installation
The executable will be located at:
```
build/exe/memory-mcp-server.exe
```

## Usage

### MCP Mode (Recommended for AI Assistants)

Run the server in MCP mode for direct integration with AI tools:

```bash
memory-mcp-server.exe --mcp
```

This mode communicates via stdin/stdout using the MCP protocol, making it ideal for integration with AI assistants like Cursor.

### HTTP Mode

Run the server as an HTTP server for external integrations:

```bash
memory-mcp-server.exe
```

The server will start on port 3000 and provide REST API endpoints.

## MCP Tools

The server provides the following MCP tools:

### 1. `scan_memory`
Scans process memory for a specific value.

**Parameters:**
- `process_name` (string): Name of the target process
- `value` (string): Value to search for
- `value_type` (string): Type of value ("string", "int", "double")

**Returns:**
- `count` (integer): Number of addresses found
- `addresses` (array): List of memory addresses

### 2. `get_addresses`
Retrieves previously found memory addresses.

**Parameters:**
- `max_count` (integer): Maximum number of addresses to return

**Returns:**
- `addresses` (array): List of memory addresses

### 3. `filter_addresses`
Filters addresses based on value changes.

**Parameters:**
- `addresses` (array): List of addresses to filter
- `new_value` (string): New value to search for
- `value_type` (string): Type of value

**Returns:**
- `filtered_addresses` (array): List of addresses that still contain the value

### 4. `reset_memory_scanner`
Resets the memory scanner state.

**Parameters:** None

**Returns:** Success status

## HTTP API Endpoints

### POST `/mcp`
Initialize MCP connection.

### GET `/tools/list`
List available MCP tools.

### POST `/tools/call`
Execute MCP tool calls.

## Configuration

### MCP Integration

Add to your MCP configuration (`~/mcp.json`):

```json
{
    "mcpServers": {
        "Memory_MCP": {
            "command": "C:/path/to/memory-mcp-server.exe",
            "args": ["--mcp"]
        }
    }
}
```

## Security Considerations

- **Process Isolation**: Only scan trusted processes
- **Memory Protection**: Respect Windows memory protection mechanisms
- **Resource Limits**: Monitor memory usage during large scans

## Performance

- **Scan Speed**: Optimized for real-time scanning of large memory regions
- **Memory Usage**: Minimal overhead with efficient address tracking
- **CPU Usage**: Non-blocking operations with configurable scan intervals

## Troubleshooting

### Common Issues

1. **"Access Denied" Errors**
   - Ensure running with administrator privileges
   - Check if target process is protected

2. **Build Failures**
   - Verify Visual Studio C++ tools are installed
   - Ensure CMake version is 3.16 or higher

3. **MCP Connection Issues**
   - Check executable path in MCP configuration
   - Verify `--mcp` argument is provided

### Debug Mode

Build with debug configuration for detailed logging:

```bash
cmake --build . --config Debug
```

## Development

### Building from Source

1. **Dependencies**: Header-only libraries (nlohmann/json, httplib)
2. **Compiler**: MSVC with C++17 support
3. **Build System**: CMake 3.16+

### Code Structure

- **MemoryScanner**: Core memory scanning logic
- **HttpServer**: HTTP API implementation
- **MCP Protocol**: Native MCP server implementation

## License

[GPL-3.0 License](LICENSE)

## Project Status

**This is the first stable release (v1.0.0) of Memory MCP Server.** 

The project is actively maintained and will receive regular updates with new features, performance improvements, and bug fixes.

### Upcoming Features (Roadmap)

- **Enhanced Memory Analysis**: Pattern recognition and memory structure analysis
- **Cross-Platform Support**: Linux and macOS compatibility
- **Advanced Filtering**: Regex-based memory search and multi-value filtering
- **Performance Monitoring**: Built-in benchmarks and optimization tools
- **Plugin System**: Extensible architecture for custom memory scanners
- **Web Dashboard**: Real-time memory monitoring interface
- **Memory Dumping**: Export memory regions for external analysis
- **Process Injection Detection**: Security-focused memory scanning features

### Version History

- **v1.0.0** (Current): Core MCP server with basic memory scanning capabilities
- **v1.1.0** (Planned): Enhanced filtering and performance optimizations
- **v1.2.0** (Planned): Advanced memory analysis tools
- **v1.3.0** (Planned): Python/NodeJS integration
- **v2.0.0** (Future): Major architecture improvements

### Contributing

Contributions are welcome! Whether it's bug reports, feature requests, code improvements, or documentation updates - every contribution helps make Memory MCP Server better.

## Special Thanks

[nlohmann/json](https://github.com/nlohmann/json)

[cpp-httplib](https://github.com/yhirose/cpp-httplib)

[Postman](https://www.postman.com/)