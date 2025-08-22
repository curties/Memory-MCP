cmake_minimum_required(VERSION 3.16)
project(MemoryMCPServer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

file(GLOB_RECURSE SOURCES src/*.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/memory
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server
    ext/json/include
    ext/http
)

add_subdirectory(ext/json)
add_subdirectory(ext/cpp-httplib)

if(WIN32)
    target_link_libraries(${PROJECT_NAME} 
        ws2_32
        psapi
        advapi32
        kernel32
        user32
        nlohmann_json::nlohmann_json
        httplib::httplib
    )
else()
    target_link_libraries(${PROJECT_NAME} 
        nlohmann_json::nlohmann_json
        httplib::httplib
    )
endif()


set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "memory-mcp-server"
)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Output directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "C++ compiler: ${CMAKE_CXX_COMPILER_ID}") 
