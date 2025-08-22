cmake_minimum_required(VERSION 3.16)
project(MemoryMCPServer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/exe)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/exe)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/exe)

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

set(SOURCES
    src/main.cpp
    src/memory_scanner.cpp
    src/http_server.cpp
)

set(HEADERS
    include/memory_scanner.h
    include/http_server.h
    include/types.h
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

target_include_directories(${PROJECT_NAME} PRIVATE 
    include
    ext/json/include
    ext/http
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME} 
        ws2_32
        psapi
        advapi32
        kernel32
        user32
    )
endif()

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:${PROJECT_NAME}>
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "memory-mcp-server"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/exe"
)

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Output directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "C++ compiler: ${CMAKE_CXX_COMPILER_ID}") 
