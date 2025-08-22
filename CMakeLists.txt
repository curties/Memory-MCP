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
add_subdirectory(ext/fmt)

if(WIN32)
    target_link_libraries(${PROJECT_NAME} 
        ws2_32
        psapi
        advapi32
        kernel32
        user32
        nlohmann_json::nlohmann_json
        httplib::httplib
        fmt::fmt
    )
else()
    target_link_libraries(${PROJECT_NAME} 
        nlohmann_json::nlohmann_json
        httplib::httplib
        fmt::fmt
    )
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "memory-mcp-server"
)

# Testing
option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING)
    enable_testing()
    
    # Fetch Google Test
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG release-1.12.1
    )
    FetchContent_MakeAvailable(googletest)
    
    # Add test executable
    add_executable(${PROJECT_NAME}_tests 
        tests/test_main.cpp
        tests/test_memory_scanner.cpp
        tests/test_types.cpp
        src/memory/memory_scanner.cpp
        src/server/http_server.cpp
    )
    
    target_include_directories(${PROJECT_NAME}_tests PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/memory
        ${CMAKE_CURRENT_SOURCE_DIR}/src/server
        ext/json/include
        ext/http
    )
    
    target_link_libraries(${PROJECT_NAME}_tests 
        nlohmann_json::nlohmann_json
        gtest
        gtest_main
    )
    
    if(WIN32)
        target_link_libraries(${PROJECT_NAME}_tests 
            ws2_32
            psapi
            advapi32
            kernel32
            user32
        )
    endif()
    
    # Add httplib for tests if needed
    target_link_libraries(${PROJECT_NAME}_tests 
        httplib::httplib
        fmt::fmt
    )
    
    add_test(NAME ${PROJECT_NAME}_tests COMMAND ${PROJECT_NAME}_tests)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Output directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "C++ compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Testing enabled: ${BUILD_TESTING}") 
