cmake_minimum_required(VERSION 3.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(obsidian
    VERSION 4.0
)

set(CMAKE_EXPORT_COMPILE_COMMANDS
    ON
    CACHE
    INTERNAL ""
)

add_library(obsidian-lib STATIC
    source/include/obsidian.hpp
    source/obsidian/asymmetric.cpp
    source/obsidian/encoding.cpp
    source/obsidian/hashing.cpp
    source/obsidian/kderivation.cpp
    source/obsidian/random.cpp
    source/obsidian/symmetric.cpp)

target_include_directories(obsidian-lib
    PUBLIC C:/OpenSSL-Win64/include/)

target_link_directories(obsidian-lib
    PUBLIC C:/OpenSSL-Win64/lib/VC/static/)

target_compile_options(obsidian-lib PUBLIC /Wall)

target_link_libraries(obsidian-lib
    libcrypto64MT
    advapi32
    user32
    Ws2_32
    Crypt32
    kernel32
    user32)

add_executable(obsidian-test
    source/obsidian-test/main.cpp
    source/obsidian-test/tests/test_encodings.cpp)

target_compile_options(obsidian-test PUBLIC /Wall)

target_link_directories(obsidian-test PUBLIC
    C:/Langs/CPP/googletest/lib/)

target_include_directories(obsidian-test PRIVATE
    C:/Langs/CPP/googletest/include/
    ./)

target_link_libraries(obsidian-test
    obsidian-lib
    gtest
    gmock)
