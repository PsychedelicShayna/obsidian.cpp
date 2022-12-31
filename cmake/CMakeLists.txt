cmake_minimum_required(VERSION 3.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(obsidian VERSION 4.0)

add_library(obsidian-lib STATIC 
    ../source/obsidian.cpp
    ../source/obsidian.hpp
)

target_include_directories(obsidian-lib 
    PUBLIC C:/OpenSSL-Win64/include/
)

target_link_directories(obsidian-lib
    PUBLIC C:/OpenSSL-Win64/lib/VC/static/
)

target_link_libraries(obsidian-lib
    libcrypto64MT
    advapi32
    user32
    Ws2_32
    Crypt32
    kernel32
    user32
)

add_executable(obsidian-test 
    ../source/main.cpp
)

target_link_libraries(obsidian-test 
    obsidian-lib
)

target_include_directories(obsidian-test 
    PRIVATE C:/OpenSSL-Win64/include/
            source/
)
