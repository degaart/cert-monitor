cmake_minimum_required(VERSION 3.24)

# Avoid warning with vcpkg and cmake 3.24
cmake_policy(SET CMP0003 NEW)

project(cert-monitor)

# There's a bug in vcpkg/drogon, si we NEED to set this ugly global variable
# here or there will be errors
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(src)

