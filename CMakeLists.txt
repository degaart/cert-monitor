cmake_minimum_required(VERSION 3.24)

# Avoid warning with vcpkg and cmake 3.24
cmake_policy(SET CMP0003 NEW)

project(cert-monitor)

add_subdirectory(src)

