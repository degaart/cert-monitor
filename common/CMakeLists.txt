find_package(fmt CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_path(BSHOSHANY_THREAD_POOL_INCLUDE_DIRS "BS_thread_pool.hpp")
set(nlohmann-json_IMPLICIT_CONVERSIONS OFF)
find_package(nlohmann_json CONFIG REQUIRED)

add_library(common
    net.cpp
    ssl.cpp
    util.cpp
)
target_compile_features(common PUBLIC cxx_std_17)
target_link_libraries(common
    PUBLIC
        fmt::fmt
        OpenSSL::SSL OpenSSL::Crypto
        nlohmann_json::nlohmann_json
)
target_include_directories(common
    PUBLIC
        ${BSHOSHANY_THREAD_POOL_INCLUDE_DIRS}
    INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/..
)


