find_package(fmt CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_path(BSHOSHANY_THREAD_POOL_INCLUDE_DIRS "BS_thread_pool.hpp")
find_package(unofficial-http-parser REQUIRED)
find_package(restinio CONFIG REQUIRED)

set(nlohmann-json_IMPLICIT_CONVERSIONS OFF)
find_package(nlohmann_json CONFIG REQUIRED)

set(SRCS
    main.cpp
)
add_executable(${PROJECT_NAME} ${SRCS})
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        fmt::fmt
        OpenSSL::SSL OpenSSL::Crypto
        restinio::restinio
        nlohmann_json::nlohmann_json
)
target_include_directories(${PROJECT_NAME}
    PRIVATE
        ${BSHOSHANY_THREAD_POOL_INCLUDE_DIRS}
)

