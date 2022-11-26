find_package(fmt CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

set(SRCS
    main.cpp
)
add_executable(${PROJECT_NAME} ${SRCS})
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)
target_link_libraries(${PROJECT_NAME} PRIVATE
    fmt::fmt
    OpenSSL::SSL OpenSSL::Crypto
)

