find_package(unofficial-http-parser REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(restinio CONFIG REQUIRED)

set(SRCS
    main.cpp
)
add_executable(${PROJECT_NAME} ${SRCS})
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        common
        restinio::restinio
)

