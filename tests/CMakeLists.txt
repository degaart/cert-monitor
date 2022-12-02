add_executable(test_stress test_stress.cpp)
target_compile_features(test_stress PRIVATE cxx_std_17)
target_link_libraries(test_stress
    PRIVATE
        common
)

add_executable(test_ssl test_ssl.cpp)
target_compile_features(test_ssl PRIVATE cxx_std_17)
target_link_libraries(test_ssl
    PRIVATE
        common
)
