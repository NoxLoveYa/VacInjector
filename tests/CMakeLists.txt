add_executable(vacsafe_tests test_injector.cpp test_stealth.cpp test_sdk.cpp test_offsets.cpp)
target_include_directories(vacsafe_tests PRIVATE ../src/common ../src/injector-core ../src/stealth ../src/sdk)
target_link_libraries(vacsafe_tests PRIVATE vacsafe_injector_core vacsafe_stealth vacsafe_sdk vacsafe_common)
add_test(NAME vacsafe_tests COMMAND vacsafe_tests)
