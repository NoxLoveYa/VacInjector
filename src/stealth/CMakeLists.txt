add_library(vacsafe_stealth STATIC stealth.cpp stealth_pre.cpp)
target_include_directories(vacsafe_stealth PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ../common)
target_link_libraries(vacsafe_stealth PUBLIC vacsafe_common)
