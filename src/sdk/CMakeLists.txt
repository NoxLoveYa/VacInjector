add_library(vacsafe_sdk STATIC sdk.cpp)
target_include_directories(vacsafe_sdk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ../common)
target_link_libraries(vacsafe_sdk PUBLIC vacsafe_common)
