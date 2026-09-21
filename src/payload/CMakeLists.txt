add_library(payload SHARED dllmain.cpp cs2_adapter.cpp source1_adapter.cpp adapter_factory.cpp)
target_include_directories(payload PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ../common ../sdk ../stealth)
target_link_libraries(payload PRIVATE vacsafe_sdk vacsafe_stealth vacsafe_common)
set_target_properties(payload PROPERTIES OUTPUT_NAME "payload")
