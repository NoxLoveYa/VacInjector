add_executable(VacSafe loader.cpp)
target_include_directories(VacSafe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ../common ../injector-core ../stealth)
target_link_libraries(VacSafe PRIVATE vacsafe_injector_core vacsafe_stealth vacsafe_common)
set_target_properties(VacSafe PROPERTIES OUTPUT_NAME "VacSafe")
