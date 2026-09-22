add_executable(VacSafe loader.cpp)
target_include_directories(VacSafe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ../common ../injector-core ../stealth)
target_link_libraries(VacSafe PRIVATE vacsafe_injector_core vacsafe_stealth vacsafe_common Psapi)
set_target_properties(VacSafe PROPERTIES OUTPUT_NAME "VacSafe")
# Double-click support: stage payload + map next to the loader after every build.
# (No DEPENDS here: TARGET form tracks the payload link already.)
add_custom_command(TARGET VacSafe POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:payload> $<TARGET_FILE_DIR:VacSafe>/payload.dll
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE_DIR:payload>/payload.map $<TARGET_FILE_DIR:VacSafe>/payload.map)
