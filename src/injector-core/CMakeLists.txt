add_library(vacsafe_injector_core STATIC
  manual_map.cpp
  thread_hijack.cpp
  remote_thread.cpp
  apc.cpp
  dispatch.cpp
  driver_client.cpp
)
target_include_directories(vacsafe_injector_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ../common ../stealth)
target_link_libraries(vacsafe_injector_core PUBLIC vacsafe_common vacsafe_stealth Psapi)
# getenv is used for dev-only diag gates (VACSAFE_VERBOSE/NOCALL); not a security boundary.
target_compile_definitions(vacsafe_injector_core PRIVATE _CRT_SECURE_NO_WARNINGS)
