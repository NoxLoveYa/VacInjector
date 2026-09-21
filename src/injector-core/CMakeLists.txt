add_library(vacsafe_injector_core STATIC
  manual_map.cpp
  thread_hijack.cpp
  remote_thread.cpp
  apc.cpp
  dispatch.cpp
  driver_client.cpp
)
target_include_directories(vacsafe_injector_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ../common)
target_link_libraries(vacsafe_injector_core PUBLIC vacsafe_common Psapi)
