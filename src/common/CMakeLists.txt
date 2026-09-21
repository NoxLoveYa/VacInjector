add_library(vacsafe_common STATIC
  common.cpp
  nt_api.cpp
  crypto.cpp
)
target_include_directories(vacsafe_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
