cmake_minimum_required(VERSION 3.27)
project(VacSafeInjector LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(VACSAFE_BUILD_DRIVER "Build kernel driver (requires WDK, test-sign only)" OFF)
option(VACSAFE_BUILD_TESTS "Build unit tests" ON)
option(VACSAFE_ARCH "Target arch override" "")

if(MSVC)
  add_compile_options(/W4 /permissive- /MP)
else()
  add_compile_options(-Wall -Wextra)
endif()

add_subdirectory(src/common)
add_subdirectory(src/injector-core)
add_subdirectory(src/stealth)
add_subdirectory(src/sdk)
add_subdirectory(src/payload)
add_subdirectory(src/loader)

if(VACSAFE_BUILD_DRIVER)
  message(STATUS "Driver build enabled (stub - provide WDK path)")
  add_subdirectory(src/driver)
endif()

if(VACSAFE_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
