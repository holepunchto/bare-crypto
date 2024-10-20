cmake_minimum_required(VERSION 3.25)

find_package(cmake-bare REQUIRED PATHS node_modules/cmake-bare)

set(CMAKE_MACOSX_BUNDLE OFF)

project(bare_crypto C)

bare_target(target)

if(target MATCHES "win32")
  set(OPENSSL_NO_ASM ON)

  add_definitions(-DWIN32_LEAN_AND_MEAN)
else()
  enable_language(ASM)
endif()

if(NOT TARGET ssl)
  add_subdirectory(vendor/boringssl EXCLUDE_FROM_ALL)
endif()

add_bare_module(bare_crypto)

target_sources(
  ${bare_crypto}
  PRIVATE
    binding.c
)

target_link_libraries(
  ${bare_crypto}
  PUBLIC
    ssl
)
