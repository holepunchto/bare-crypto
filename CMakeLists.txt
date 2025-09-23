cmake_minimum_required(VERSION 4.0)

find_package(cmake-bare REQUIRED PATHS node_modules/cmake-bare)
find_package(cmake-fetch REQUIRED PATHS node_modules/cmake-fetch)

project(bare_crypto C CXX)

bare_target(target)

if(target MATCHES "win32")
  add_definitions(-DWIN32_LEAN_AND_MEAN)
endif()

if(target MATCHES "win32-x64")
  enable_language(ASM_NASM)
else()
  enable_language(ASM)
endif()

fetch_package("github:google/boringssl#0.20250818.0")

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
