cmake_minimum_required(VERSION 3.25)

project(bare_crypto C)

include(bare)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT TARGET ssl)
  set(
    INSTALL_DESTINATION_DEFAULT
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    BUNDLE DESTINATION ${CMAKE_INSTALL_BINDIR}
  )

  if(MSVC)
    set(OPENSSL_NO_ASM ON)
  endif()

  if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
  endif()

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
