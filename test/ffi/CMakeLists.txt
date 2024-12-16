cmake_minimum_required(VERSION 3.16)
project(NepTUNTest LANGUAGES C CXX)

option(BUILD_TESTING "Enable tests" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_GTEST_DISCOVER_TESTS_DISCOVERY_MODE PRE_TEST)

set(NEPTUN_SOURCE_ROOT ${CMAKE_SOURCE_DIR}/../..)
set(NEPTUN_BUILD_TARGET "release")
set(NEPTUN_LIBRARY_FILENAME "libneptun.a")
set(NEPTUN_LIBRARY_PATH ${NEPTUN_SOURCE_ROOT}/target/${NEPTUN_BUILD_TARGET}/${NEPTUN_LIBRARY_FILENAME})

add_library(neptun STATIC IMPORTED)
set_property(TARGET neptun PROPERTY IMPORTED_LOCATION ${NEPTUN_LIBRARY_PATH})
set_property(TARGET neptun PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${NEPTUN_SOURCE_ROOT}/neptun/src)

add_compile_options(-Wall -Wextra -Wpedantic)

add_library(common STATIC common.c common.h)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(common PUBLIC neptun)

add_executable(keygen keygen.c)
target_link_libraries(keygen PRIVATE common)

add_executable(client client.c)
target_link_libraries(client PRIVATE common)

add_executable(server server.c)
target_link_libraries(server PRIVATE common)

# Testing only available if this is the main app
if(${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME} AND BUILD_TESTING)
  include(FetchContent)
    FetchContent_Declare(
    googletest
    GIT_TAG v1.14.0
    GIT_REPOSITORY https://github.com/google/googletest.git
  )

  enable_testing()

  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  include(GoogleTest)
  mark_as_advanced(
          BUILD_GMOCK BUILD_GTEST BUILD_SHARED_LIBS
          gmock_build_tests gtest_build_samples gtest_build_tests
          gtest_disable_pthreads gtest_force_shared_crt gtest_hide_internal_symbols
  )

  if (BUILD_TESTING)
    add_subdirectory(test)
  endif ()
endif()
