cmake_minimum_required(VERSION 3.2)
project(NepTUNTest LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

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
