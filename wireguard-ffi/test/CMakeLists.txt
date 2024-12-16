add_library(common STATIC common.c common.h)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(common PUBLIC neptun)

add_executable(keygen keygen.c)
target_link_libraries(keygen PRIVATE common)

add_executable(client client.c)
target_link_libraries(client PRIVATE common)

add_executable(server server.c)
target_link_libraries(server PRIVATE common)

macro(package_add_test TESTNAME)
  # create an exectuable in which the tests will be stored
  add_executable(${TESTNAME} ${ARGN})
  # link the Google test infrastructure, mocking library, and a default main fuction to
  # the test executable.  Remove g_test_main if writing your own main function.
  target_link_libraries(${TESTNAME} PRIVATE gtest gmock)
  # gtest_discover_tests replaces gtest_add_tests,
  # see https://cmake.org/cmake/help/v3.10/module/GoogleTest.html for more options to pass to it
  gtest_discover_tests(${TESTNAME}
      # set a working directory so your project root so that you can find test data via paths relative to the project root
      WORKING_DIRECTORY ${PROJECT_DIR}
      PROPERTIES VS_DEBUGGER_WORKING_DIRECTORY "${PROJECT_DIR}"
  )
  set_target_properties(${TESTNAME} PROPERTIES FOLDER tests)
endmacro()

package_add_test(test_ffi
  test_ffi.cpp)
target_link_libraries(test_ffi PUBLIC
  # absl::strings absl::str_format 
        common
        gtest_main)
