add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

add_definitions(-std=c++11)

set(path_utils_SRC
  path_utils.cpp
)
add_library(path_utils STATIC ${path_utils_SRC})
set_target_properties(path_utils PROPERTIES POSITION_INDEPENDENT_CODE on)

set(util_SRC
  bench.cpp
  fileutil.cpp
  iovec_utils.cpp
)

include_directories(
  "${GTEST}"
  "${GTEST}/include"
)

include_directories(
  "${GMOCK}"
  "${GMOCK}/include"
)

set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} ${GTEST}/lib ${GMOCK}/lib)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
include_directories("${CMAKE_SOURCE_DIR}")

set(test_LIB
  gtest
  gtest_main
  gmock
  path_utils
  tc_helper
  pthread
)

function (add_unittest TestName LibName)
  add_executable(${TestName} "${CMAKE_CURRENT_SOURCE_DIR}/${TestName}.cpp")
  target_link_libraries(${TestName} ${base_LIBS} ${boost_LIBS} ${test_LIB} ${LibName})
  add_test(NAME ${TestName} COMMAND ${TestName})
endfunction (add_unittest)

add_library(tc_util STATIC ${util_SRC})
target_link_libraries(tc_util path_utils)

add_unittest(bench_test tc_util)
add_unittest(zipf_test tc_util)
add_unittest(fileutil_test tc_util)
add_unittest(path_utils_test tc_util)
add_unittest(common_types_test tc_util)
add_unittest(iovec_utils_test tc_util)
