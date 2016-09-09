add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(tc_SRC
  tc_impl.c
  tc_lib.cpp
)

include_directories(
  "${GTEST}"
  "${GTEST}/include"
)

include_directories(
  "${GMOCK}"
  "${GMOCK}/include"
)

include_directories("${CMAKE_CURRENT_SOURCE_DIR}")
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
include_directories("${CMAKE_SOURCE_DIR}")

add_library(gtest "${GTEST}/src/gtest-all.cc")
add_library(gtest_main "${GTEST}/src/gtest_main.cc")
add_library(gmock "${GMOCK}/src/gmock-all.cc")
add_library(gmock_main "${GMOCK}/src/gmock_main.cc")

add_library(tc_impl STATIC ${tc_SRC})
#target_link_libraries(tc_impl
  #support
  #log
  #config_parsing
  #tc_util
  #tc_impl_posix
  #tc_impl_nfs4
#) 

set_target_properties(tc_impl PROPERTIES POSITION_INDEPENDENT_CODE on)

set(tc_LIBS
  tc_impl
  tc_impl_posix
  tc_impl_nfs4
  tc_util
  tc_helper
  path_utils
  MainServices
  ${PROTOCOLS}
  ${GANESHA_CORE}
  ${SYSTEM_LIBRARIES}
  ${LIBTIRPC_LIBRARIES}
  config_parsing
)

set(test_LIB
  pthread
  gtest
  gtest_main
  gmock
  gmock_main
  ${tc_LIBS}
)

function (add_unittest TestName LibName)
  add_executable(${TestName} "${CMAKE_CURRENT_SOURCE_DIR}/${TestName}.cpp")
  target_link_libraries(${TestName} ${base_LIBS} ${boost_LIBS} ${test_LIB} ${LibName})
  add_test(NAME ${TestName} COMMAND ${TestName})
endfunction (add_unittest)

add_unittest(tc_test tc_impl)

find_package(gflags REQUIRED)
add_executable(tc_bench tc_bench.cpp)
target_link_libraries(tc_bench gflags ${tc_LIBS} ${GBENCH_LIBRARIES})

add_executable(tc_rw_files tc_rw_files.cpp)
target_link_libraries(tc_rw_files gflags ${tc_LIBS})

add_executable(tc_append tc_append.cpp)
target_link_libraries(tc_append gflags ${tc_LIBS})
