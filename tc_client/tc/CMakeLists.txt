add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

add_definitions(-std=c++11)

set(tc_SRC
  tc_impl.c
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

set(test_LIB
  pthread
  gtest
  gtest_main
  gmock
  gmock_main
  tc_impl
  tc_impl_posix
  tc_impl_nfs4
  tc_util
  tc_helper
  MainServices
  ${PROTOCOLS}
  ${GANESHA_CORE}
  ${SYSTEM_LIBRARIES}
  ${LIBTIRPC_LIBRARIES}
  config_parsing
)

function (add_unittest TestName LibName)
  add_executable(${TestName} "${CMAKE_CURRENT_SOURCE_DIR}/${TestName}.cpp")
  target_link_libraries(${TestName} ${base_LIBS} ${boost_LIBS} ${test_LIB} ${LibName})
  add_test(NAME ${TestName} COMMAND ${TestName})
endfunction (add_unittest)

add_unittest(tc_test tc_impl)
