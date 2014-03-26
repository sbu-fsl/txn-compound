add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

set( LIB_PREFIX 64)

########### library dependency ################
find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})

file(GLOB ProtoFiles "${CMAKE_CURRENT_SOURCE_DIR}/*.proto")
include_directories(${CMAKE_CURRENT_BINARY_DIR})
PROTOBUF_GENERATE_CPP(ProtoSources ProtoHeaders ${ProtoFiles})
message(STATUS "protocol sources: " ${ProtoSources})
message(STATUS "protocol headers: " ${ProtoHeaders})

########### unit tests ################

enable_testing()

#set(GTEST "$ENV{GOOGLE_TEST}")
set(GTEST "/home/mchen/software/gtest-1.7.0")

include_directories(
	"${GTEST}"
	"${GTEST}/include"
)

add_library(gtest "${GTEST}/src/gtest-all.cc")

add_library(gtest_main "${GTEST}/src/gtest_main.cc")

find_library(TBB_LIB tbb "/usr/local/lib64/tbb/")
message(STATUS "tbb library: " ${TBB_LIB})

set(secnfs_LIB
  gos
  glog
  cryptopp
  pthread
  ${TBB_LIB}
  ${PROTOBUF_LIBRARIES}
)

set(test_LIB
	gtest
	gtest_main
)

set(secnfs_SRC
  secnfs.cpp
  context.cpp
  secnfs_lib.cpp
  proxy_manager.cpp
  ${ProtoSources}
  ${ProtoHeaders}
)

function(add_unittest TestName)
  add_executable(${TestName} "${TestName}.cpp" ${secnfs_SRC} test_helper.cpp)
  target_link_libraries(${TestName} ${secnfs_LIB} ${test_LIB})
  add_test(NAME ${TestName} COMMAND ${TestName})
endfunction(add_unittest)

add_unittest(secnfs_test)
add_unittest(context_test)
add_unittest(secnfs.pb_test)
add_unittest(secnfs_lib_test)

########### next target ###############

SET(fsalsecnfs_LIB_SRCS
   handle.c
   file.c
   xattrs.c
   secnfs_methods.h
   main.c
   export.c
   fsal_convert.c
   ${secnfs_SRC}
)

add_library(fsalsecnfs SHARED ${fsalsecnfs_LIB_SRCS})

target_link_libraries(fsalsecnfs ${secnfs_LIB})

set_target_properties(fsalsecnfs PROPERTIES VERSION 4.2.0 SOVERSION 4)
install(TARGETS fsalsecnfs COMPONENT fsal DESTINATION ${FSAL_DESTINATION} )


########### install files ###############
