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

set(test_LIB
	gtest
	gtest_main
	cryptopp
	pthread
)

add_executable(secnfs_test secnfs_test.cpp secnfs.cpp)
target_link_libraries(secnfs_test ${test_LIB})
add_test(NAME secnfs_test COMMAND secnfs_test)

add_executable(secnfs.pb_test secnfs.pb_test.cpp ${ProtoSources} ${ProtoHeaders})
target_link_libraries(secnfs.pb_test ${test_LIB} ${PROTOBUF_LIBRARIES})
add_test(NAME secnfs.pb_test COMMAND secnfs.pb_test)

add_executable(secnfs_lib_test secnfs_lib_test.cpp secnfs_lib.cpp)
target_link_libraries(secnfs_lib_test ${test_LIB})
add_test(NAME secnfs_lib_test COMMAND secnfs_lib_test)

########### next target ###############

SET(fsalsecnfs_LIB_SRCS
   handle.c
   file.c
   xattrs.c
   secnfs_methods.h
   main.c
   export.c
   secnfs.cpp
   fsal_convert.c
   context.cpp
   secnfs_lib.cpp
)

add_library(fsalsecnfs SHARED ${fsalsecnfs_LIB_SRCS})

target_link_libraries(fsalsecnfs
  gos
  cryptopp
  pthread
)

set_target_properties(fsalsecnfs PROPERTIES VERSION 4.2.0 SOVERSION 4)
install(TARGETS fsalsecnfs COMPONENT fsal DESTINATION ${FSAL_DESTINATION} )


########### install files ###############
