add_definitions(
  -D__USE_GNU
  -D_GNU_SOURCE
)

set( LIB_PREFIX 64)

########### unit tests ################

enable_testing()

#set(GTEST "$ENV{GOOGLE_TEST}")
set(GTEST "/home/mchen/software/gtest-1.7.0")

message(STATUS "GTEST = " ${GTEST})

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
