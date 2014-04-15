# cmake rule for thread-sanitizer.
#
# Make sure gcc 4.8.2 is installed and configured using
#	$ export CC=/opt/gcc-4.8.2/bin/gcc
#	$ export CXX=/opt/gcc-4.8.2/bin/g++
#

SET(USE_TSAN 1)

SET(TSAN_C_FLAGS "-fsanitize=thread -fPIE")
SET(TSAN_CXX_FLAGS "-fsanitize=thread -fPIE")

SET(TSAN_EXE_LINKER_FLAGS "-fsanitize=thread -pie")
SET(TSAN_SHARED_LINKER_FLAGS "-fsanitize=thread -pie")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TSAN_C_FLAGS}")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${TSAN_CXX_FLAGS}")

if (USE_TSAN)
	SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${TSAN_EXE_LINKER_FLAGS}")
	SET(CMAKE_LINKER_LINKER_FLAGS "${CMAKE_LINKER_LINKER_FLAGS} ${TSAN_LINKER_LINKER_FLAGS}")
endif(USE_TSAN)
