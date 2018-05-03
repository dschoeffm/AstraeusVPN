CMAKE_MINIMUM_REQUIRED(VERSION 2.9)
PROJECT(Astraeus CXX)

option(ASTRAEUSVPN_BUILD_TBB "Build TBB in AstraeusVPN" ON)
option(ASTRAEUSVPN_BUILD_LIBSODIUM "Build libsodium in AstraeusVPN" ON)
option(ASTRAEUSVPN_BUILD_HEXDUMP "Build hexdump in AstraeusVPN" ON)
option(ASTRAEUSVPN_BUILD_BINARIES "Build application binaries for AstraeusVPN" ON)

if(ASTRAUESVPN_BUILD_HEXDUMP)
	add_definitions(-DASTRAEUS_BUILD_HEXDUMP)
endif()

# Default build type is Release
if(NOT CMAKE_BUILD_TYPE)
	SET(CMAKE_BUILD_TYPE "Release")
endif(NOT CMAKE_BUILD_TYPE)

SET(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++14 -march=native -g -fno-omit-frame-pointer")

SET(CMAKE_CXX_FLAGS_DEBUG "-DDEBUG -g3 -O0 -fno-optimize-sibling-calls -fno-inline")
SET(CMAKE_CXX_FLAGS_RELEASE "-O3")

INCLUDE_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

FILE(GLOB LIBSOURCES lib/*.cpp)

# This will build OpenSSL
ADD_SUBDIRECTORY(deps)
LINK_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/deps/tbb
	${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium_install/lib
)
INCLUDE_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/deps/tbb/include
	${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium_install/include
)

SET(ALL_LIBS
	libsodium.a
	libtbb.a
	pthread
)

ADD_LIBRARY(${PROJECT_NAME} STATIC ${LIBSOURCES})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${ALL_LIBS})

ADD_DEPENDENCIES(${PROJECT_NAME} TBB libsodium)

if(ASTRAEUSVPN_BUILD_BINARIES)
	FILE(GLOB EXES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
	foreach(EXECPP ${EXES})
		GET_FILENAME_COMPONENT(EXE ${EXECPP} NAME_WE)
		ADD_EXECUTABLE(${EXE} ${EXECPP})
		TARGET_LINK_LIBRARIES(${EXE} ${PROJECT_NAME})
	endforeach(EXECPP)
endif()
