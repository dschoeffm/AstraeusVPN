CMAKE_MINIMUM_REQUIRED(VERSION 2.9)
PROJECT(Astraeus CXX)

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
	${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl
	${CMAKE_CURRENT_SOURCE_DIR}/deps/tbb
	${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium_install/lib64
)
INCLUDE_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl/include/
	${CMAKE_CURRENT_SOURCE_DIR}/deps/tbb/include
	${CMAKE_CURRENT_SOURCE_DIR}/deps/libsodium_install/include
)
SET(OPENSSL_LIBS
	-Wl,--whole-archive
	libssl.a
	-Wl,--whole-archive
	libcrypto.a
	-Wl,--no-whole-archive
	dl
)
# OpenSSL part is finished here

SET(ALL_LIBS
	pthread
	libsodium.a
	libtbb.a
	${OPENSSL_LIBS}
)

ADD_LIBRARY(${PROJECT_NAME} STATIC ${LIBSOURCES})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${ALL_LIBS})

ADD_DEPENDENCIES(${PROJECT_NAME} OpenSSL TBB libsodium)

#ADD_EXECUTABLE(server src/server.cpp)
#TARGET_LINK_LIBRARIES(server ${PROJECT_NAME})
#
#ADD_EXECUTABLE(client src/client.cpp)
#TARGET_LINK_LIBRARIES(client ${PROJECT_NAME})

FILE(GLOB EXES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
foreach(EXECPP ${EXES})
	GET_FILENAME_COMPONENT(EXE ${EXECPP} NAME_WE)
	ADD_EXECUTABLE(${EXE} ${EXECPP})
	TARGET_LINK_LIBRARIES(${EXE} ${PROJECT_NAME})
endforeach(EXECPP)
