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
)
INCLUDE_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/deps/openssl/include/
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
	tbb
	${OPENSSL_LIBS}
)

ADD_LIBRARY(${PROJECT_NAME} STATIC ${LIBSOURCES})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${ALL_LIBS})

ADD_DEPENDENCIES(${PROJECT_NAME} OpenSSL)

ADD_EXECUTABLE(server src/server.cpp)
TARGET_LINK_LIBRARIES(server ${PROJECT_NAME})

ADD_EXECUTABLE(client src/client.cpp)
TARGET_LINK_LIBRARIES(client ${PROJECT_NAME})
