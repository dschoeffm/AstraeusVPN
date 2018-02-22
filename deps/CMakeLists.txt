CMAKE_MINIMUM_REQUIRED(VERSION 2.9)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/tbb/libtbb.a
	PRE_LINK
	COMMAND $(MAKE) "extra_inc=big_iron.inc"
	COMMENT "Building TBB"
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tbb/
)

add_custom_target(TBB DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tbb/libtbb.a
	${CMAKE_CURRENT_SOURCE_DIR}/tbb/libtbb.a)

###############################################################################

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/libsodium_install/lib/libsodium.a
	PRE_LINK
	COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/libsodium/configure"
	"--prefix=${CMAKE_CURRENT_SOURCE_DIR}/libsodium_install" "--enable-opt"
	"--libdir=${CMAKE_CURRENT_SOURCE_DIR}/libsodium_install/lib"
	COMMAND $(MAKE)
	COMMAND $(MAKE) "install"
	COMMENT "Building libsodium"
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libsodium/
)

add_custom_target(libsodium DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libsodium_install/lib/libsodium.a)

