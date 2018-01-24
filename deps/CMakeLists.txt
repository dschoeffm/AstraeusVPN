CMAKE_MINIMUM_REQUIRED(VERSION 2.9)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/openssl/libssl.a
	${CMAKE_CURRENT_SOURCE_DIR}/openssl/libcrypto.a
	PRE_LINK
	COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/openssl/config"
	COMMAND $(MAKE) "build_libs"
	COMMENT "Building OpenSSL - This may take a while"
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/openssl/
)

add_custom_target(OpenSSL DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/openssl/libssl.a
	${CMAKE_CURRENT_SOURCE_DIR}/openssl/libcrypto.a)
