#include <stdexcept>
#include <string>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "dtls.hpp"

using namespace DTLS;
using namespace std;

SSL_CTX *DTLS::createClientCTX() {

	int result = 0;

	// Create a new context using DTLS
	// This should always use the highest possible version
	SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
	if (ctx == nullptr) {
		throw new std::runtime_error(
			"DTLS::createClientCTX() SSL_CTX_new(DTLS_method()) failed");
	}

	// Set our supported ciphers
	result = SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
	if (result != 1) {
		throw new std::runtime_error(
			"DTLS::createClientCTX() SSL_CTX_set_cipher_list() failed");
	}

	auto verifyFun = [](int ok, X509_STORE_CTX *ctx) {
		(void)ok;
		(void)ctx;
		return 1;
	};

	// Accept every cert
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verifyFun);

	// Do not query the BIO for an MTU
	SSL_CTX_set_options(ctx, SSL_OP_NO_QUERY_MTU);

	return ctx;
};

/*
SSL_CTX *DTLS::createServerCTX(std::string keyname) {
	SSL_CTX *ctx = createClientCTX();

	// Load key and certificate
	std::string certfile = "./" + keyname + "-cert.pem";
	std::string keyfile = "./" + keyname + "-key.pem";

	// Load the certificate file; contains also the public key
	int result = SSL_CTX_use_certificate_file(ctx, certfile.c_str(), SSL_FILETYPE_PEM);
	if (result != 1) {
		throw new std::runtime_error(
			"DTLS::createServerCTX() cannot load certificate file.\n"
			"IN CASE YOU DIDN'T CREATE ONE:\n"
			"openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem "
			"-out server-cert.pem\n\n");
	}

	// Load private key
	result = SSL_CTX_use_PrivateKey_file(ctx, keyfile.c_str(), SSL_FILETYPE_PEM);
	if (result != 1) {
		throw new std::runtime_error("DTLS::createServerCTX() cannot load private key file");
	}

	// Check if the private key is valid
	result = SSL_CTX_check_private_key(ctx);
	if (result != 1) {
		throw new std::runtime_error("DTLS::createServerCTX() private key check failed");
	}

	return ctx;
};
*/

SSL_CTX *DTLS::createServerCTX(const char *keyname) {
	int result = 0;

	// Create a new context using DTLS
	SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
	if (ctx == nullptr) {
		throw new std::runtime_error(
			"DTLS::createClientCTX() SSL_CTX_new(DTLS_method()) failed");
	}

	// Set our supported ciphers
	result = SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
	if (result != 1) {
		throw new std::runtime_error(
			"DTLS::createClientCTX() SSL_CTX_set_cipher_list() failed");
	}

	auto verifyFun = [](int ok, X509_STORE_CTX *ctx) {
		(void)ok;
		(void)ctx;
		return 1;
	};

	// The client doesn't have to send it's certificate
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verifyFun);

	// Load key and certificate
	char certfile[1024];
	char keyfile[1024];
	sprintf(certfile, "./%s-cert.pem", keyname);
	sprintf(keyfile, "./%s-key.pem", keyname);

	// Load the certificate file; contains also the public key
	result = SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM);
	if (result != 1) {
		throw new std::runtime_error(
			"DTLS::createServerCTX() cannot load certificate file.\n"
			"IN CASE YOU DIDN'T CREATE ONE:\n"
			"openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout server-key.pem "
			"-out server-cert.pem\n\n");
	}

	// Load private key
	result = SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM);
	if (result != 1) {
		throw new std::runtime_error("DTLS::createServerCTX() cannot load private key file");
	}

	// Check if the private key is valid
	result = SSL_CTX_check_private_key(ctx);
	if (result != 1) {
		throw new std::runtime_error("DTLS::createServerCTX() private key check failed");
	}

	return ctx;
}

Connection DTLS::createServerConn(SSL_CTX *ctx) {
	SSL *ssl = SSL_new(ctx);
	if (ssl == NULL) {
		throw new std::runtime_error("DTLS::createServerConn() SSL_new() failed");
	}

	BIO *wbio = BIO_new(BIO_s_memQ());
	if (wbio == NULL) {
		throw new std::runtime_error("DTLS::createServerConn() BIO_new() failed");
	}

	BIO *rbio = BIO_new(BIO_s_memQ());
	if (rbio == NULL) {
		throw new std::runtime_error("DTLS::createServerConn() BIO_new() failed");
	}

	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, rbio, wbio);

	Connection c;

	c.ssl = ssl;
	c.wbio = wbio;
	c.rbio = rbio;

	return c;
};

Connection DTLS::createClientConn(SSL_CTX *ctx) {
	SSL *ssl = SSL_new(ctx);
	if (ssl == NULL) {
		throw new std::runtime_error("DTLS::createClientConn() SSL_new() failed");
	}

	BIO *wbio = BIO_new(BIO_s_memQ());
	if (wbio == NULL) {
		throw new std::runtime_error("DTLS::createClientConn() BIO_new() failed");
	}

	BIO *rbio = BIO_new(BIO_s_memQ());
	if (rbio == NULL) {
		throw new std::runtime_error("DTLS::createClientConn() BIO_new() failed");
	}

	SSL_set_connect_state(ssl);
	SSL_set_bio(ssl, rbio, wbio);

	Connection c;

	c.ssl = ssl;
	c.wbio = wbio;
	c.rbio = rbio;

	return c;
};

int DTLS::bindSocket(int port) {
	int fd;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		throw new std::system_error(std::error_code(errno, std::generic_category()),
			std::string("DTLS::bindSocket() socket() failed"));
	}

	if (::bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
		throw new std::system_error(std::error_code(errno, std::generic_category()),
			std::string("DTLS::bindSocket() bind() failed"));
	}

	return fd;
};

int DTLS::createSocket() {
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		throw new std::system_error(std::error_code(errno, std::generic_category()),
			std::string("DTLS::bindSocket() socket() failed"));
	}

	return fd;
};
