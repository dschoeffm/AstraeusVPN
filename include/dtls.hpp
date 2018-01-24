#include <iostream>
#include <string>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace DTLS {

struct Connection {
	SSL *ssl;
	BIO *wbio;
	BIO *rbio;
};

SSL_CTX *createClientCTX();
SSL_CTX *createServerCTX(const char *keyname);

Connection createServerConn(SSL_CTX *ctx);
Connection createClientConn(SSL_CTX *ctx);

int bindSocket(int port);
int createSocket();

}; // namespace DTLS
