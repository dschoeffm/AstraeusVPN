#include <array>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include <arpa/inet.h>
#include <cstring>
#include <signal.h>
#include <sys/select.h>
#include <unistd.h>

#include "common.hpp"
#include "dtls.hpp"
#include "tap.hpp"

using namespace std;

// Taken from:
// https://stackoverflow.com/a/20602159
struct pairhash {
public:
	template <typename T, typename U> std::size_t operator()(const std::pair<T, U> &x) const {
		return std::hash<T>()(x.first) ^ std::hash<U>()(x.second);
	}
};

static int stopFlag = 0;

void sigHandler(int sig) {
	(void)sig;
	stopFlag = 1;
}

int runConnect(int fd, char *buf, int bufLen, SSL_CTX *ctx, struct sockaddr_in *dst_addr) {

	D(std::cout << "run handlePacket" << std::endl;)

	DTLS::Connection conn = DTLS::createClientConn(ctx);

	// Start the handshake
	SSL_connect(conn.ssl);

	// Write out all data
	int readCount;
	while ((readCount = BIO_read(conn.wbio, buf, bufLen)) > 0) {
		int sendBytes = sendto(
			fd, buf, readCount, 0, (struct sockaddr *)dst_addr, sizeof(struct sockaddr_in));

		if (sendBytes != readCount) {
			throw new std::system_error(std::error_code(errno, std::generic_category()),
				std::string("runConnect() sendto() failed"));
		} else {
			D(std::cout << "runConnect() Send packet to peer" << std::endl;)
		}
	}

	return 0;
};

void usage(string name) {
	cout << "Usage: " << name << " <server IP> <server port>" << endl;
	exit(0);
}

int main(int argc, char **argv) {
	try {
		if (argc < 3) {
			usage(string(argv[0]));
		}

		// Prepare server address
		struct sockaddr_in server;
		if (inet_aton(argv[1], &server.sin_addr) != 1) {
			cout << "inet_aton() failed" << endl;
			exit(EXIT_FAILURE);
		}
		server.sin_port = htons(atoi(argv[2]));
		server.sin_family = AF_INET;

		signal(SIGINT, sigHandler);

		SSL_CTX *ctx = DTLS::createClientCTX();

		// Create the server UDP listener socket
		int fd = DTLS::createSocket();
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(struct timeval));

		std::cout << "socket created" << std::endl;

		char buf[2048];

		while (stopFlag == 0) {
			runConnect(fd, buf, 2048, ctx, &server);
		}
		close(fd);

		std::cout << "Client shutting down..." << std::endl;
	} catch (std::exception *e) {
		std::cout << "Caught exception:" << std::endl;
		std::cout << e->what() << std::endl;
	}
}
