#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include <arpa/inet.h>
#include <cstring>
#include <signal.h>
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

int handlePacket(int fd, struct DTLS::Connection &conn, char *buf, int bufLen, int recvBytes,
	struct sockaddr_in *src_addr, TapDevice &tap) {

	std::cout << "run handlePacket" << std::endl;

	if (BIO_write(conn.rbio, buf, recvBytes) != recvBytes) {
		throw new std::runtime_error("handlePacket() BIO_write() failed");
	}

	if (SSL_is_init_finished(conn.ssl)) {
		// Here the handshake is already finished

		// Try to read incoming byte from the connection
		int readLen = SSL_read(conn.ssl, buf, bufLen);
		if ((readLen <= 0) && (SSL_get_shutdown(conn.ssl) == 0)) {
			throw new std::runtime_error("handlePacket() SSL_read() failed");
		}

		// Try to write the incoming bytes to the TAP device
		if (readLen > 0) {
			if (readLen < 14) {
				std::cout << "Tunneled frame too short -> dropping" << std::endl;
			} else {
				int writeLen = tap.write(buf, readLen);
				if (writeLen <= 0) {
					std::cout << "readLen=" << readLen << std::endl;
					throw new std::runtime_error("handlePacket() tap.write() failed");
				} else {
					std::cout << "Written data to TAP" << std::endl;
				}
			}
		}
	} else {
		// We are currently conducting a handshake

		std::cout << "handlePacket() running handshake" << std::endl;

		// The return code is pretty useless, throw it away
		SSL_accept(conn.ssl);
	}

	// Write out all data
	int readCount;
	while ((readCount = BIO_read(conn.wbio, buf, bufLen)) > 0) {
		int sendBytes = sendto(
			fd, buf, readCount, 0, (struct sockaddr *)src_addr, sizeof(struct sockaddr_in));

		if (sendBytes != readCount) {
			throw new std::system_error(std::error_code(errno, std::generic_category()),
				std::string("handlePacket() sendto() failed"));
		} else {
			std::cout << "Send packet to peer" << std::endl;
		}
	}

	if (SSL_get_shutdown(conn.ssl) != 0) {
		if (SSL_shutdown(conn.ssl) == 1) {
			SSL_free(conn.ssl);
			return 1;
		}
	}

	return 0;
}

int main(int argc, char **argv) {
	try {
		(void)argc;
		(void)argv;

		signal(SIGINT, sigHandler);

		// For now, just create a tap interface
		std::string devName = "astraeus";
		TapDevice tap(devName);

		std::cout << "Create tap dev: " << devName << std::endl;

		/*
		char buffer[2048];
		size_t bufSize = 2048;

		while (stopFlag == 0) {
			int ret = tap.read(buffer, bufSize);
			if (ret > 0) {
				hexdump(buffer, ret);
			} else {
				std::cout << "read() failed" << std::endl;
				break;
			}
		}
		*/

		SSL_CTX *ctx = DTLS::createServerCTX("server");

		// Create the server UDP listener socket
		int fd = DTLS::bindSocket(4433);
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(struct timeval));

		std::cout << "bound socket" << std::endl;

		std::unordered_map<std::pair<unsigned long, unsigned short>, struct DTLS::Connection,
			pairhash>
			connections;

		char buf[2048];

		while (stopFlag == 0) {
			struct sockaddr_in src_addr;
			socklen_t addrlen = sizeof(struct sockaddr_in);

			// Try to recv a packet
			int ret =
				recvfrom(fd, (void *)buf, 2048, 0, (struct sockaddr *)&src_addr, &addrlen);
			if (ret < 0) {
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
					continue;
				} else {
					throw new std::system_error(
						std::error_code(errno, std::generic_category()),
						std::string("main() recvfrom() failed"));
				}
			} else {
				std::cout << "received a packet" << std::endl;
			}

			// Look up if there already exists a connection
		conn_lockup:
			auto conn_it = connections.find({src_addr.sin_addr.s_addr, src_addr.sin_port});
			if (conn_it == connections.end()) {
				std::cout << "Connection from new client" << std::endl;
				connections.insert({{src_addr.sin_addr.s_addr, src_addr.sin_port},
					DTLS::createServerConn(ctx)});
				goto conn_lockup;
			}

			// Just double checking
			if (conn_it == connections.end()) {
				throw new std::runtime_error("conn_it is invalid...");
			}

			if (handlePacket(fd, conn_it->second, buf, 2048, ret, &src_addr, tap) == 1) {
				connections.erase(conn_it);
			}
		}

		close(fd);

		std::cout << "Server shutting down..." << std::endl;

	} catch (std::exception *e) {
		std::cout << "Caught exception:" << std::endl;
		std::cout << e->what() << std::endl;
	}
}
