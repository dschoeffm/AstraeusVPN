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

int handlePacket(int fd, DTLS::Connection &conn, char *buf, int bufLen, int recvBytes,
	struct sockaddr_in *src_addr, TapDevice &tap) {

	D(std::cout << "run handlePacket" << std::endl;)

	if (recvBytes > 0) {
		if (BIO_write(conn.rbio, buf, recvBytes) != recvBytes) {
			throw new std::runtime_error("handlePacket() BIO_write() failed");
		}
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
			int writeLen = tap.write(buf, readLen);
			if (writeLen < 0) {
				std::cout << "readLen=" << readLen << std::endl;
				throw new std::runtime_error("handlePacket() tap.write() failed");
			} else {
				D(std::cout << "Written data to TAP" << std::endl;)
			}
		}
	} else {
		// We are currently conducting a handshake

		std::cout << "handlePacket() running handshake" << std::endl;

		// The return code is pretty useless, throw it away
		SSL_connect(conn.ssl);

		if (SSL_is_init_finished(conn.ssl)) {
			std::cout << "handlePacket() Handshake finished" << std::endl;
		}
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
			D(std::cout << "handlePacket() Send packet to peer" << std::endl;)
		}
	}

	if (SSL_get_shutdown(conn.ssl) != 0) {
		if (SSL_shutdown(conn.ssl) == 1) {
			SSL_free(conn.ssl);
			return 1;
		}
	}

	return 0;
};

int handleTap(int fd, char *buf, int bufLen, int readLen, DTLS::Connection *conn,
	struct sockaddr_in dst) {
	if (SSL_write(conn->ssl, buf, readLen) != readLen) {
		throw new std::runtime_error("handleTap() BIO_write() failed");
	}

	int packetCount = 0;

	int readCount;
	while ((readCount = BIO_read(conn->wbio, buf, bufLen)) > 0) {
		int sendBytes = sendto(
			fd, buf, readCount, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr_in));

		if (sendBytes != readCount) {
			throw new std::system_error(std::error_code(errno, std::generic_category()),
				std::string("handleTap() sendto() failed"));
		} else {
			D(std::cout << "handleTap() Send packet to peer" << std::endl;)
			packetCount++;
		}
	}

	return packetCount;
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

		// For now, just create a tap interface
		std::string devName = "astraeus";
		TapDevice tap(devName);

		std::cout << "Create tap dev: " << devName << std::endl;

		SSL_CTX *ctx = DTLS::createClientCTX();

		// Create the server UDP listener socket
		int fd = DTLS::createSocket();
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(struct timeval));

		std::cout << "socket created" << std::endl;

		char buf[2048];

		fd_set rfd, rfds;
		FD_ZERO(&rfds);
		FD_SET(tap.getFd(), &rfds);
		FD_SET(fd, &rfds);
		int maxfd = max(fd, tap.getFd());

		DTLS::Connection conn = DTLS::createClientConn(ctx);

		// Start the handshake
		SSL_connect(conn.ssl);
		handlePacket(fd, conn, buf, 2048, 0, &server, tap);

		while (stopFlag == 0) {
			struct sockaddr_in src_addr;
			socklen_t addrlen = sizeof(struct sockaddr_in);

			rfd = rfds;

			// Call select and wait for something interesting to happen
			int ret = select(maxfd + 1, &rfd, NULL, NULL, NULL);
			if (0 > ret) {
				if (errno == EINTR)
					continue; // that's ok

				throw new std::system_error(std::error_code(errno, std::generic_category()),
					std::string("select() failed"));
			}
			if (0 == ret) {
				continue;
			}

			if (FD_ISSET(fd, &rfd)) {
				// A DTLS packet is ready to be received
				ret = recvfrom(
					fd, (void *)buf, 2048, 0, (struct sockaddr *)&src_addr, &addrlen);
				if (ret < 0) {
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {
						continue;
					} else {
						throw new std::system_error(
							std::error_code(errno, std::generic_category()),
							std::string("main() recvfrom() failed"));
					}
				} else {
					D(std::cout << "received a packet" << std::endl;)
				}

				if (handlePacket(fd, conn, buf, 2048, ret, &src_addr, tap) == 1) {
					stopFlag = 1;
				}
			} else if (FD_ISSET(tap.getFd(), &rfd)) {
				// There is data on the TAP interface
				int readLen = tap.read(buf, 2048);

				D(std::cout << "TAP got data" << std::endl;)
				if (handleTap(fd, buf, 2048, readLen, &conn, server) < 0) {
					throw new std::runtime_error("handleTap() didn't send any packets");
				}
			}
		}

		close(fd);

		std::cout << "Client shutting down..." << std::endl;
	} catch (std::exception *e) {
		std::cout << "Caught exception:" << std::endl;
		std::cout << e->what() << std::endl;
	}
}
