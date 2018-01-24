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

struct machash {
public:
	std::size_t operator()(const std::array<uint8_t, 6> &x) const {
		uint64_t a, b;
		a = x[0];
		a |= static_cast<uint64_t>(x[1]) << 8;
		a |= static_cast<uint64_t>(x[2]) << 16;

		b = x[3];
		b |= static_cast<uint64_t>(x[4]) << 8;
		b |= static_cast<uint64_t>(x[5]) << 16;

		b = b << 4;

		return a + b;
	}
};

static int stopFlag = 0;

void sigHandler(int sig) {
	(void)sig;
	stopFlag = 1;
}

struct client {
	struct DTLS::Connection conn;
	std::array<uint8_t, 6> mac;
	uint32_t ip;
	uint16_t port;
};

int handlePacket(int fd, struct client *c, char *buf, int bufLen, int recvBytes,
	struct sockaddr_in *src_addr, TapDevice &tap,
	std::unordered_map<std::array<uint8_t, 6>, struct client *, machash> &macToClient) {

	std::cout << "run handlePacket" << std::endl;

	if (BIO_write(c->conn.rbio, buf, recvBytes) != recvBytes) {
		throw new std::runtime_error("handlePacket() BIO_write() failed");
	}

	if (SSL_is_init_finished(c->conn.ssl)) {
		// Here the handshake is already finished

		// Try to read incoming byte from the connection
		int readLen = SSL_read(c->conn.ssl, buf, bufLen);
		if ((readLen <= 0) && (SSL_get_shutdown(c->conn.ssl) == 0)) {
			throw new std::runtime_error("handlePacket() SSL_read() failed");
		}

		// Try to write the incoming bytes to the TAP device
		if (readLen > 0) {
			int writeLen = tap.write(buf, readLen);
			memcpy(c->mac.data(), buf + 6, 6);
			macToClient.insert({c->mac, c});
			if (writeLen < 0) {
				std::cout << "readLen=" << readLen << std::endl;
				throw new std::runtime_error("handlePacket() tap.write() failed");
			} else {
				std::cout << "Written data to TAP" << std::endl;
			}
		}
	} else {
		// We are currently conducting a handshake

		std::cout << "handlePacket() running handshake" << std::endl;

		// The return code is pretty useless, throw it away
		SSL_accept(c->conn.ssl);
	}

	// Write out all data
	int readCount;
	while ((readCount = BIO_read(c->conn.wbio, buf, bufLen)) > 0) {
		int sendBytes = sendto(
			fd, buf, readCount, 0, (struct sockaddr *)src_addr, sizeof(struct sockaddr_in));

		if (sendBytes != readCount) {
			throw new std::system_error(std::error_code(errno, std::generic_category()),
				std::string("handlePacket() sendto() failed"));
		} else {
			std::cout << "handlePacket() Send packet to peer" << std::endl;
		}
	}

	if (SSL_get_shutdown(c->conn.ssl) != 0) {
		if (SSL_shutdown(c->conn.ssl) == 1) {
			SSL_free(c->conn.ssl);
			return 1;
		}
	}

	return 0;
};

int handleTap(int fd, char *buf, int bufLen, int readLen, client *c) {
	if (BIO_write(c->conn.rbio, buf, readLen) != readLen) {
		throw new std::runtime_error("handleTap() BIO_write() failed");
	}
	struct sockaddr_in dst_addr;
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = c->ip;
	dst_addr.sin_port = c->port;

	int packetCount = 0;

	int readCount;
	while ((readCount = BIO_read(c->conn.wbio, buf, bufLen)) > 0) {
		int sendBytes = sendto(
			fd, buf, readCount, 0, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr_in));

		if (sendBytes != readCount) {
			throw new std::system_error(std::error_code(errno, std::generic_category()),
				std::string("handleTap() sendto() failed"));
		} else {
			std::cout << "handleTap() Send packet to peer" << std::endl;
			packetCount++;
		}
	}
	return packetCount;
};

int main(int argc, char **argv) {
	try {
		(void)argc;
		(void)argv;

		signal(SIGINT, sigHandler);

		// For now, just create a tap interface
		std::string devName = "astraeus";
		TapDevice tap(devName);

		std::cout << "Create tap dev: " << devName << std::endl;

		SSL_CTX *ctx = DTLS::createServerCTX("server");

		// Create the server UDP listener socket
		int fd = DTLS::bindSocket(4433);
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(struct timeval));

		std::cout << "bound socket" << std::endl;

		std::unordered_map<std::pair<unsigned long, unsigned short>, struct client *,
			pairhash>
			ipToClient;

		std::unordered_map<std::array<uint8_t, 6>, struct client *, machash> macToClient;

		char buf[2048];

		fd_set rfd, rfds;
		FD_ZERO(&rfds);
		FD_SET(tap.getFd(), &rfds);
		FD_SET(fd, &rfds);
		int maxfd = max(fd, tap.getFd());

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
					std::cout << "received a packet" << std::endl;
				}

				// Look up if there already exists a connection
			conn_lockup:
				auto conn_it = ipToClient.find({src_addr.sin_addr.s_addr, src_addr.sin_port});
				if (conn_it == ipToClient.end()) {
					std::cout << "Connection from new client" << std::endl;
					struct client *c = new client();
					memset(c, 0, sizeof(struct client));
					c->conn = DTLS::createServerConn(ctx);
					c->ip = src_addr.sin_addr.s_addr;
					c->port = src_addr.sin_port;

					ipToClient.insert({{src_addr.sin_addr.s_addr, src_addr.sin_port}, c});
					goto conn_lockup;
				}

				// Just double checking
				if (conn_it == ipToClient.end()) {
					throw new std::runtime_error("conn_it is invalid...");
				}

				if (handlePacket(fd, conn_it->second, buf, 2048, ret, &src_addr, tap,
						macToClient) == 1) {
					struct client *c = conn_it->second;
					ipToClient.erase(conn_it);
					auto macIt = macToClient.find(c->mac);
					if (macIt != macToClient.end()) {
						macToClient.erase(macIt);
					}
				}
			} else if (FD_ISSET(tap.getFd(), &rfd)) {
				// There is data on the TAP interface
				std::array<uint8_t, 6> mac;
				int readLen = tap.read(buf, 2048);
				memcpy(mac.data(), buf, 6);
				auto conn_it = macToClient.find(mac);

				if (conn_it != macToClient.end()) {
					if (handleTap(fd, buf, 2048, readLen, conn_it->second) == 0) {
						throw new std::runtime_error("handleTap() didn't send any packets");
					}
				}
			}
		}

		close(fd);

		std::cout << "Server shutting down..." << std::endl;
	} catch (std::exception *e) {
		std::cout << "Caught exception:" << std::endl;
		std::cout << e->what() << std::endl;
	}
}
