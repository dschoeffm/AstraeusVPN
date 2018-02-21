#include <array>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <cstring>
#include <signal.h>
#include <sys/select.h>
#include <unistd.h>

#include <tbb/concurrent_hash_map.h>
#include <tbb/spin_mutex.h>

#include "common.hpp"
#include "cryptoProto.hpp"
#include "tap.hpp"

using namespace std;
// using namespace tbb;

#define NUM_THREADS 8

// Taken from:
// https://stackoverflow.com/a/20602159
struct pairhash {
public:
	template <typename T, typename U> std::size_t operator()(const std::pair<T, U> &x) const {
		return std::hash<T>()(x.first) ^ std::hash<U>()(x.second);
	}

	template <typename T, typename U> static std::size_t hash(const std::pair<T, U> &x) {
		return std::hash<T>()(x.first) ^ std::hash<U>()(x.second);
	}

	template <typename T, typename U>
	static bool equal(const std::pair<T, U> &x, const std::pair<T, U> &y) {
		return (x.first == y.first) && (x.second == y.second);
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

	static std::size_t hash(const std::array<uint8_t, 6> &x) {
		machash m;
		return m(x);
	}

	static bool equal(const std::array<uint8_t, 6> &x, const std::array<uint8_t, 6> &y) {
		return !memcmp(x.data(), y.data(), 6);
	}
};

using ipTable = tbb::concurrent_hash_map<std::pair<unsigned long, unsigned short>,
	struct client *, pairhash>;
using macTable = tbb::concurrent_hash_map<std::array<uint8_t, 6>, struct client *, machash>;

static int stopFlag = 0;

void sigHandler(int sig) {
	(void)sig;
	stopFlag = 1;
}

struct client {
	AstraeusProto::protoHandle handle;
	bool handshake;

	std::array<uint8_t, 6> mac;
	uint32_t ip;
	uint16_t port;
	tbb::spin_mutex mtx;
};

#if 0
int handlePacket(int fd, struct client *c, char *buf, int bufLen, int recvBytes,
	struct sockaddr_in *src_addr, TapDevice &tap, macTable &macToClient) {

	D(std::cout << "run handlePacket" << std::endl;)

	std::lock_guard<tbb::spin_mutex> lckGuard(c->mtx);

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
				D(std::cout << "Written data to TAP" << std::endl;)
			}
		}
	} else {
		// We are currently conducting a handshake

		std::cout << "handlePacket() running handshake" << std::endl;

		// The return code is pretty useless, throw it away
		SSL_accept(c->conn.ssl);

		if (SSL_is_init_finished(c->conn.ssl)) {
			std::cout << "handlePacket() Handshake finished" << std::endl;
			std::cout << "Algorith: " << SSL_get_cipher_name(c->conn.ssl)
					  << " Keylength: " << SSL_get_cipher_bits(c->conn.ssl, nullptr)
					  << std::endl;
		}
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
			D(std::cout << "handlePacket() Send packet to peer" << std::endl;)
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
#endif

int handlePacket(int fd, struct client *c, char *buf, int bufLen, int recvBytes,
	struct sockaddr_in *src_addr, TapDevice &tap, macTable &macToClient) {
	(void)bufLen;

	if (c->handshake) {
		int sendCount;
		int ret = AstraeusProto::handleHandshakeServer(
			c->handle, reinterpret_cast<uint8_t *>(buf), sendCount);
		if (ret == 1) {
			c->handshake = false;
		} else {
			int sendBytes = sendto(fd, buf, sendCount, 0, (struct sockaddr *)src_addr,
				sizeof(struct sockaddr_in));
			if (sendBytes != sendCount) {
				throw new std::runtime_error("handlePacket() sendto() failed");
			}
		}
	} else {
		uint8_t outBuf[2048];
		unsigned int outBufLen;
		decryptTunnelMsg(
			reinterpret_cast<uint8_t *>(buf), recvBytes, outBuf, outBufLen, c->handle);
		int writeLen = tap.write(outBuf, outBufLen);
		memcpy(c->mac.data(), buf + 6, 6);
		macToClient.insert({c->mac, c});

		if (writeLen < 0) {
			throw new std::runtime_error("handlePacket() tap.write() failed");
		} else {
			D(std::cout << "Written data to TAP" << std::endl;)
		}
	}

	return 0;
}

int handleTap(int fd, char *buf, int bufLen, int readLen, client *c) {
	(void)bufLen;

	std::lock_guard<tbb::spin_mutex> lckGuard(c->mtx);

	uint8_t outBuf[2048];
	unsigned int outBufLen;
	AstraeusProto::encryptTunnelMsg(
		reinterpret_cast<uint8_t *>(buf), readLen, outBuf, outBufLen, c->handle);

	struct sockaddr_in dst_addr;
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = c->ip;
	dst_addr.sin_port = c->port;

	int sendBytes = sendto(
		fd, outBuf, outBufLen, 0, (struct sockaddr *)&dst_addr, sizeof(struct sockaddr_in));

	if (sendBytes != static_cast<int>(outBufLen)) {
		throw new std::system_error(std::error_code(errno, std::generic_category()),
			std::string("handleTap() sendto() failed"));
	} else {
		D(std::cout << "handleTap() Send packet to peer" << std::endl;)
	}

	return 0;
};

void selectThread(
	int fd, std::shared_ptr<TapDevice> tap, ipTable *ipToClient, macTable *macToClient) {
	fd_set rfd, rfds;
	FD_ZERO(&rfds);
	FD_SET(tap->getFd(), &rfds);
	FD_SET(fd, &rfds);
	int maxfd = max(fd, tap->getFd());
	char buf[2048];
	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	try {
		while (stopFlag == 0) {
			struct sockaddr_in src_addr;
			socklen_t addrlen = sizeof(struct sockaddr_in);

			rfd = rfds;

			// Call select and wait for something interesting to happen
			int ret = select(maxfd + 1, &rfd, NULL, NULL, &tv);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			if (0 > ret) {
				if (errno == EINTR) {
					std::cout << "select() returned after EINTR" << std::endl;
					continue; // that's ok
				}

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
							std::string("selectThread() recvfrom() failed"));
					}
				} else {
					D(std::cout << "received a packet" << std::endl;)
				}

				ipTable::accessor connIt;
				if (!ipToClient->find(
						connIt, {src_addr.sin_addr.s_addr, src_addr.sin_port})) {
					std::cout << "Connection from new client" << std::endl;
					struct client *c = new client();
					memset(c, 0, sizeof(struct client));
					c->handshake = true;
					c->ip = src_addr.sin_addr.s_addr;
					c->port = src_addr.sin_port;

					ipToClient->insert(
						connIt, {{src_addr.sin_addr.s_addr, src_addr.sin_port}, c});
				}

				if (handlePacket(fd, connIt->second, buf, 2048, ret, &src_addr, *tap,
						*macToClient) == 1) {
					struct client *c = connIt->second;
					ipToClient->erase(connIt);
					macToClient->erase(c->mac);
					c->mtx.lock();
					delete (c);
				}

			} else if (FD_ISSET(tap->getFd(), &rfd)) {
				// There is data on the TAP interface
				std::array<uint8_t, 6> mac;
				int readLen = tap->read(buf, 2048);
				memcpy(mac.data(), buf, 6);

				macTable::accessor connIt;
				if (macToClient->find(connIt, mac)) {
					if (handleTap(fd, buf, 2048, readLen, connIt->second) == 0) {
						throw new std::runtime_error("handleTap() didn't send any packets");
					}
				}
			}
		}
	} catch (std::exception *e) {
		cout << "Caught exception: " << e->what() << std::endl;
		exit(1);
	}

	close(fd);
};

int main(int argc, char **argv) {
	try {
		(void)argc;
		(void)argv;

		signal(SIGINT, sigHandler);

		int fds[NUM_THREADS];
		ipTable ipToClient;
		macTable macToClient;
		std::thread *selectThreads[NUM_THREADS];

		for (int i = 0; i < NUM_THREADS; i++) {

			// For now, just create a tap interface
			std::string devName = "astraeus";
			auto tap = std::make_shared<TapDevice>(devName);

			std::cout << "Create tap dev: " << devName << std::endl;

			// Create the server UDP listener socket
			fds[i] = AstraeusProto::bindSocket(4433);
			struct timeval tv;
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			setsockopt(
				fds[i], SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(struct timeval));

			std::cout << "bound socket" << std::endl;

			try {
				selectThreads[i] =
					new std::thread(selectThread, fds[i], tap, &ipToClient, &macToClient);
			} catch (std::exception *e) {
				cout << "Caught exception: " << e->what() << std::endl;
				exit(1);
			}
		}

		for (int i = 0; i < NUM_THREADS; i++) {
			try {
				selectThreads[i]->join();
				delete (selectThreads[i]);
			} catch (std::exception *e) {
				cout << "Caught exception: " << e->what() << std::endl;
				exit(1);
			}
		}

		std::cout << "Server shutting down..." << std::endl;
	} catch (std::exception *e) {
		std::cout << "Caught exception:" << std::endl;
		std::cout << e->what() << std::endl;
	}
}
