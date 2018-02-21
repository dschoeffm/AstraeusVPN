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

int handlePacket(int fd, struct client *c, char *buf, int bufLen, int recvBytes,
	struct sockaddr_in *src_addr, macTable &macToClient) {
	(void)bufLen;

	if (c->handshake) {
		int sendCount;
		int ret = AstraeusProto::handleHandshakeServer(
			c->handle, reinterpret_cast<uint8_t *>(buf), sendCount);

		if (ret == 1) {
			c->handshake = false;
		}

		if (sendCount > 0) {
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

		std::cout << "handlePacket() hexdump of packet" << std::endl;
		hexdump(outBuf, outBufLen);

		memcpy(c->mac.data(), buf + 6, 6);
		macToClient.insert({c->mac, c});
	}

	return 0;
}

void selectThread(int fd, ipTable *ipToClient, macTable *macToClient,
	AstraeusProto::identityHandle *ident) {
	char buf[2048];

	try {
		while (stopFlag == 0) {
			struct sockaddr_in src_addr;
			socklen_t addrlen = sizeof(struct sockaddr_in);
			int ret;

			ret = recvfrom(fd, (void *)buf, 2048, 0, (struct sockaddr *)&src_addr, &addrlen);
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
			if (!ipToClient->find(connIt, {src_addr.sin_addr.s_addr, src_addr.sin_port})) {
				std::cout << "Connection from new client" << std::endl;
				struct client *c = new client();
				memset(c, 0, sizeof(struct client));
				AstraeusProto::generateHandle(*ident, c->handle);
				c->handshake = true;
				c->ip = src_addr.sin_addr.s_addr;
				c->port = src_addr.sin_port;

				ipToClient->insert(
					connIt, {{src_addr.sin_addr.s_addr, src_addr.sin_port}, c});
			}

			if (handlePacket(fd, connIt->second, buf, 2048, ret, &src_addr, *macToClient) ==
				1) {
				struct client *c = connIt->second;
				ipToClient->erase(connIt);
				macToClient->erase(c->mac);
				c->mtx.lock();
				delete (c);
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

		AstraeusProto::identityHandle ident;
		AstraeusProto::generateIdentity(ident);

		for (int i = 0; i < NUM_THREADS; i++) {

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
					new std::thread(selectThread, fds[i], &ipToClient, &macToClient, &ident);
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
