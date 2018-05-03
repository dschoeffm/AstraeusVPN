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
//#include "dtls.hpp"
#include "cryptoProto.hpp"
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

int handlePacket(int fd, AstraeusProto::protoHandle &handle, char *buf, int bufLen,
	int recvBytes, struct sockaddr_in *src_addr, TapDevice &tap) {

	(void)bufLen;

	DEBUG_ENABLED(std::cout << "run handlePacket" << std::endl;)

	if (!AstraeusProto::handshakeOngoing(handle)) {
		// Here the handshake is already finished

		// Try to read incoming byte from the connection
		uint8_t bufOut[2048];
		unsigned int bufOutLen;
		AstraeusProto::decryptTunnelMsg(
			reinterpret_cast<uint8_t *>(buf), recvBytes, bufOut, bufOutLen, handle);

		// Try to write the incoming bytes to the TAP device
		if (bufOutLen > 0) {
			int writeLen = tap.write(bufOut, bufOutLen);
			if (writeLen < 0) {
				std::cout << "bufOutLen=" << bufOutLen << std::endl;
				throw new std::runtime_error("handlePacket() tap.write() failed");
			} else {
				DEBUG_ENABLED(std::cout << "Written data to TAP" << std::endl;)
			}
		} else {
			throw new std::runtime_error("handlePacket() bufOutLen <= 0");
		}
	} else {
		// We are currently conducting a handshake
		int sendCount;
		handleHandshakeClient(handle, reinterpret_cast<uint8_t *>(buf), sendCount);

		std::cout << "handlePacket() running handshake" << std::endl;

		if (sendCount > 0) {
			int sendBytes = sendto(fd, buf, sendCount, 0, (struct sockaddr *)src_addr,
				sizeof(struct sockaddr_in));
			if (sendBytes != sendCount) {
				throw new std::runtime_error("handlePacket() sendto() failed");
			}
		}
	}

	return 0;
};

int handleTap(int fd, char *buf, int bufLen, int readLen, AstraeusProto::protoHandle &handle,
	struct sockaddr_in dst) {

	(void)bufLen;

	uint8_t bufOut[2048];
	unsigned int bufOutLen;

	encryptTunnelMsg(reinterpret_cast<uint8_t *>(buf), readLen, bufOut, bufOutLen, handle);

	int sendBytes =
		sendto(fd, bufOut, bufOutLen, 0, (struct sockaddr *)&dst, sizeof(struct sockaddr_in));

	if (sendBytes != static_cast<int>(bufOutLen)) {
		throw new std::system_error(std::error_code(errno, std::generic_category()),
			std::string("handleTap() sendto() failed"));
	} else {
		DEBUG_ENABLED(std::cout << "handleTap() Send packet to peer" << std::endl;)
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

		// For now, just create a tap interface
		std::string devName = "astraeus";
		TapDevice tap(devName);

		std::cout << "Create tap dev: " << devName << std::endl;

		// Create the server UDP listener socket
		int fd = AstraeusProto::createSocket();
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

		AstraeusProto::identityHandle ident;
		AstraeusProto::generateIdentity(ident);
		AstraeusProto::protoHandle handle;
		int readCount =
			AstraeusProto::generateInit(ident, handle, reinterpret_cast<uint8_t *>(buf));

		int sendBytes = sendto(
			fd, buf, readCount, 0, (struct sockaddr *)&server, sizeof(struct sockaddr_in));
		if (sendBytes != readCount) {
			throw new runtime_error("sendto() failed");
		}

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
					DEBUG_ENABLED(std::cout << "received a packet" << std::endl;)
				}

				if (handlePacket(fd, handle, buf, 2048, ret, &src_addr, tap) == 1) {
					stopFlag = 1;
				}
			} else if (FD_ISSET(tap.getFd(), &rfd)) {
				// There is data on the TAP interface
				int readLen = tap.read(buf, 2048);

				DEBUG_ENABLED(std::cout << "TAP got data" << std::endl;)
				if (handleTap(fd, buf, 2048, readLen, handle, server) < 0) {
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
