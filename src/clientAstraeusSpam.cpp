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

static int stopFlag = 0;

void sigHandler(int sig) {
	(void)sig;
	stopFlag = 1;
}

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

		// Create the server UDP listener socket
		int fd = AstraeusProto::createSocket();
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(struct timeval));

		std::cout << "socket created" << std::endl;

		char buf[2048];

		AstraeusProto::identityHandle ident;
		AstraeusProto::generateIdentity(ident);
		AstraeusProto::protoHandle handle;
		uint8_t nonceSeed[randombytes_SEEDBYTES];

		randombytes_buf(nonceSeed, randombytes_SEEDBYTES);

		AstraeusProto::generateHandle(ident, handle);

		while (stopFlag == 0) {
			int readCount = AstraeusProto::generateInitGivenHandleAndSeed(
				handle, reinterpret_cast<uint8_t *>(buf), nonceSeed);
			sodium_increment(nonceSeed, randombytes_SEEDBYTES);

			int sendBytes = sendto(fd, buf, readCount, 0, (struct sockaddr *)&server,
				sizeof(struct sockaddr_in));
			if (sendBytes != readCount) {
				throw new runtime_error("sendto() failed");
			}
		}

		close(fd);

		std::cout << "Client shutting down..." << std::endl;
	} catch (std::exception *e) {
		std::cout << "Caught exception:" << std::endl;
		std::cout << e->what() << std::endl;
	}
}
