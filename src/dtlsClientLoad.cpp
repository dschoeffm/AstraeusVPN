#include <array>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>

#include <thread>

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
	struct sockaddr_in *src_addr, uint8_t *wData, unsigned int wDataLen,
	uint64_t &totalSent) {

	DEBUG_ENABLED(std::cout << "run handlePacket" << std::endl;)

	int totalRead = 0;
	int totalRecv = 0;
	int written = 0;

	if (recvBytes > 0) {
		if (BIO_write(conn.rbio, buf, recvBytes) != recvBytes) {
			throw new std::runtime_error("handlePacket() BIO_write() failed");
		}
	}

	if (SSL_is_init_finished(conn.ssl)) {
		// Here the handshake is already finished

		// Try to read incoming byte from the connection
		int readLen = SSL_read(conn.ssl, buf, bufLen);
		totalRead += readLen;
		if ((readLen <= 0) && (SSL_get_shutdown(conn.ssl) == 0)) {
			throw new std::runtime_error("handlePacket() SSL_read() failed");
		}

		// Throw the data away
		(void)buf;
	} else {
		// We are currently conducting a handshake

		std::cout << "handlePacket() running handshake" << std::endl;

		// The return code is pretty useless, throw it away
		SSL_connect(conn.ssl);

		if (SSL_is_init_finished(conn.ssl)) {
			std::cout << "handlePacket() Handshake finished" << std::endl;
			std::cout << "Algorith: " << SSL_get_cipher_name(conn.ssl)
					  << " Keylength: " << SSL_get_cipher_bits(conn.ssl, nullptr)
					  << std::endl;
			int written = 0;
			while (written < wDataLen) {
				written += SSL_write(conn.ssl, wData + written, 500);

				// int totalRead = 0;
				int readCount;
				// while(totalRead < written){
				while ((readCount = BIO_read(conn.wbio, buf, 1400)) > 0) {
					totalRead += readCount;
					int sendBytes = sendto(fd, buf, readCount, 0, (struct sockaddr *)src_addr,
						sizeof(struct sockaddr_in));

					if (sendBytes != readCount) {
						throw new std::system_error(
							std::error_code(errno, std::generic_category()),
							std::string("handlePacket() sendto() failed"));
					} else {
						DEBUG_ENABLED(
							std::cout << "handlePacket() Send packet to peer" << std::endl;)
						totalSent += sendBytes;
					}
				}
				//}

				socklen_t addrlen = sizeof(struct sockaddr_in);

				int ret = recvfrom(fd, (void *)buf, 1400, MSG_DONTWAIT, NULL, NULL);
				if (ret > 0) {
					totalRecv += ret;
				}
				/*
				if(ret > 0){
					std::cout << "got packet" << std::endl;
					if (BIO_write(conn.rbio, buf, recvBytes) != recvBytes) {
						throw new std::runtime_error("handlePacket() BIO_write() failed");
					}
					ret = SSL_read(conn.ssl, buf, bufLen);
					if(ret > 0){
						totalRecv += ret;
					} else {
						std::cout << "ret was <0" << std::endl;
					}
				}
				*/
			}
		}
	}

	// Write out all data
	int readCount;
	while ((readCount = BIO_read(conn.wbio, buf, 1400)) > 0) {
		int sendBytes = sendto(
			fd, buf, readCount, 0, (struct sockaddr *)src_addr, sizeof(struct sockaddr_in));

		if (sendBytes != readCount) {
			throw new std::system_error(std::error_code(errno, std::generic_category()),
				std::string("handlePacket() sendto() failed"));
		} else {
			DEBUG_ENABLED(std::cout << "handlePacket() Send packet to peer" << std::endl;)
			totalSent += sendBytes;
		}
	}

	DEBUG_ENABLED(std::cout << "Waiting to receive all the data" << std::endl;)

	int counter = 0;
	while ((totalRecv < totalRead) && (stopFlag == 0) && (counter < 5)) {
		socklen_t addrlen = sizeof(struct sockaddr_in);

		int ret = recvfrom(fd, (void *)buf, 1400, 0, (struct sockaddr *)&src_addr, &addrlen);
		if (ret > 0) {
			totalRecv += ret;
		} else {
			counter++;
		}
		/*
		if(ret > 0){
			if (BIO_write(conn.rbio, buf, recvBytes) != recvBytes) {
				throw new std::runtime_error("handlePacket() BIO_write() failed");
			}
			ret = SSL_read(conn.ssl, buf, bufLen);
			if(ret > 0){
				totalRecv += ret;
			}
		}
		*/
	}

	if (counter > 1) {
		std::cout << "shutdown because of counter" << std::endl;
		return 1;
	}

	// if ((SSL_get_shutdown(conn.ssl) != 0) || (totalSent >= wDataLen)) {
	if (SSL_shutdown(conn.ssl) == 1) {
		SSL_free(conn.ssl);
		return 1;
	}
	//}

	return 0;
};

void runThread(
	struct sockaddr_in server, SSL_CTX *ctx, uint8_t *wData, unsigned int wDataLen) {

	int ret;

	uint64_t totalSent = 0;

	int fd = DTLS::createSocket();
	connect(fd, reinterpret_cast<sockaddr *>(&server), sizeof(struct sockaddr_in));

	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(struct timeval));

	DTLS::Connection conn = DTLS::createClientConn(ctx);

	char buf[1400];

	try {

		// Start the handshake
		SSL_connect(conn.ssl);
		handlePacket(fd, conn, buf, 1400, 0, &server, wData, wDataLen, totalSent);

		while (stopFlag == 0) {
			struct sockaddr_in src_addr;
			socklen_t addrlen = sizeof(struct sockaddr_in);

			// A DTLS packet is ready to be received
			ret = recvfrom(fd, (void *)buf, 1400, 0, (struct sockaddr *)&src_addr, &addrlen);
			if (ret < 0) {
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR)) {

					// See if we can send data
					int readCount;
					while ((readCount = BIO_read(conn.wbio, buf, 1400)) > 0) {
						int sendBytes = sendto(fd, buf, readCount, 0,
							(struct sockaddr *)&src_addr, sizeof(struct sockaddr_in));

						if (sendBytes != readCount) {
							throw new std::system_error(
								std::error_code(errno, std::generic_category()),
								std::string("handlePacket() sendto() failed"));
						} else {
							DEBUG_ENABLED(std::cout << "handlePacket() Send packet to peer"
													<< std::endl;)
							totalSent += sendBytes;
						}
					}

					continue;
				} else {
					throw new std::system_error(
						std::error_code(errno, std::generic_category()),
						std::string("main() recvfrom() failed"));
				}
			} else {
				DEBUG_ENABLED(std::cout << "received a packet" << std::endl;)
			}

			if (handlePacket(
					fd, conn, buf, 1400, ret, &src_addr, wData, wDataLen, totalSent) == 1) {
				stopFlag = 1;
			}
		}
	} catch (std::exception *e) {
		std::cout << "Caugth exception: " << e->what() << std::endl;
	}

	close(fd);
}

void usage(string name) {
	cout << "Usage: " << name << " <server IP> <server port> <numConns> <DataLen>" << endl;
	exit(0);
}

int main(int argc, char **argv) {
	try {
		if (argc < 5) {
			usage(string(argv[0]));
		}

		int numConns = atoi(argv[3]);
		int DataLen = atoi(argv[4]);

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

		uint8_t *wData = reinterpret_cast<uint8_t *>(malloc(DataLen));

		/*
				std::thread *threads =
					reinterpret_cast<std::thread *>(malloc(sizeof(std::thread) * numConns));

				for (int i = 0; i < numConns; i++) {
					threads[i] = std::thread(runThread, server, ctx, wData, DataLen);
					server.sin_port = htons(ntohs(server.sin_port) + 1);
				}
		*/

		std::thread threads[512];

		for (int i = 0; i < numConns; i++) {
			threads[i] = std::thread(runThread, server, ctx, wData, DataLen);
			server.sin_port = htons(ntohs(server.sin_port) + 1);
		}

		for (int i = 0; i < numConns; i++) {
			threads[i].join();
		}

		std::cout << "Client shutting down..." << std::endl;
	} catch (std::exception *e) {
		std::cout << "Caught exception:" << std::endl;
		std::cout << e->what() << std::endl;
	}
}
