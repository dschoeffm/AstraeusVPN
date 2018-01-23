#include <cstdlib>
#include <iostream>
#include <string>

#include <signal.h>
#include <unistd.h>

#include "common.hpp"
#include "tap.hpp"

static int stopFlag = 0;

void sigHandler(int sig) {
	(void)sig;
	stopFlag = 1;
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;

	signal(SIGINT, sigHandler);

	// For now, just create a tap interface
	std::string devName = "astraeus";
	TapDevice tap(devName);

	std::cout << "Create tap dev: " << devName << std::endl;

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

	std::cout << "Shutting down..." << std::endl;

	return 0;
};
