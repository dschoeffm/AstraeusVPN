#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <system_error>

#include "tap.hpp"

// This is based on the Linux Kernel documentation
// /path/to/src/Documentation/networking/tuntap.txt
TapDevice::TapDevice(std::string &devName) {
	struct ifreq ifr;
	int err;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		throw new std::system_error(std::error_code(errno, std::generic_category()),
			std::string("tapAlloc: open() failed"));
	}

	memset(&ifr, 0, sizeof(ifr));

	// We want a tap interface without any added infos
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if (devName != "") {
		strncpy(ifr.ifr_name, devName.c_str(), IFNAMSIZ);
	}

	err = ioctl(fd, TUNSETIFF, (void *)&ifr);

	if (err < 0) {
		int errnoSave = errno;
		close(fd);
		throw new std::system_error(std::error_code(errnoSave, std::generic_category()),
			std::string("tapAlloc: open() failed"));
	}

	devName.assign(ifr.ifr_name);
};

TapDevice::~TapDevice() { close(fd); };

int TapDevice::read(void *buffer, size_t bufLen) { return ::read(fd, buffer, bufLen); };
int TapDevice::write(const void *buffer, size_t bufLen) {
	if (bufLen < 14) {
		return 0;
	}
	return ::write(fd, buffer, bufLen);
};

int TapDevice::getFd() { return fd; };
