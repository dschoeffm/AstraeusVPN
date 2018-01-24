#ifndef TAP_HPP
#define TAP_HPP

#include <cstdint>
#include <string>

class TapDevice {
private:
	int fd;

public:
	TapDevice(std::string &devName);
	~TapDevice();

	int read(void *buffer, size_t bufLen);
	int write(const void *buffer, size_t bufLen);

	int getFd();
};

#endif /* TAP_HPP */
