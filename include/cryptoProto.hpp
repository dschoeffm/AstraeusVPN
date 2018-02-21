#ifndef CRYPTOPROTO_HPP
#define CRYPTOPROTO_HPP

#include <cstdint>

#include "sodium.h"

namespace AstraeusProto {
struct initMsg {
	static constexpr uint8_t initMsgType = 0;

	uint8_t type;
	uint8_t ecdhe[crypto_kx_PUBLICKEYBYTES];
	uint8_t ecdsa[crypto_sign_PUBLICKEYBYTES];
	uint8_t nonce[16];
} __attribute__((packed));

struct authMsg {
	static constexpr uint8_t authMsgType = 1;

	uint8_t type;
	uint8_t sig[crypto_sign_BYTES];
} __attribute__((packed));

struct tunnelMsg {
	static constexpr uint8_t tunnelMsgType = 2;

	uint8_t type;
	uint8_t nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
	uint8_t mac[crypto_aead_chacha20poly1305_IETF_ABYTES];
} __attribute__((packed));

struct identityHandle {
	uint8_t pubKey[crypto_sign_PUBLICKEYBYTES];
	uint8_t secKey[crypto_sign_SECRETKEYBYTES];
};

struct protoHandle {
	AstraeusProto::initMsg initiator;
	AstraeusProto::initMsg responder;
	uint8_t txKey[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
	uint8_t rxKey[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
	uint8_t txNonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
	uint8_t rxNonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
	uint8_t ecdhPub[crypto_kx_PUBLICKEYBYTES];
	uint8_t ecdhSec[crypto_kx_SECRETKEYBYTES];
	uint8_t peerEcdsaPub[crypto_sign_PUBLICKEYBYTES];
	identityHandle *ident;

	enum { INIT, AUTH, TUNNEL } type;
};

void fillInitMsg(struct initMsg *msg, protoHandle &handle);
void handleInitMsg(struct initMsg *msg, protoHandle &handle);

void fillAuthMsg(struct authMsg *msg, protoHandle &handle);
void handleAuthMsg(struct authMsg *msg, protoHandle &handle);

// Will return 0 if handshake is ongoing
// Will return 1 if tunnel is ready
int handleHandshakeServer(protoHandle &handle, uint8_t *msg, int &sendCount);
int handleHandshakeClient(protoHandle &handle, uint8_t *msg, int &sendCount);

// Generate the identity
void generateIdentity(identityHandle &ident);

// Generate Init message and protoHandle
// Will write init msg into "msg", and handle into "handle"
int generateInit(identityHandle &ident, protoHandle &handle, uint8_t *msg);

void decryptTunnelMsg(uint8_t *msgIn, unsigned int msgInLen, uint8_t *msgOut,
	unsigned int &msgOutLen, protoHandle &handle);
void encryptTunnelMsg(uint8_t *msgIn, unsigned int msgInLen, uint8_t *msgOut,
	unsigned int &msgOutLen, protoHandle &handle);

int bindSocket(int port);
int createSocket();

bool inline handshakeOngoing(protoHandle &handle) {
	if (handle.type == protoHandle::TUNNEL) {
		return false;
	} else {
		return true;
	}
}

}; // namespace AstraeusProto

#endif /* CRYPTOPROTO_HPP */
