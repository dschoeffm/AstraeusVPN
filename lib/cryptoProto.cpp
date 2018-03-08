#include <cassert>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <system_error>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "common.hpp"
#include "cryptoProto.hpp"

using namespace AstraeusProto;

void AstraeusProto::fillInitMsg(struct initMsg *msg, protoHandle &handle) {

	memcpy(msg->ecdhe, handle.ecdhPub, crypto_kx_PUBLICKEYBYTES);
	randombytes_buf(msg->nonce, sizeof(msg->nonce));
	memcpy(handle.txNonce, msg->nonce, sizeof(msg->nonce));
	msg->type = AstraeusProto::initMsg::initMsgType;
	memcpy(msg->ecdsa, handle.ident->pubKey, sizeof(msg->ecdsa));

	DEBUG_ENABLED(std::cout << "fillInitMsg() init msg:" << std::endl;)
	DEBUG_ENABLED(hexdump(msg, sizeof(struct initMsg));)

	// handle.type = protoHandle::INIT;
};

void AstraeusProto::fillInitMsgSeed(struct initMsg *msg, protoHandle &handle,
	const uint8_t nonceSeed[randombytes_SEEDBYTES]) {

	memcpy(msg->ecdhe, handle.ecdhPub, crypto_kx_PUBLICKEYBYTES);
	randombytes_buf_deterministic(msg->nonce, sizeof(msg->nonce), nonceSeed);
	memcpy(handle.txNonce, msg->nonce, sizeof(msg->nonce));
	msg->type = AstraeusProto::initMsg::initMsgType;
	memcpy(msg->ecdsa, handle.ident->pubKey, sizeof(msg->ecdsa));

	DEBUG_ENABLED(std::cout << "fillInitMsg() init msg:" << std::endl;)
	DEBUG_ENABLED(hexdump(msg, sizeof(struct initMsg));)

	// handle.type = protoHandle::INIT;
};

void AstraeusProto::fillInitMsgNonce(
	struct initMsg *msg, protoHandle &handle, const uint8_t nonce[ASTRAEUSPROTONONCELEN]) {

	memcpy(msg->ecdhe, handle.ecdhPub, crypto_kx_PUBLICKEYBYTES);
	memcpy(msg->nonce, nonce, sizeof(msg->nonce));
	memcpy(handle.txNonce, msg->nonce, sizeof(msg->nonce));
	msg->type = AstraeusProto::initMsg::initMsgType;
	memcpy(msg->ecdsa, handle.ident->pubKey, sizeof(msg->ecdsa));

	DEBUG_ENABLED(std::cout << "fillInitMsg() init msg:" << std::endl;)
	DEBUG_ENABLED(hexdump(msg, sizeof(struct initMsg));)

	// handle.type = protoHandle::INIT;
};

void AstraeusProto::handleInitMsg(struct initMsg *msg, protoHandle &handle, bool client) {
	if (handle.type != protoHandle::INIT) {
		throw new std::runtime_error("handleInitMsg() current state is not init");
	}

	if (msg->type != initMsg::initMsgType) {
		throw new std::runtime_error("handleInitMsg() msg is not init");
	}

	DEBUG_ENABLED(
		std::cout << std::endl
				  << "AstraeusProto::handleInitMsg() own ecdh public key:" << std::endl;)
	DEBUG_ENABLED(hexdump(&handle.ecdhPub, sizeof(handle.ecdhPub));)
	DEBUG_ENABLED(
		std::cout << "AstraeusProto::handleInitMsg() peer ecdh public key:" << std::endl;)
	DEBUG_ENABLED(hexdump(msg->ecdhe, sizeof(msg->ecdhe));)

#ifndef ASTRAEUS_PSK
	// Create the session keys
	if (client) {
		if (crypto_kx_client_session_keys(handle.rxKey, handle.txKey, handle.ecdhPub,
				handle.ecdhSec, msg->ecdhe) != 0) {
			throw new std::runtime_error("handleInitMsg() key exchange failed");
		}
	} else {
		if (crypto_kx_server_session_keys(handle.rxKey, handle.txKey, handle.ecdhPub,
				handle.ecdhSec, msg->ecdhe) != 0) {
			throw new std::runtime_error("handleInitMsg() key exchange failed");
		}
	}
#else

	/*
	 * XXX
	 * XXX This is just a toy experiment and should never be used
	 * XXX
	 */

	unsigned char keyid[crypto_generichash_blake2b_SALTBYTES] = {0};
	const unsigned char appid[crypto_generichash_blake2b_PERSONALBYTES] = {0};
	unsigned char masterkey[sizeof(handle.txNonce) * 2 + sizeof(handle.ecdhPub) * 2 + 16] = {
		0};

	unsigned char psk[16] = {0};

	if (client) {
		memcpy(masterkey, handle.txNonce, sizeof(handle.txNonce));
		memcpy(masterkey + sizeof(handle.txNonce), handle.rxNonce, sizeof(handle.rxNonce));
		memcpy(
			masterkey + sizeof(handle.txNonce) * 2, handle.ecdhPub, sizeof(handle.ecdhPub));
		memcpy(masterkey + sizeof(handle.txNonce) * 2 + sizeof(handle.ecdhPub), msg->ecdhe,
			sizeof(msg->ecdhe));
		memcpy(masterkey + sizeof(handle.txNonce) * 2 + sizeof(handle.ecdhPub) * 2, psk, 16);

		crypto_generichash_blake2b_salt_personal(handle.txKey, sizeof(handle.txKey), NULL, 0,
			masterkey, sizeof(masterkey), keyid, appid);

		sodium_increment(keyid, sizeof keyid);

		crypto_generichash_blake2b_salt_personal(handle.rxKey, sizeof(handle.rxKey), NULL, 0,
			masterkey, sizeof(masterkey), keyid, appid);
	} else {
		memcpy(masterkey, handle.rxNonce, sizeof(handle.rxNonce));
		memcpy(masterkey + sizeof(handle.rxNonce), handle.txNonce, sizeof(handle.txNonce));
		memcpy(masterkey + sizeof(handle.txNonce) * 2, msg->ecdhe, sizeof(msg->ecdhe));
		memcpy(masterkey + sizeof(handle.txNonce) * 2 + sizeof(handle.ecdhPub),
			handle.ecdhPub, sizeof(handle.ecdhPub));
		memcpy(masterkey + sizeof(handle.txNonce) * 2 + sizeof(handle.ecdhPub) * 2, psk, 16);

		crypto_generichash_blake2b_salt_personal(handle.rxKey, sizeof(handle.rxKey), NULL, 0,
			masterkey, sizeof(masterkey), keyid, appid);

		sodium_increment(keyid, sizeof keyid);

		crypto_generichash_blake2b_salt_personal(handle.txKey, sizeof(handle.txKey), NULL, 0,
			masterkey, sizeof(masterkey), keyid, appid);
	}
#endif

	DEBUG_ENABLED(std::cout << "AstraeusProto::handleInitMsg() own rx key:" << std::endl;)
	DEBUG_ENABLED(hexdump(&handle.rxKey, sizeof(handle.rxKey));)
	DEBUG_ENABLED(std::cout << "AstraeusProto::handleInitMsg() own tx key:" << std::endl;)
	DEBUG_ENABLED(hexdump(&handle.txKey, sizeof(handle.txKey));)

	memcpy(handle.peerEcdsaPub, msg->ecdsa, sizeof(handle.peerEcdsaPub));
	memcpy(handle.rxNonce, msg->nonce, sizeof(handle.rxNonce));

	// handle.type = protoHandle::AUTH;

	/*
	 * XXX At this point, a peer would think about accepting the ECDSA key
	 * XXX This would be done against a database, or by similar means
	 * XXX An attack on this implementation is obvious
	 */
};

void AstraeusProto::fillAuthMsg(struct authMsg *msg, protoHandle &handle) {
	if (handle.type != protoHandle::AUTH) {
		throw new std::runtime_error("fillAuthMsg() current state is not auth");
	}

	msg->type = AstraeusProto::authMsg::authMsgType;

	crypto_sign_detached(msg->sig, NULL, reinterpret_cast<uint8_t *>(&handle.sigHeader),
		sizeof(handle.sigHeader), handle.ident->secKey);

	DEBUG_ENABLED(std::cout << std::endl
							<< "fillAuthMsg() Signature public key:" << std::endl;)
	DEBUG_ENABLED(hexdump(handle.ident->pubKey, sizeof(handle.ident->pubKey));)

	DEBUG_ENABLED(std::cout << "fillAuthMsg() Signature in message:" << std::endl;)
	DEBUG_ENABLED(hexdump(msg->sig, sizeof(msg->sig));)

	DEBUG_ENABLED(std::cout << "fillAuthMsg() auth msg:" << std::endl;)
	DEBUG_ENABLED(hexdump(msg, sizeof(struct authMsg));)

	if (crypto_sign_verify_detached(msg->sig, reinterpret_cast<uint8_t *>(&handle.sigHeader),
			sizeof(handle.sigHeader), handle.ident->pubKey) != 0) {
		throw new std::runtime_error("fillAuthMsg() own signature verification failed");
	}
};

void AstraeusProto::handleAuthMsg(struct authMsg *msg, protoHandle &handle) {
	if (handle.type != protoHandle::AUTH) {
		throw new std::runtime_error("handleAuthMsg() current state is not auth");
	}

	if (msg->type != authMsg::authMsgType) {
		throw new std::runtime_error("handleAuthMsg() msg is not auth");
	}

	int ret =
		crypto_sign_verify_detached(msg->sig, reinterpret_cast<uint8_t *>(&handle.sigHeader),
			sizeof(handle.sigHeader), handle.peerEcdsaPub);

	if (ret != 0) {
		std::cout << "handleAuthMsg() Signature error" << std::endl;
		std::cout << "handleAuthMsg() Signature public key:" << std::endl;
		hexdump(&handle.peerEcdsaPub, sizeof(handle.peerEcdsaPub));
		std::cout << "handleAuthMsg() Signature header:" << std::endl;
		hexdump(&handle.sigHeader, sizeof(handle.sigHeader));

		throw new std::runtime_error(
			"AstraeusProto::handleAuthMsg() Signature doesn't match");
	}

	assert(crypto_aead_chacha20poly1305_IETF_KEYBYTES == crypto_kx_SESSIONKEYBYTES);

	memset(handle.rxNonce, 0, sizeof(handle.rxNonce));
	memset(handle.txNonce, 0, sizeof(handle.txNonce));

	// handle.type = protoHandle::TUNNEL;
};

void AstraeusProto::decryptTunnelMsg(uint8_t *msgIn, unsigned int msgInLen, uint8_t *msgOut,
	unsigned int &msgOutLen, protoHandle &handle) {
	int ret;

	tunnelMsg *header = reinterpret_cast<tunnelMsg *>(msgIn);

	if (header->type != AstraeusProto::tunnelMsg::tunnelMsgType) {
		std::cout << "AstraeusProto::decryptTunnelMsg() type="
				  << static_cast<int>(header->type) << std::endl;
		throw new std::runtime_error("AstraeusProto::decryptTunnelMsg() Msg type is wrong");
	}

	if (sodium_compare(handle.rxNonce, header->nonce, sizeof(handle.rxNonce)) != -1) {
		std::cout << "AstraeusProto::decryptTunnelMsg() saved nonce:" << std::endl;
		hexdump(handle.rxNonce, sizeof(handle.rxNonce));
		std::cout << "AstraeusProto::decryptTunnelMsg() received nonce:" << std::endl;
		hexdump(header->nonce, sizeof(header->nonce));
		throw new std::runtime_error("AstraeusProto::decryptTunnelMsg() Unexpected nonce");
	}

	uint8_t *payload = msgIn + sizeof(tunnelMsg);
	ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached(msgOut, NULL, payload,
		msgInLen - sizeof(struct tunnelMsg), header->mac, header->nonce,
		sizeof(header->nonce), header->nonce, handle.rxKey);

	msgOutLen = msgInLen - sizeof(struct tunnelMsg);
	memcpy(handle.rxNonce, header->nonce, sizeof(handle.rxNonce));

	if (ret != 0) {
		throw new std::runtime_error("AstraeusProto::decryptTunnelMsg() decryption failed");
	}
};

void AstraeusProto::encryptTunnelMsg(uint8_t *msgIn, unsigned int msgInLen, uint8_t *msgOut,
	unsigned int &msgOutLen, protoHandle &handle) {
	int ret;

	sodium_increment(handle.txNonce, sizeof(handle.txNonce));

	tunnelMsg *header = reinterpret_cast<tunnelMsg *>(msgOut);
	header->type = tunnelMsg::tunnelMsgType;

	uint8_t *payload = msgOut + sizeof(tunnelMsg);
	memcpy(header->nonce, handle.txNonce, sizeof(header->nonce));

	ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(payload, header->mac, NULL,
		msgIn, msgInLen, header->nonce, sizeof(header->nonce), NULL, header->nonce,
		handle.txKey);

	if (ret != 0) {
		throw new std::runtime_error("AstraeusProto::encryptTunnelMsg() encryption failed");
	}
	msgOutLen = msgInLen + sizeof(tunnelMsg);
};

int AstraeusProto::handleHandshakeServer(protoHandle &handle, uint8_t *msg, int &sendCount) {
	switch (handle.type) {
	case protoHandle::INIT:
		handleInitMsg(reinterpret_cast<initMsg *>(msg), handle, false);
		memcpy(handle.sigHeader.ecdheInitiator, reinterpret_cast<initMsg *>(msg)->ecdhe,
			sizeof(handle.sigHeader.ecdheInitiator));
		memcpy(handle.sigHeader.ecdsaInitiator, reinterpret_cast<initMsg *>(msg)->ecdsa,
			sizeof(handle.sigHeader.ecdsaInitiator));
		memcpy(handle.sigHeader.nonceInitiator, reinterpret_cast<initMsg *>(msg)->nonce,
			sizeof(handle.sigHeader.nonceInitiator));

		fillInitMsg(reinterpret_cast<initMsg *>(msg), handle);
		memcpy(handle.sigHeader.ecdheResponder, reinterpret_cast<initMsg *>(msg)->ecdhe,
			sizeof(handle.sigHeader.ecdheResponder));
		memcpy(handle.sigHeader.ecdsaResponder, reinterpret_cast<initMsg *>(msg)->ecdsa,
			sizeof(handle.sigHeader.ecdsaResponder));
		memcpy(handle.sigHeader.nonceResponder, reinterpret_cast<initMsg *>(msg)->nonce,
			sizeof(handle.sigHeader.nonceResponder));

		sendCount = sizeof(initMsg);
		handle.type = protoHandle::AUTH;
		break;

	case protoHandle::AUTH:
		handleAuthMsg(reinterpret_cast<authMsg *>(msg), handle);
		fillAuthMsg(reinterpret_cast<authMsg *>(msg), handle);
		handle.type = protoHandle::TUNNEL;

		sendCount = sizeof(authMsg);
		break;

	default:
		throw new std::runtime_error("AstraeusProto::handleHandshake() type unknown");
		break;
	}

	if (handle.type == protoHandle::TUNNEL) {
		return 1;
	} else {
		return 0;
	}
};

int AstraeusProto::handleHandshakeClient(protoHandle &handle, uint8_t *msg, int &sendCount) {
	switch (handle.type) {
	case protoHandle::INIT:
		handleInitMsg(reinterpret_cast<initMsg *>(msg), handle, true);
		memcpy(handle.sigHeader.ecdheResponder, reinterpret_cast<initMsg *>(msg)->ecdhe,
			sizeof(handle.sigHeader.ecdheResponder));
		memcpy(handle.sigHeader.ecdsaResponder, reinterpret_cast<initMsg *>(msg)->ecdsa,
			sizeof(handle.sigHeader.ecdsaResponder));
		memcpy(handle.sigHeader.nonceResponder, reinterpret_cast<initMsg *>(msg)->nonce,
			sizeof(handle.sigHeader.nonceResponder));

		handle.type = protoHandle::AUTH;

		fillAuthMsg(reinterpret_cast<authMsg *>(msg), handle);
		sendCount = sizeof(authMsg);
		break;

	case protoHandle::AUTH:
		handleAuthMsg(reinterpret_cast<authMsg *>(msg), handle);
		sendCount = 0;
		handle.type = protoHandle::TUNNEL;
		break;

	default:
		throw new std::runtime_error("AstraeusProto::handleHandshake() type unknown");
		break;
	}

	if (handle.type == protoHandle::TUNNEL) {
		return 1;
	} else {
		return 0;
	}
};

void AstraeusProto::generateIdentity(identityHandle &ident) {
	crypto_sign_keypair(ident.pubKey, ident.secKey);
};

int AstraeusProto::generateInit(identityHandle &ident, protoHandle &handle, uint8_t *msg) {
	generateHandle(ident, handle);

	return generateInitGivenHandle(handle, msg);
};

int AstraeusProto::generateInitGivenHandle(protoHandle &handle, uint8_t *msg) {
	fillInitMsg(reinterpret_cast<initMsg *>(msg), handle);
	handle.type = protoHandle::INIT;
	memcpy(handle.sigHeader.ecdheInitiator, reinterpret_cast<initMsg *>(msg)->ecdhe,
		sizeof(handle.sigHeader.ecdheInitiator));
	memcpy(handle.sigHeader.ecdsaInitiator, reinterpret_cast<initMsg *>(msg)->ecdsa,
		sizeof(handle.sigHeader.ecdsaInitiator));
	memcpy(handle.sigHeader.nonceInitiator, reinterpret_cast<initMsg *>(msg)->nonce,
		sizeof(handle.sigHeader.nonceInitiator));

	return sizeof(initMsg);
};

int AstraeusProto::generateInitGivenHandleAndSeed(
	protoHandle &handle, uint8_t *msg, const uint8_t nonceSeed[randombytes_SEEDBYTES]) {
	fillInitMsgSeed(reinterpret_cast<initMsg *>(msg), handle, nonceSeed);
	handle.type = protoHandle::INIT;
	memcpy(handle.sigHeader.ecdheInitiator, reinterpret_cast<initMsg *>(msg)->ecdhe,
		sizeof(handle.sigHeader.ecdheInitiator));
	memcpy(handle.sigHeader.ecdsaInitiator, reinterpret_cast<initMsg *>(msg)->ecdsa,
		sizeof(handle.sigHeader.ecdsaInitiator));
	memcpy(handle.sigHeader.nonceInitiator, reinterpret_cast<initMsg *>(msg)->nonce,
		sizeof(handle.sigHeader.nonceInitiator));

	return sizeof(initMsg);
};

int AstraeusProto::generateInitGivenHandleAndNonce(
	protoHandle &handle, uint8_t *msg, const uint8_t nonce[ASTRAEUSPROTONONCELEN]) {
	fillInitMsgNonce(reinterpret_cast<initMsg *>(msg), handle, nonce);
	handle.type = protoHandle::INIT;
	memcpy(handle.sigHeader.ecdheInitiator, reinterpret_cast<initMsg *>(msg)->ecdhe,
		sizeof(handle.sigHeader.ecdheInitiator));
	memcpy(handle.sigHeader.ecdsaInitiator, reinterpret_cast<initMsg *>(msg)->ecdsa,
		sizeof(handle.sigHeader.ecdsaInitiator));
	memcpy(handle.sigHeader.nonceInitiator, reinterpret_cast<initMsg *>(msg)->nonce,
		sizeof(handle.sigHeader.nonceInitiator));

	return sizeof(initMsg);
};

void AstraeusProto::generateHandle(identityHandle &ident, protoHandle &handle) {
	memset(&handle, 0, sizeof(protoHandle));
	handle.ident = &ident;
	crypto_kx_keypair(handle.ecdhPub, handle.ecdhSec);
};

void AstraeusProto::generateHandleGivenKey(identityHandle &ident, protoHandle &handle,
	uint8_t ecdhPub[crypto_kx_PUBLICKEYBYTES], uint8_t ecdhSec[crypto_kx_SECRETKEYBYTES]) {
	memset(&handle, 0, sizeof(protoHandle));
	handle.ident = &ident;
	memcpy(handle.ecdhPub, ecdhPub, sizeof(handle.ecdhPub));
	memcpy(handle.ecdhSec, ecdhSec, sizeof(handle.ecdhSec));
};

int AstraeusProto::bindSocket(int port) {
	int fd;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		throw new std::system_error(std::error_code(errno, std::generic_category()),
			std::string("AstraeusProto::bindSocket() socket() failed"));
	}

	int optval = 1;
	int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
	if (ret != 0) {
		throw new std::system_error(std::error_code(errno, std::generic_category()),
			std::string("AstraeusProto::bindSocket() setsockopt() failed"));
	}

	if (::bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
		throw new std::system_error(std::error_code(errno, std::generic_category()),
			std::string("AstraeusProto::bindSocket() bind() failed"));
	}

	return fd;
};

int AstraeusProto::createSocket() {
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		throw new std::system_error(std::error_code(errno, std::generic_category()),
			std::string("AstraeusProto::bindSocket() socket() failed"));
	}

	return fd;
};
