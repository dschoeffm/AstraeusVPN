#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>

#include "sodium.h"

void testChaCha20() {
	char testStr[] = "This is a test";
	char testStrDec[sizeof(testStr)];
	char addStr[] = "ADD";

	uint8_t nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
	uint8_t key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
	uint8_t ciphertext[sizeof(testStr) + crypto_aead_chacha20poly1305_IETF_ABYTES];
	unsigned long long ciphertext_len;
	unsigned long long message_len;

	crypto_aead_chacha20poly1305_ietf_keygen(key);
	randombytes_buf(nonce, sizeof(nonce));

	crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
		reinterpret_cast<unsigned char *>(testStr), sizeof(testStr),
		reinterpret_cast<unsigned char *>(addStr), sizeof(addStr), NULL, nonce, key);

	int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
		reinterpret_cast<unsigned char *>(testStrDec), &message_len, NULL, ciphertext,
		ciphertext_len, reinterpret_cast<unsigned char *>(addStr), sizeof(addStr), nonce,
		key);

	assert(ret == 0);
	assert(memcmp(testStr, testStrDec, sizeof(testStr)) == 0);
};

void testECDH() {

	unsigned char client_pk[crypto_kx_PUBLICKEYBYTES], client_sk[crypto_kx_SECRETKEYBYTES];
	unsigned char client_rx[crypto_kx_SESSIONKEYBYTES], client_tx[crypto_kx_SESSIONKEYBYTES];

	unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
	unsigned char server_rx[crypto_kx_SESSIONKEYBYTES], server_tx[crypto_kx_SESSIONKEYBYTES];

	crypto_kx_keypair(client_pk, client_sk);
	crypto_kx_keypair(server_pk, server_sk);

	int ret;
	ret =
		crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk, server_pk);
	assert(ret == 0);

	ret =
		crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk);
	assert(ret == 0);

	assert(memcmp(server_rx, client_tx, sizeof(crypto_kx_SESSIONKEYBYTES)) == 0);
	assert(memcmp(server_tx, client_rx, sizeof(crypto_kx_SESSIONKEYBYTES)) == 0);
};

void testECDSA() {

	unsigned char msg[] = "this is a test";

	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];
	unsigned char sig[crypto_sign_BYTES];
	int ret;

	ret = crypto_sign_keypair(pk, sk);
	assert(ret == 0);

	ret = crypto_sign_detached(sig, NULL, msg, sizeof(msg), sk);
	assert(ret == 0);

	ret = crypto_sign_verify_detached(sig, msg, sizeof(msg), pk);
	assert(ret == 0);
};

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;

	testChaCha20();
	std::cout << "[OK] ChaCha20" << std::endl;

	testECDH();
	std::cout << "[OK] ECDH" << std::endl;

	testECDSA();
	std::cout << "[OK] ECDSA" << std::endl;

	std::cout << "All tests successful" << std::endl;
	return 0;
}
