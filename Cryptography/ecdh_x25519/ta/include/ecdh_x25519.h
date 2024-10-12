#ifndef _ECDH_X25519_H
#define _ECDH_X25519_H

#define TA_ECDH_X25519_UUID \
	{ 0xd1364928, 0x171d, 0x419c, \
		{ 0xb7, 0xca, 0xe5, 0x7d, 0x64, 0x86, 0x9c, 0x28} }


#define USE_ECDSA_ALGORITHM 			TEE_ALG_X25519
#define USE_ELEMENT						TEE_ECC_CURVE_25519
#define KEYPAIR_BITS 					(256)
#define KEYPAIR_SIZE 					(KEYPAIR_BITS / 8)
#define USE_ALG_AES_HASH				TEE_ALG_SHA256
#define AES_SECRET_BITS 				(256)


/* 
 * @brief : generate key pair by ECDH
 *
 * param[0] (memref-output) : the public key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ECDH_X25519_GEN_DH_KEYPAIR			0

/* 
 * @brief : generate shared key
 *
 * param[0] (memref-input) : the peer public key x
 * param[1] (memref-input) : the peer public key y
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ECDH_X25519_DERIVE_KEY				1

/* 
 * @brief : use shared key encrypt message
 *
 * param[0] (memref-input) 	: the cipher text
 * param[1] (memref-input) 	: IV
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ECDH_X25519_DECRYPT					2

#endif /* _ECDH_X25519_H */
