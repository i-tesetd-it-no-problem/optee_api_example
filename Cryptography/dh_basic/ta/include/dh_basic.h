#ifndef _DH_BASIC_H
#define _DH_BASIC_H

#define TA_DH_BASIC_UUID \
	{ 0xa49c2ff4, 0xd6c8, 0x4552, \
		{ 0xb3, 0x0e, 0xba, 0x84, 0x7f, 0xb6, 0xd6, 0x86} }

#define KEYPAIR_BITS (1024)
#define KEYPAIR_BYTES (KEYPAIR_BITS / 8)

#define KEY_SHARED_BITS (256)
#define KEY_SHARED_BYTES (KEY_SHARED_BITS / 8)

#define USE_ALG_AES_HASH		TEE_ALG_SHA256
#define AES_SECRET_BITS (256)

/* 
 * @brief : generate key pair by DH
 *
 * param[0] (memref-output) : the public key
 * param[1] (memref-input) 	: the prime
 * param[2] (memref-input) 	: the base
 * param[3] (unsued)
 */
#define DH_BASIC_GEN_DH_KEYPAIR			0

/* 
 * @brief : generate shared key
 *
 * param[0] (memref-input) : the peer public key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define DH_BASIC_DERIVE_KEY				1

/* 
 * @brief : use shared key encrypt message
 *
 * param[0] (memref-input) 	: the cipher text
 * param[1] (memref-input) 	: IV
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define DH_BASIC_DECRYPT				2

#endif /* _DH_BASIC_H */
