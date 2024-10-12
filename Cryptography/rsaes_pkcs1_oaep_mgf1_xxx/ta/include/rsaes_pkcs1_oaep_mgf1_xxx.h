#ifndef _RSAES_PKCS1_OAEP_MGF1_XXX_H
#define _RSAES_PKCS1_OAEP_MGF1_XXX_H

#define TA_RSAES_PKCS1_OAEP_MGF1_XXX_UUID \
	{ 0x0cfa47d1, 0x216b, 0x4286, \
		{ 0xac, 0x1c, 0x08, 0x6d, 0x6a, 0x7e, 0x55, 0x8b} }

#define KEYPAIR_BITS (2048) // can be 1024, 2048, 3072, 4096
#define KEYPAIR_SIZE (KEYPAIR_BITS / 8)

// choose one 
// #define USE_ALGORITHM 	TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1
// #define USE_ALGORITHM 	TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224
// #define USE_ALGORITHM 	TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256
// #define USE_ALGORITHM 	TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384
#define USE_ALGORITHM 	TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512 //if use this , KEYPAIR_BITS must choose 2048

/* 
 * @brief : generate keypair
 *
 * param[0] (unsued)
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define RSAES_PKCS1_OAEP_MGF1_GEN_KEY 		0

/* 
 * @brief : encrypt
 *
 * param[0] (memref-input) 	: plain text
 * param[1] (memref-output)	: cipher text
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define RSAES_PKCS1_OAEP_MGF1_ENCRYPT 		1

/* 
 * @brief : decrypt
 *
 * param[0] (memref-input) 	: cipher text
 * param[1] (memref-output)	: plain text
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define RSAES_PKCS1_OAEP_MGF1_DECRYPT 		2

#endif /* _RSAES_PKCS1_OAEP_MGF1_XXX_H */
