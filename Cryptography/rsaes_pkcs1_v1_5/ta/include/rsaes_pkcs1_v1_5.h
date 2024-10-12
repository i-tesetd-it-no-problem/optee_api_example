#ifndef _RSAES_PKCS1_V1_5_H
#define _RSAES_PKCS1_V1_5_H

#define TA_RSAES_PKCS1_V1_5_UUID \
	{ 0x95a9449c, 0xdce7, 0x4dda, \
		{ 0xa1, 0xb7, 0x37, 0xf7, 0xeb, 0x29, 0xab, 0x91} }

#define KEYPAIR_SIZE (128)
#define KEYPAIR_BITS (KEYPAIR_SIZE * 8) // can be 1024, 2048, 3072, 4096

/* 
 * @brief : generate keypair
 *
 * param[0] (unsued)
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define RSAES_PKCS1_V1_5_GEN_KEY 		0

/* 
 * @brief : encrypt
 *
 * param[0] (memref-input) 	: plain text
 * param[1] (memref-output)	: cipher text
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define RSAES_PKCS1_V1_5_ENCRYPT 		1

/* 
 * @brief : decrypt
 *
 * param[0] (memref-input) 	: cipher text
 * param[1] (memref-output)	: plain text
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define RSAES_PKCS1_V1_5_DECRYPT 		2

#endif /* _RSAES_PKCS1_V1_5_H */
