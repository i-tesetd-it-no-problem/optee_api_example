#ifndef _HASH_H
#define _HASH_H

/***************************************************************** */
/* choose one algoirithm to test */

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_MD5
// #define DIGEST_BITS 				(128)

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_SHA1
// #define DIGEST_BITS 				(160)

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_SHA224
// #define DIGEST_BITS 				(224)

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_SHA256
// #define DIGEST_BITS 				(256)

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_SHA384
// #define DIGEST_BITS 				(384)

#define USE_DIGEST_ALGORITHM 		TEE_ALG_SHA512
#define DIGEST_BITS 				(512)

///////////////////////////////////
// OPTEE is not surpport SHA-3

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_SHA3_224
// #define DIGEST_BITS 				(224)

// #define USE_DIGEST_ALGORITHM		TEE_ALG_SHA3_256
// #define DIGEST_BITS 				(256)

// #define USE_DIGEST_ALGORITHM		TEE_ALG_SHA3_384
// #define DIGEST_BITS 				(384)

// #define USE_DIGEST_ALGORITHM		TEE_ALG_SHA3_512
// #define DIGEST_BITS 				(512)

/***************************************************************** */

#define TA_HASH_UUID \
	{ 0xa4660423, 0x4973, 0x4f91, \
		{ 0x9b, 0xb6, 0x88, 0x2e, 0x72, 0x56, 0xe3, 0xec} }

/* 
 * @brief : create digest
 *
 * param[0] (memref-input) 	: message
 * param[1] (memref-output)	: digest
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define HASH_DIGEST 	0

#endif /* _HASH_H */
