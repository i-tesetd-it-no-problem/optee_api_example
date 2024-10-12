#ifndef _RSASSA_PKCS1_V1_5_XXX_H
#define _RSASSA_PKCS1_V1_5_XXX_H


/***************************************************************** */
/* choose one algoirithm to test */

// #define USE_RSA_ALGORITHM 		TEE_ALG_RSASSA_PKCS1_V1_5_MD5
// #define USE_DIGEST_ALGORITHM 	TEE_ALG_MD5
// #define DIGEST_BITS 				(128)

// #define USE_RSA_ALGORITHM 		TEE_ALG_RSASSA_PKCS1_V1_5_SHA1
// #define USE_DIGEST_ALGORITHM 	TEE_ALG_SHA1
// #define DIGEST_BITS 				(160)

// #define USE_RSA_ALGORITHM 		TEE_ALG_RSASSA_PKCS1_V1_5_SHA224
// #define USE_DIGEST_ALGORITHM 	TEE_ALG_SHA224
// #define DIGEST_BITS 				(224)

#define USE_RSA_ALGORITHM 			TEE_ALG_RSASSA_PKCS1_V1_5_SHA256
#define USE_DIGEST_ALGORITHM 		TEE_ALG_SHA256
#define DIGEST_BITS 				(256)

// #define USE_RSA_ALGORITHM 		TEE_ALG_RSASSA_PKCS1_V1_5_SHA384
// #define USE_DIGEST_ALGORITHM 	TEE_ALG_SHA384
// #define DIGEST_BITS 				(384)

// #define USE_RSA_ALGORITHM 		TEE_ALG_RSASSA_PKCS1_V1_5_SHA512
// #define USE_DIGEST_ALGORITHM 	TEE_ALG_SHA512
// #define DIGEST_BITS 				(512)
/***************************************************************** */

#define TA_RSASSA_PKCS1_V1_5_XXX_UUID \
	{ 0x02585df7, 0xac8f, 0x489f, \
		{ 0xa7, 0xb4, 0xe7, 0xb5, 0xeb, 0x7f, 0x4e, 0xb6} }

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
#define RSASSA_PKCS1_V1_5_XXX_GEN_KEY 	0

/* 
 * @brief : digest
 *
 * param[0] (memref-input) 	: message
 * param[1] (memref-output)	: digest
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define RSASSA_PKCS1_V1_5_XXX_DIGEST 	1

/* 
 * @brief : generate signatrue
 *
 * param[0] (memref-input) 	: digest
 * param[1] (memref-output)	: signature
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define RSASSA_PKCS1_V1_5_XXX_SIGN 		2

/* 
 * @brief : verify signatrue
 *
 * param[0] (memref-input) 	: digest
 * param[1] (memref-input)	: signature
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define RSASSA_PKCS1_V1_5_XXX_VERIFY 	3

#endif /* _RSASSA_PKCS1_V1_5_XXX_H */
