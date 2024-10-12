#ifndef _HMAC_XXX_H
#define _HMAC_XXX_H

#define TA_HMAC_XXX_UUID \
	{ 0xd443b788, 0x5283, 0x498b, \
		{ 0x99, 0x40, 0x5e, 0xe5, 0xf9, 0x2f, 0x6a, 0x45} }

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_HMAC_MD5
// #define USE_KEY_TYPE				TEE_TYPE_HMAC_MD5
// #define MAC_BITS 				(128)

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_HMAC_SHA1
// #define USE_KEY_TYPE				TEE_TYPE_HMAC_SHA1
// #define MAC_BITS 				(160)

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_HMAC_SHA224
// #define USE_KEY_TYPE				TEE_TYPE_HMAC_SHA224
// #define MAC_BITS 				(224)

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_HMAC_SHA256
// #define USE_KEY_TYPE				TEE_TYPE_HMAC_SHA256
// #define MAC_BITS 				(256)

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_HMAC_SHA384
// #define USE_KEY_TYPE				TEE_TYPE_HMAC_SHA384
// #define MAC_BITS 				(384)

#define USE_DIGEST_ALGORITHM 		TEE_ALG_HMAC_SHA512
#define USE_KEY_TYPE				TEE_TYPE_HMAC_SHA512
#define MAC_BITS 					(512)

// #define USE_DIGEST_ALGORITHM 	TEE_ALG_HMAC_SM3
// #define USE_KEY_TYPE				TEE_TYPE_HMAC_SM3
// #define MAC_BITS 				(256)

/* 
 * @brief : generate key
 *
 * param[0] (memref-output) : 	key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define HMAC_XXX_GEN_KEY				0

/* 
 * @brief : Authentication
 *
 * param[0] (memref-input) 	: Message
 * param[1] (memref-output) : MAC
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define HMAC_XXX_GEN_MAC				1

/* 
 * @brief : Authentication
 *
 * param[0] (memref-input) 	: Message
 * param[1] (memref-input) 	: MAC
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define HMAC_XXX_VERIFY_MAC				2

#endif /* _HMAC_XXX_H */
