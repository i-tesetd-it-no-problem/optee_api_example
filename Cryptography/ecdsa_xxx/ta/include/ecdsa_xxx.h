#ifndef _ECDSA_XXX_H
#define _ECDSA_XXX_H

/***************************************************************** */
/* choose one algoirithm to test */
// #define USE_ECDSA_ALGORITHM 			TEE_ALG_ECDSA_P192
// #define USE_ELEMENT					TEE_ECC_CURVE_NIST_P192
// #define KEYPAIR_BITS 				(192)
// #define KEYPAIR_SIZE 				(KEYPAIR_BITS / 8)

// #define USE_ECDSA_ALGORITHM 			TEE_ALG_ECDSA_P224
// #define USE_ELEMENT					TEE_ECC_CURVE_NIST_P224
// #define KEYPAIR_BITS 				(224)
// #define KEYPAIR_SIZE 				(KEYPAIR_BITS / 8)

// #define USE_ECDSA_ALGORITHM 			TEE_ALG_ECDSA_P256
// #define USE_ELEMENT					TEE_ECC_CURVE_NIST_P256
// #define KEYPAIR_BITS 				(256)
// #define KEYPAIR_SIZE 				(KEYPAIR_BITS / 8)

// #define USE_ECDSA_ALGORITHM 			TEE_ALG_ECDSA_P384
// #define USE_ELEMENT					TEE_ECC_CURVE_NIST_P384
// #define KEYPAIR_BITS 				(384)
// #define KEYPAIR_SIZE 				(KEYPAIR_BITS / 8)

#define USE_ECDSA_ALGORITHM 			TEE_ALG_ECDSA_P521
#define USE_ELEMENT						TEE_ECC_CURVE_NIST_P521
#define KEYPAIR_BITS 					(521)
#define KEYPAIR_SIZE 					(66)

/***************************************************************** */

#define TA_ECDSA_XXX_UUID \
	{ 0xad3fae37, 0x3956, 0x48fe, \
		{ 0x86, 0xb3, 0xa6, 0xf9, 0x13, 0x5a, 0x87, 0xcb} }

#define DIGEST_BITS (256)

/* 
 * @brief : generate keypair
 *
 * param[0] (unsued)
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ECDSA_XXX_GEN_KEY 	0

/* 
 * @brief : hash
 *
 * param[0] (memref-input) 	: message
 * param[1] (memref-output)	: digest
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ECDSA_XXX_DIGEST 	1

/* 
 * @brief : sign
 *
 * param[0] (memref-input) 	: digest
 * param[1] (memref-output)	: tag
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ECDSA_XXX_SIGN 		2

/* 
 * @brief : verify
 *
 * param[0] (memref-input) 	: digest
 * param[1] (memref-input)	: tag
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ECDSA_XXX_VERIFY 	3

#endif /* _ECDSA_XXX_H */
