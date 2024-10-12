#ifndef _ECDH_XXX_H
#define _ECDH_XXX_H

#define TA_ECDH_XXX_UUID \
	{ 0xc7df3d74, 0x69f8, 0x45b0, \
		{ 0x9f, 0xe4, 0xf4, 0x94, 0x40, 0x19, 0xe7, 0x22} }

/***************************************************************** */
/* choose one algoirithm to test */
// #define USE_ECDSA_ALGORITHM 			TEE_ALG_ECDH_P192
// #define USE_ELEMENT					TEE_ECC_CURVE_NIST_P192
// #define KEYPAIR_BITS 				(192)
// #define KEYPAIR_SIZE 				(KEYPAIR_BITS / 8)

// #define USE_ECDSA_ALGORITHM 			TEE_ALG_ECDH_P224
// #define USE_ELEMENT					TEE_ECC_CURVE_NIST_P224
// #define KEYPAIR_BITS 				(224)
// #define KEYPAIR_SIZE 				(KEYPAIR_BITS / 8)

// #define USE_ECDSA_ALGORITHM 			TEE_ALG_ECDH_P256
// #define USE_ELEMENT					TEE_ECC_CURVE_NIST_P256
// #define KEYPAIR_BITS 				(256)
// #define KEYPAIR_SIZE 				(KEYPAIR_BITS / 8)

// #define USE_ECDSA_ALGORITHM 			TEE_ALG_ECDH_P384
// #define USE_ELEMENT					TEE_ECC_CURVE_NIST_P384
// #define KEYPAIR_BITS 				(384)
// #define KEYPAIR_SIZE 				(KEYPAIR_BITS / 8)

#define USE_ECDSA_ALGORITHM 			TEE_ALG_ECDH_P521
#define USE_ELEMENT						TEE_ECC_CURVE_NIST_P521
#define KEYPAIR_BITS 					(521)
#define KEYPAIR_SIZE 					(KEYPAIR_BITS / 8 + 1)

/***************************************************************** */

#define USE_ALG_AES_HASH		TEE_ALG_SHA256
#define AES_SECRET_BITS (256)

/* 
 * @brief : generate key pair by ECDH
 *
 * param[0] (memref-output) : the public key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ECDH_GEN_DH_KEYPAIR			0

/* 
 * @brief : generate shared key
 *
 * param[0] (memref-input) : the peer public key x
 * param[1] (memref-input) : the peer public key y
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ECDH_DERIVE_KEY				1

/* 
 * @brief : use shared key encrypt message
 *
 * param[0] (memref-input) 	: the cipher text
 * param[1] (memref-input) 	: IV
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ECDH_DECRYPT				2

#endif /* _ECDH_XXX_H */
