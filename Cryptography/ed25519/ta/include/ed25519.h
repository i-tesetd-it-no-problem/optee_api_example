#ifndef _ED25519_H
#define _ED25519_H

#define TA_ED25519_UUID \
	{ 0x21af99ba, 0x8506, 0x4a2b, \
		{ 0xb3, 0xf4, 0xeb, 0x92, 0xe0, 0x42, 0x65, 0x28} }

#define KEYPAIR_BITS 					(256)
#define KEYPAIR_SIZE 					(KEYPAIR_BITS / 8)

/* 
 * @brief : generate keypair
 *
 * param[0] (unsued)
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ED25519_GEN_KEY 	0

/* 
 * @brief : sign
 *
 * param[0] (memref-input) 	: message
 * param[1] (memref-output)	: tag
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ED25519_SIGN 		1

/* 
 * @brief : verify
 *
 * param[0] (memref-input) 	: message
 * param[1] (memref-input)	: tag
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define ED25519_VERIFY 	2

#endif /* _ED25519_H */
