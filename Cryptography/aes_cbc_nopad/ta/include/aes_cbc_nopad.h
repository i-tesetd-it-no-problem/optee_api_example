#ifndef _AES_CBC_NOPAD_H
#define _AES_CBC_NOPAD_H

#define TA_AES_CBC_NOPAD_UUID \
	{ 0x0fa57fa4, 0x73e1, 0x4aae, \
		{ 0x93, 0x18, 0xdf, 0xd8, 0xe3, 0x18, 0x18, 0x98} }

/* 
 * @brief : generate key by AES-CBC-NOPAD algorithm
 *
 * param[0] (memref-output) : 	the generated key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_AES_CBC_NOPAD_GEN_KEY 		0

/* 
 * @brief : generate initial vector
 *
 * param[0] (memref-output) : 	the initial vector
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_AES_CBC_NOPAD_GEN_IV 		1

/* 
 * @brief : use the generated to encrypt plain text
 *
 * param[0] (memref-input) 	:	plain text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	cipher text
 * param[3] (unsued)
 */
#define TA_AES_CBC_NOPAD_ENCRYPT 		2

/* 
 * @brief : use the generated to decrypt cipher text
 *
 * param[0] (memref-input) 	:	cipher text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	plain text
 * param[3] (unsued)
 */
#define TA_AES_CBC_NOPAD_DECRYPT 		3

#endif /* _AES_CBC_NOPAD_H */
