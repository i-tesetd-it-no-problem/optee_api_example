#ifndef _AES_XTS_H
#define _AES_XTS_H

#define TA_AES_XTS_UUID \
	{ 0xe53ba603, 0x3110, 0x4fac, \
		{ 0x94, 0xbc, 0xc8, 0xd7, 0xe3, 0x7e, 0xa2, 0x6e} }

/* 
 * @brief : generate key by AES-XTS algorithm
 *
 * param[0] (memref-output) : 	the generated key1
 * param[1] (memref-output) : 	the generated key2
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_AES_XTS_GEN_KEY 		0

/* 
 * @brief : generate initial vector
 *
 * param[0] (memref-output) : 	the initial vector
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_AES_XTS_GEN_IV 		1

/* 
 * @brief : use the generated to encrypt plain text
 *
 * param[0] (memref-input) 	:	plain text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	cipher text
 * param[3] (unsued)
 */
#define TA_AES_XTS_ENCRYPT 		2

/* 
 * @brief : use the generated to decrypt cipher text
 *
 * param[0] (memref-input) 	:	cipher text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	plain text
 * param[3] (unsued)
 */
#define TA_AES_XTS_DECRYPT 		3

#endif /* _AES_XTS_H */
