#ifndef _AES_CTS_H
#define _AES_CTS_H

#define TA_AES_CTS_UUID \
	{ 0xbc78d31e, 0xc9c9, 0x4312, \
		{ 0xa9, 0x3c, 0xe3, 0x7c, 0x9c, 0x8c, 0x7b, 0x17} }

/* 
 * @brief : generate key by AES-CTS algorithm
 *
 * param[0] (memref-output) : 	the generated key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_AES_CTS_GEN_KEY 		0

/* 
 * @brief : generate initial vector
 *
 * param[0] (memref-output) : 	the initial vector
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_AES_CTS_GEN_IV 		1

/* 
 * @brief : use the generated to encrypt plain text
 *
 * param[0] (memref-input) 	:	plain text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	cipher text
 * param[3] (unsued)
 */
#define TA_AES_CTS_ENCRYPT 		2

/* 
 * @brief : use the generated to decrypt cipher text
 *
 * param[0] (memref-input) 	:	cipher text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	plain text
 * param[3] (unsued)
 */
#define TA_AES_CTS_DECRYPT 		3

#endif /* _AES_CTS_H */
