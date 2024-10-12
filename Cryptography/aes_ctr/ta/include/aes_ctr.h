#ifndef _AES_CTR_H
#define _AES_CTR_H

#define TA_AES_CTR_UUID \
	{ 0xe2366aab, 0x1c0a, 0x412a, \
		{ 0x9b, 0x81, 0x53, 0xf9, 0xd3, 0x82, 0x1f, 0xc1} }

/* 
 * @brief : generate key by AES-CTR algorithm
 *
 * param[0] (memref-output) : 	the generated key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_AES_CTR_GEN_KEY 		0

/* 
 * @brief : generate initial vector
 *
 * param[0] (memref-output) : 	the initial vector
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_AES_CTR_GEN_IV 		1

/* 
 * @brief : use the generated to encrypt plain text
 *
 * param[0] (memref-input) 	:	plain text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	cipher text
 * param[3] (unsued)
 */
#define TA_AES_CTR_ENCRYPT 		2

/* 
 * @brief : use the generated to decrypt cipher text
 *
 * param[0] (memref-input) 	:	cipher text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	plain text
 * param[3] (unsued)
 */
#define TA_AES_CTR_DECRYPT 		3

#endif /* _AES_CTR_H */
