#ifndef _AES_ECB_NOPAD_H
#define _AES_ECB_NOPAD_H

#define TA_AES_ECB_NOPAD_UUID \
	{ 0x2f1c50d5, 0x7b64, 0x4f11, \
		{ 0xa4, 0xcf, 0x8e, 0x1a, 0xd8, 0x6f, 0xb5, 0x60} }

/* 
 * @brief : generate key by AES-ECB-NOPAD algorithm
 *
 * param[0] (memref-output) : 	the generated key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_AES_CBC_NOPAD_GEN_KEY 	0

/* 
 * @brief : use the generated to encrypt plain text
 *
 * param[0] (memref-input) 	:	plain text
 * param[1] (memref-output) :	cipher text
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_AES_ECB_NOPAD_ENCRYPT 	1

/* 
 * @brief : use the generated to decrypt cipher text
 *
 * param[0] (memref-input) 	:	cipher text
 * param[1] (memref-output) :	plain text
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_AES_ECB_NOPAD_DECRYPT 	2

#endif /* _AES_ECB_NOPAD_H */
