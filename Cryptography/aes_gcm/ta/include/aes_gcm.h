#ifndef _AES_GCM_H
#define _AES_GCM_H

#define TA_AES_GCM_UUID \
	{ 0x70eb931d, 0xd838, 0x4584, \
		{ 0x91, 0x24, 0xcb, 0xe3, 0x20, 0x31, 0xbb, 0x65} }

/* 
 * @brief : generate key by AES-GCM algorithm
 *
 * param[0] (memref-output) : 	key
 * param[1] (memref-output) :   iv
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define AES_GCM_GEN_KEY				0

/* 
 * @brief : Authentication Encrypt
 *
 * param[0] (memref-input) 	: plain text
 * param[1] (memref-input) 	: iv
 * param[2] (memref-output) : cipher text
 * param[3] (memref-output) : tag
 */
#define AES_GCM_AE_ENCRYPR			1

/* 
 * @brief : Authentication Decrypt
 *
 * param[0] (memref-input) 	: cipher text
 * param[1] (memref-input) 	: iv
 * param[3] (memref-output) : plain text
 * param[4] (memref-input)  : tag
 */
#define AES_GCM_AE_DECRYPR			2

#endif /* _AES_GCM_H */
