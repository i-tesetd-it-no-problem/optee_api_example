#ifndef _AES_CCM_H
#define _AES_CCM_H

#define TA_AES_CCM_UUID \
	{ 0x5f7df382, 0xc9b6, 0x496b, \
		{ 0x89, 0x79, 0x67, 0xf1, 0x3c, 0xe9, 0x68, 0x5f} }

/* 
 * @brief : generate key by AES-CCM algorithm
 *
 * param[0] (memref-output) : 	key
 * param[1] (memref-output) :   iv
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define AES_CCM_GEN_KEY				0

/* 
 * @brief : Authentication Encrypt
 *
 * param[0] (memref-input) 	: plain text
 * param[1] (memref-input) 	: iv
 * param[2] (memref-output) : cipher text
 * param[3] (memref-output) : tag
 */
#define AES_CCM_AE_ENCRYPR			1

/* 
 * @brief : Authentication Decrypt
 *
 * param[0] (memref-input) 	: cipher text
 * param[1] (memref-input) 	: iv
 * param[3] (memref-output) : plain text
 * param[4] (memref-input)  : tag
 */
#define AES_CCM_AE_DECRYPR			2

#endif /* _AES_CCM_H */
