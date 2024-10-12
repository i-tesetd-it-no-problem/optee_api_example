#ifndef _SM4_CTR_H
#define _SM4_CTR_H

#define TA_SM4_CTR_UUID \
	{ 0x6ac5a9a5, 0xd5fc, 0x4d0e, \
		{ 0xb8, 0xc3, 0x7f, 0x76, 0xde, 0xb0, 0x15, 0xfb} }

/* 
 * @brief : generate key by SM4-CTR algorithm
 *
 * param[0] (memref-output) : 	the generated key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_SM4_CTR_GEN_KEY 		0

/* 
 * @brief : generate initial vector
 *
 * param[0] (memref-output) : 	the initial vector
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_SM4_CTR_GEN_IV 		1

/* 
 * @brief : use the generated to encrypt plain text
 *
 * param[0] (memref-input) 	:	plain text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	cipher text
 * param[3] (unsued)
 */
#define TA_SM4_CTR_ENCRYPT 		2

/* 
 * @brief : use the generated to decrypt cipher text
 *
 * param[0] (memref-input) 	:	cipher text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	plain text
 * param[3] (unsued)
 */
#define TA_SM4_CTR_DECRYPT 		3

#endif /* _SM4_CTR_H */
