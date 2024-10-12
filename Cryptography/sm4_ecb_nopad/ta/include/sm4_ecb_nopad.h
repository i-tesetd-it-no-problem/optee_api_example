#ifndef _SM4_ECB_NOPAD_H
#define _SM4_ECB_NOPAD_H

#define TA_SM4_ECB_NOPAD_UUID \
	{ 0x86f19caf, 0xbccc, 0x4df4, \
		{ 0x99, 0xaf, 0x50, 0xc9, 0x2d, 0xb0, 0xbe, 0x29} }

/* 
 * @brief : generate key by SM4-ECB-NOPAD algorithm
 *
 * param[0] (memref-output) : 	the generated key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_SM4_CBC_NOPAD_GEN_KEY 	0

/* 
 * @brief : use the generated to encrypt plain text
 *
 * param[0] (memref-input) 	:	plain text
 * param[1] (memref-output) :	cipher text
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_SM4_ECB_NOPAD_ENCRYPT 	1

/* 
 * @brief : use the generated to decrypt cipher text
 *
 * param[0] (memref-input) 	:	cipher text
 * param[1] (memref-output) :	plain text
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_SM4_ECB_NOPAD_DECRYPT 	2

#endif /* _SM4_ECB_NOPAD_H */
