#ifndef _SM4_CBC_NOPAD_H
#define _SM4_CBC_NOPAD_H

#define TA_SM4_CBC_NOPAD_UUID \
	{ 0xd0519cfc, 0x1839, 0x47b8, \
		{ 0x92, 0x14, 0x7c, 0xf6, 0x58, 0x8b, 0xe4, 0x99} }

/* 
 * @brief : generate key by SM4-CBC-NOPAD algorithm
 *
 * param[0] (memref-output) : 	the generated key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_SM4_CBC_NOPAD_GEN_KEY 		0

/* 
 * @brief : generate initial vector
 *
 * param[0] (memref-output) : 	the initial vector
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define TA_SM4_CBC_NOPAD_GEN_IV 		1

/* 
 * @brief : use the generated to encrypt plain text
 *
 * param[0] (memref-input) 	:	plain text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	cipher text
 * param[3] (unsued)
 */
#define TA_SM4_CBC_NOPAD_ENCRYPT 		2

/* 
 * @brief : use the generated to decrypt cipher text
 *
 * param[0] (memref-input) 	:	cipher text
 * param[1] (memref-input) 	:	IV
 * param[2] (memref-output) :	plain text
 * param[3] (unsued)
 */
#define TA_SM4_CBC_NOPAD_DECRYPT 		3

#endif /* _SM4_CBC_NOPAD_H */
