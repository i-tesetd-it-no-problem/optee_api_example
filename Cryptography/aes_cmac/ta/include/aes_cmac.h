#ifndef _AES_CMAC_H
#define _AES_CMAC_H

#define TA_AES_CMAC_UUID \
	{ 0xd0ae44a0, 0x6a59, 0x4be3, \
		{ 0xaf, 0x7e, 0x19, 0x38, 0x63, 0x16, 0xcd, 0x3f} }

/* 
 * @brief : generate key by AES-CBC-PKCS5 algorithm to do mac
 *
 * param[0] (memref-output) : 	the mac key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define AES_CMAC_GEN_KEY			0

/* 
 * @brief : do mac
 *
 * param[0] (memref-input) 	: the message
 * param[1] (memref-output) : the MAC
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define AES_CMAC_GEN_MAC			1

/* 
 * @brief : verify the mac
 *
 * param[0] (memref-input) 	: the message
 * param[1] (memref-input) 	: the MAC
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define AES_CMAC_VERIFY			2

#endif /* _AES_CMAC_H */
