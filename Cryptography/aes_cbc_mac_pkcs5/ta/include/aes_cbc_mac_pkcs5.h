#ifndef _AES_CBC_MAC_PKCS5_H
#define _AES_CBC_MAC_PKCS5_H

#define TA_AES_CBC_MAC_PKCS5_UUID \
	{ 0x827066b8, 0xe173, 0x44a4, \
		{ 0x9d, 0x46, 0x49, 0x5d, 0x08, 0xec, 0x5a, 0xba} }

/* 
 * @brief : generate key by AES-CBC-PKCS5 algorithm to do mac
 *
 * param[0] (memref-output) : 	the mac key
 * param[1] (unsued)
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define AES_CBC_MAC_PKCS5_GEN_KEY			0

/* 
 * @brief : do mac
 *
 * param[0] (memref-input) 	: the message
 * param[1] (memref-output) : the MAC
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define AES_CBC_MAC_PKCS5_GEN_MAC			1

/* 
 * @brief : verify the mac
 *
 * param[0] (memref-input) 	: the message
 * param[1] (memref-input) 	: the MAC
 * param[2] (unsued)
 * param[3] (unsued)
 */
#define AES_CBC_MAC_PKCS5_VERIFY			2

#endif /* _AES_CBC_MAC_PKCS5_H */
